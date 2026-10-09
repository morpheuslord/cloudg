---
title: Rate limits and throttling
lede: "Every cloud API call cloudg makes goes through one process-wide governor that paces it, slows down when a provider pushes back, and records what it lost instead of failing the map."
meta:
  - [Package, "`cloudg.resilience`"]
  - [Config, "[`ratelimit`](/reference/config/ratelimit/)"]
  - [Since, "0.6.0"]
source: docs/RESILIENCE.md
since: "0.6.0"
---

A single `cloudg map -p aws --org --regions all` runs 133 deep collector tasks, a Cloud Control sweep and a tagging sweep in every region of every member account, and some collectors fan out per item (one `DescribeImageAttribute` per AMI). Those APIs have quotas, and the quotas are shared with your CI pipelines, Terraform runs and the console. Up to 0.5.x cloudg trusted each SDK's own retries. Forty EC2 clients in one account then backed off independently and kept the account's bucket empty, a service that stayed throttled looked the same in coverage as an access error, and nothing remembered that an API had just said no.

Since 0.6.0 the `cloudg.resilience` package sits between cloudg and every SDK. You rarely need to touch it. This page explains what it does so you can read its output and tune it when an estate needs it. Every key and default is in the [ratelimit reference](/reference/config/ratelimit/), and the Python side in the [cloudg.resilience API](/api/resilience/).

## How one call is paced

Every call is attributed to a scope, `Scope(provider, account, region, service, operation)`, which prints as `aws/123456789012/us-east-1/ec2` (with `/DescribeSubnets` appended where the operation matters). Before the call goes out it passes four gates, and after it comes back the outcome feeds the same state.

```mermaid caption="call_with_resilience: the full sequence. The SDK integrations reuse the same parts and let the SDK do the retrying."
flowchart TD
  A[Call arrives with a scope] --> B{"Breaker open or deadline spent?"}
  B -->|yes| X["Fail fast, nothing sent"]
  B -->|no| D["Take tokens: provider, account, leaf bucket"]
  D --> E["Take a bulkhead slot"]
  E --> F[Send the request]
  F --> G{Outcome}
  G -->|success| H["Recover rate, close breaker"]
  G -->|THROTTLED| I["Halve rate, pause for Retry-After"]
  I --> J{"Retries, deadline and budget left?"}
  G -->|TRANSIENT| J
  J -->|yes| B
  J -->|no| Z["Breaker counts a failure, record give-up"]
  G -->|FATAL| R[Re-raise at once]
```

Errors are sorted by `classify(exc)` into three kinds. THROTTLED means the provider asked cloudg to slow down: AWS `Throttling`, `RequestLimitExceeded`, `TooManyRequestsException` and the rest of botocore's list, Azure `SubscriptionRequestsThrottled`, GCP `ResourceExhausted`, or any bare HTTP 429 or 503. TRANSIENT covers 408, 500, 502, 504 and connection resets. FATAL is everything else with a provider error code, `AccessDenied` included. The classifier reads error codes, exception classes and HTTP statuses first and only falls back to message text when none of them says anything.

### Token buckets per provider, account, region and service

A call takes a token from up to three buckets, most general first, and waits for the slowest:

| Level | Key | On by default |
|---|---|---|
| Provider-wide | `global_max_rps` | no, for every provider |
| Account | `account_max_rps` | Azure only: 20 rps, burst 200, per subscription |
| Leaf | account x region x service, or x operation | yes |

The leaf goes down to the operation for AWS `ec2`, which throttles each API action separately, and for any `"<service>.<Operation>"` override you configure. The built-in leaf rates sit at or just below each provider's documented limits:

| Provider | Leaf | Rate (rps) | Burst |
|---|---|---|---|
| AWS | default per service | 20 | 40 |
| AWS | `ec2`, per API action | 20 | 100 |
| AWS | `sts` | 50 | 100 |
| AWS | `lambda` | 15 | 15 |
| AWS | `iam` | 10 | 40 |
| AWS | `route53`, `resourcegroupstaggingapi` | 5 | 5, 10 |
| AWS | `organizations`, `cloudformation`, `cloudcontrol` | 5 | 10 |
| AWS | `controltower` | 2 | 5 |
| Azure | default per subscription x resource provider | 15 | 100 |
| Azure | `network` / `storage` | 30 / 0.33 | 200 / 20 |
| Azure | `resourcegraph`, per user | 3 | 15 |
| GCP | default per project or organization x API | 10 | 20 |
| GCP | `cloudasset.ListAssets` | 1.5 | 10 |
| GCP | `cloudasset.SearchAllResources`, `SearchAllIamPolicies` | 6 | 20 |

Buckets work by reservation. Taking a token never blocks while the limiter's lock is held: the balance can go negative and the caller is told how long to sleep. That queues callers fairly in arrival order and lets asyncio code and worker threads share one limiter.

### Adaptive halving and additive recovery

Each leaf bucket adjusts its rate the way TCP congestion control does (AIMD). When a call in the scope is throttled, the bucket's rate is halved, never below the provider's `min_rps` (AWS 0.2, Azure 0.1, GCP 0.05), and its stored burst is drained so queued callers cannot all fire at once. Throttles within one second of the last decrease count as the same event, so forty simultaneous 429s halve the rate once. If the provider sent a Retry-After hint, the bucket is also paused for that long, capped at 300 seconds.

Recovery is slow on purpose. After five seconds without a throttle, each success adds 5% of the configured ceiling back, at most once per five seconds. An EC2 action at 20 rps that is throttled twice, a second apart, runs at 5 rps, and steady success brings it back to 20 rps in about 75 seconds. botocore's `adaptive` retry mode does something similar per client; the difference is that this state is shared by every client in the process.

Only leaves adapt. The account and provider-wide buckets stay fixed, and `adaptive: false` freezes a provider's leaves too.

### Bulkheads

A bulkhead caps requests in flight per provider and account: 128 for AWS, 16 for Azure and GCP (`max_concurrency`). What holds a slot depends on the integration. On AWS it is one API call, so botocore's retries of that call reuse the slot. Azure holds one per HTTP attempt, and GCP one per whole Cloud Asset listing, all pages included.

### Circuit breakers

Each leaf scope has a breaker with the same granularity as its bucket: per EC2 action, per service elsewhere. A throttled `DescribeSubnets` therefore does not block `DescribeVpcs` in the same account and region.

```mermaid caption="One breaker. Rejected calls never reach the provider and never count as failures."
stateDiagram-v2
  [*] --> Closed
  Closed --> Closed: success resets the count
  Closed --> Open: breaker_threshold consecutive failures
  Open --> HalfOpen: cooldown elapsed
  HalfOpen --> Closed: probe succeeds, base cooldown restored
  HalfOpen --> Open: probe fails, cooldown doubled up to 600 s
  HalfOpen --> HalfOpen: probe lease expires, next call probes
```

A failure here means a call that still failed with throttling or a transient error after all its retries. The defaults are 5 consecutive failures (`breaker_threshold`) and a 60-second cooldown (`breaker_cooldown_seconds`). While open, calls fail at once with `circuit open for <scope> after repeated throttling; retry in <n>s`.

Some things deliberately do not count. A call the open circuit rejected was never sent. A call stopped by an empty retry budget was stopped by cloudg, not by the service. And a FATAL answer such as `AccessDenied` or a 404 proves the service is reachable, so it resets the failure count like a success. An `AccessDenied` storm never opens a circuit.

### Retries and the retry budget

`call_with_resilience` retries THROTTLED and TRANSIENT errors with decorrelated jitter, `min(cap, uniform(0.5, 3 x previous))`, never sleeping less than the server's Retry-After. It stops at the first of `max_retries` (8), the per-call `deadline_seconds` (900) or the provider's retry budget.

The budget is the piece that protects a degraded provider. Each provider starts with `retry_budget` tokens (500). Every retry after the first two of a call costs one, and every success refunds 0.1. When a whole provider is struggling, successes stop refilling it, the budget runs dry and cloudg stops multiplying the load. The first two retries of each call stay free, so a long run that drained the budget does not leave every later call without a single retry.

The SDKs keep their own retry loops, and cloudg plugs into them:

| Provider | Who retries | Settings that apply |
|---|---|---|
| AWS | botocore, via event hooks on every session cloudg builds | `aws.retry_mode` (adaptive), `aws.max_retries` (10 retries after the first attempt); the budget can end the loop |
| Azure | azure-core, with an explicit `RetryPolicy` and a per-attempt throttle policy | `ratelimit.azure.max_retries`, `max_backoff_seconds`, `deadline_seconds`, budget |
| GCP | google-api-core `Retry` per page | `ratelimit.gcp.max_backoff_seconds`, `deadline_seconds`, at most `max_retries` consecutive retries per page, budget |

`ratelimit.aws.max_retries`, `max_backoff_seconds` and `deadline_seconds` do not touch botocore. They only bound your own calls through `call_with_resilience`.

## How coverage records throttled scopes

Throttling never fails a map. A service that stayed throttled is recorded in coverage and the rest of the run continues.

Many AWS collectors catch per-item errors so that one bad resource does not stop a sweep. Before 0.6.0 that meant a collector whose calls were all throttled reported SUCCESS with fewer assets. Now a per-task ledger counts calls that gave up after retries and calls an open circuit skipped, and either turns the task's record PARTIAL:

```json
{"service": "vpc", "status": "SUCCESS", "asset_count": 2, "error": null}
{"service": "subnets", "status": "PARTIAL", "asset_count": 0, "error": "throttled: 1 call(s) gave up after retries (throttled: DescribeSubnets (retries exhausted): RequestLimitExceeded: Request limit exceeded.)"}
```

A collector that lets the error escape is recorded FAILED with an error starting `throttled:`. On Azure you get an `azure_<service>` record with FAILED and `azure_full` turns PARTIAL; on GCP the listing record says `listing truncated: throttled: ...`.

The run's numbers are attached to the result. `InventoryResult.throttling` is `None` unless something eventful happened (a throttle, a transient error, a give-up, a rejection, a breaker trip, or at least a second spent waiting for tokens), `summary["throttling"]` holds the short form, and `inventory-map.json` carries the full block under a top-level `throttling` key:

```json title="inventory-map.json (excerpt)"
"throttling": {
  "totals": {"calls": 2, "throttled": 11, "transient_errors": 0, "retries": 10,
             "gave_up": 1, "rejected": 0, "breaker_trips": 0, "wait_seconds": 0.949},
  "messages": [
    "aws/123456789012/us-east-1/ec2: throttled 11x, slowed to 5.0 rps, 10 retries, 1 calls gave up"
  ],
  "skipped": {
    "aws/123456789012/us-east-1/ec2": "throttled: DescribeSubnets (retries exhausted): RequestLimitExceeded: Request limit exceeded."
  },
  "scopes": {"...": "per-scope counters"},
  "breakers": {},
  "slowed_buckets": {
    "aws/123456789012/us-east-1/ec2/DescribeSubnets": {"rate_rps": 5.0, "ceiling_rps": 20.0, "throttles": 11}
  }
}
```

`cloudg map` logs each message at WARNING as `Throttling: <line>`. A scope that was never throttled but spent a long time queued for tokens gets a message too, such as `aws/123456789012/us-east-1/ec2: waited 418.6s for rate limit`, which is what an AMI-heavy region looks like at the default EC2 rates. `scopes` is per service; `slowed_buckets` and `breakers` are keyed at bucket granularity (here per EC2 action) and come from the process-wide governor when the run ended, so in a process running several collections they can include other runs' scopes.

Reading it from Python:

```python title="throttling_report.py"
from cloudg import CloudGConfig
from cloudg.inventory import InventoryMapper

config = CloudGConfig(providers=["aws"])
config.aws.regions = ["us-east-1", "eu-west-1"]

result = InventoryMapper(config).map_inventory_sync()

if result.throttling is None:
    print("no API pushed back")
else:
    for line in result.throttling["messages"]:
        print(line)
    for scope, reason in result.throttling["skipped"].items():
        print(f"incomplete: {scope}: {reason}")

for record in result.coverage:
    for svc in record.services:
        if svc.error and svc.error.startswith("throttled:"):
            print(record.account_id, record.region, svc.service, svc.status.value)
```

## Guard rails for live collections (MCP)

People rarely run `cloudg map` twice in a minute. An AI agent might. The MCP live tools (`map_inventory`, `collect_assets`, `run_scanners`, `run_pipeline`) therefore run inside a `LiveOperationGuard`:

- Identical concurrent calls share one run. The second caller gets the same result with `"joined": true`.
- At most `live_max_concurrent` (1) live operation per scope and `live_max_concurrent_total` (2) overall.
- After an operation touching a scope finishes, successfully or not, the scope cools down for `live_cooldown_seconds` (120). Failures cool down too, since a failure is often throttling.
- `live_caller_max_operations` per caller per `live_caller_window_seconds` is available but off (0).
- An operation still running after `live_operation_timeout_seconds` (3600) is cancelled and frees its scopes.

Scopes come from the config: `aws/<account>` per configured account, else `aws/profile:<name>`, else `aws`, and the equivalents for Azure subscriptions and GCP projects. A refusal is a tool error with code -31029 and `reason` `cooldown`, `busy` or `quota`, plus `retry_after_seconds` and a `use_dataset` pointer to the newest loaded live dataset covering the same providers. Principals with the `admin` or `operator` role can pass `force=true` to skip the cooldown, though not the concurrency caps.

The tool `rate_limit_status` and the resource `cloudg://ratelimit` show cooldowns, operations in flight and the governor's throttling state without calling any cloud API. Point agents at them before they reach for a live tool. These guard rails are separate from the MCP policy's per-principal rate limits, which decide how often someone may call a tool at all; see the [MCP server](/mcp/) section.

## Tuning the ratelimit block

Start from the defaults and read the run's `throttling` block before changing anything. Unset (`null`) limits use the built-ins, service overrides merge into the built-in table key by key, and a misspelled key anywhere under `ratelimit` is logged and ignored rather than failing the load:

```text
WARNING cloudg.config: Unknown config key ratelimit.aws.max_rpss is ignored
```

### One noisy service

Override that service, not the provider. For EC2 prefer an operation key, which slows one action instead of all of them:

```yaml title="config.yaml"
ratelimit:
  aws:
    services:
      resourcegroupstaggingapi: {max_rps: 1, burst: 2}    # a cost tool shares this quota
      ec2.DescribeImageAttribute: {max_rps: 5, burst: 10} # AMI-heavy region
```

:::warning An override replaces the whole built-in entry
`ec2: {max_rps: 10}` drops the built-in burst of 100 to 20 (twice the rate). Repeat the burst if you want to keep it: `ec2: {max_rps: 10, burst: 50}`. EC2 stays per action either way.
:::

### A shared or large estate

Throttling spread over many services of one account calls for `account_max_rps`; it is off for AWS, where an organization run across many regions could otherwise send 20 rps per service per region into one account. `global_max_rps` caps everything one process sends to a provider, whatever the account.

```yaml title="config.yaml"
ratelimit:
  aws:
    max_rps: 8                 # every account x region x service bucket
    burst: 16
    account_max_rps: 40        # all services of one account together
    global_max_rps: 200        # all of AWS from this process
    max_concurrency: 64        # requests in flight per account
    min_rps: 0.1
    breaker_cooldown_seconds: 120
    services:
      ec2: {max_rps: 10, burst: 50}
      iam: {max_rps: 4, burst: 8}
      cloudcontrol: {max_rps: 2, burst: 4}
  azure:
    account_max_rps: 10        # per subscription
    services:
      resourcegraph: {max_rps: 1, burst: 5}
  gcp:
    services:
      cloudasset.ListAssets: {max_rps: 0.5, burst: 5}
```

Lowering `max_rps` leaves headroom for the pipelines and people using the same quota. The cost is a longer run, and the adaptive limiter only reacts after the provider has already throttled someone.

### Breakers and budgets

Breakers opening on a flaky service: raise `breaker_threshold` rather than the cooldown. Set `per_operation: true` on a service to give each operation its own bucket and breaker. That only helps where scopes carry an operation, which is AWS and the GCP Cloud Asset RPCs; Azure scopes stop at the resource provider. When a provider is degraded as a whole, a lower `retry_budget` makes cloudg give up sooner.

```yaml title="config.yaml"
ratelimit:
  aws:
    breaker_threshold: 10
    retry_budget: 200
    services:
      ssm: {max_rps: 10, burst: 20, per_operation: true}
```

### Agents that collect too often

```yaml title="config.yaml"
ratelimit:
  live_cooldown_seconds: 600         # ten minutes between live maps of one scope
  live_caller_max_operations: 3      # per principal...
  live_caller_window_seconds: 3600   # ...per hour
  aws:
    live_cooldown_seconds: 900       # AWS scopes cool down longer
```

### Turning it off

`ratelimit.enabled: false` removes pacing, breakers, cloudg-level retries and the Azure retry overrides for every provider; botocore keeps its own retries from `aws.max_retries`. `ratelimit.<provider>.enabled: false` does the same for one provider. That is for benchmarks or a mock cloud, not for production estates.

The same settings from Python, for embedders:

```python title="tuned_config.py"
from cloudg import CloudGConfig
from cloudg.resilience import configure, get_governor

config = CloudGConfig.model_validate(
    {
        "providers": ["aws"],
        "ratelimit": {
            "aws": {"account_max_rps": 40, "services": {"iam": {"max_rps": 4, "burst": 8}}},
            "live_cooldown_seconds": 600,
        },
    }
)
configure(config)   # InventoryMapper and the collectors also do this for you
print(get_governor().budget("aws").remaining)
```

## What it does not cover

Learned rates and breaker state live in memory, so each new `cloudg map` process starts from the configured rates. A few calls are not instrumented yet: the GCP organization-policy and access-context-manager clients outside the asset listing, the urllib fallback that lists Azure subscriptions, and the single region-discovery call. A blocking boto3 or Azure call made on an event-loop thread goes ahead without a bulkhead slot when none is free, so `max_concurrency` is not a hard cap on that path. And per-item fan-out is now held to the documented rates, which makes some maps slower than in 0.5.x: 1,000 `DescribeImageAttribute` calls in one region take about 50 seconds at 20 rps.

:::links
- [cloudg.resilience](/api/resilience/) `call_with_resilience`, `@resilient`, the governor and the guard from Python.
- [ratelimit reference](/reference/config/ratelimit/) Every key with its default.
- [Inventory mapping](/guides/inventory-mapping/) Where coverage records come from.
:::
