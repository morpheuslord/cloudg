# Rate limits and throttling

cloudg 0.6.0 adds `cloudg.resilience`, a package that paces every cloud API call cloudg makes, reacts when a provider throttles, and records what happened in the run's coverage instead of failing the map. This document is for programmers: what the package does, how each provider is wired into it, every configuration key, what a throttled run looks like, the Python API, and what it does not cover yet.

Related documents: the [feature reference](https://github.com/morpheuslord/cloudg/blob/main/docs/DOCUMENTATION.md) (configuration and Python API chapters), the [MCP guide](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP.md) (section 15 covers the live tools) and the [MCP tool reference](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP_TOOLS.md).

Unless a section says otherwise, every number below was read from the code in `cloudg/resilience/` and `cloudg/config.py`, and every example output was produced by running the code shown.

## Contents

1. [Why it exists](#1-why-it-exists)
2. [How one call is paced](#2-how-one-call-is-paced)
3. [Provider wiring](#3-provider-wiring)
4. [Built-in limits](#4-built-in-limits)
5. [Configuration](#5-configuration)
6. [What you see when a provider throttles](#6-what-you-see-when-a-provider-throttles)
7. [Live operations and the MCP layer](#7-live-operations-and-the-mcp-layer)
8. [Python API](#8-python-api)
9. [Tuning](#9-tuning)
10. [Known limitations](#10-known-limitations)
11. [Testing](#11-testing)

## 1. Why it exists

A single `cloudg map -p aws --org --regions all` runs 133 deep collectors, a Cloud Control sweep and a tagging sweep in every region of every member account, and several collectors fan out per item (one `DescribeImageAttribute` call per AMI, for example). Azure is read per subscription through Resource Manager and Resource Graph, GCP per project or organization through Cloud Asset Inventory. Every one of those APIs has a request quota, and most of them are shared with whatever else runs in the account: CI pipelines, Terraform, the console, other auditors.

Up to 0.5.x, cloudg relied on each SDK's own retries. That works for one region of one account. At organization scale it had three problems. Clients did not know about each other, so forty concurrent EC2 clients in one account each backed off on their own and kept the account's bucket empty. A service that stayed throttled made its collector fail outright, which looked the same in coverage as an access error. And nothing remembered that an API had just pushed back.

The third problem got worse with the MCP layer. An AI agent can call `map_inventory` again a minute after the last run finished, and again after that, which a person running `cloudg map` would not do. Each repeat starts every collector from full speed against APIs that are still recovering.

The package addresses those with one shared, process-wide governor:

- calls are paced by token buckets shared by every client in the process, set at or below each provider's published limits;
- a throttled scope slows down for everyone using it and speeds up again gradually;
- a service that stays throttled is cut off by a circuit breaker for a while, and the rest of the map continues;
- the outcome is recorded: coverage says `throttled: ...`, and the map carries a `throttling` block with per-scope counters;
- live collections triggered through MCP are deduplicated, capped and cooled down.

## 2. How one call is paced

```text
call_with_resilience(fn, scope)
  1. circuit breaker      open?  -> CircuitOpenError, no request sent
  2. deadline             spent? -> DeadlineExceededError
  3. rate limiter         provider bucket, account bucket, leaf bucket (adaptive)
  4. bulkhead             in-flight cap per provider x account
  5. fn(...)              the API call
  6. on error             FATAL      -> re-raise at once
                          THROTTLED  -> halve the scope's rate, pause for Retry-After
                          THROTTLED or TRANSIENT -> sleep (decorrelated jitter,
                            never less than Retry-After) and go to 1, while
                            retries, deadline and retry budget allow
                          otherwise  -> breaker counts a failure, re-raise
  every step is counted in the run's stats; give-ups also go to the task's
  throttle ledger, which turns its coverage record PARTIAL
```

That is the full sequence of `call_with_resilience`. The SDK integrations in [section 3](#3-provider-wiring) reuse the same parts but let the SDK do the retrying, so not every step applies to every provider. The table in [section 5.4](#54-where-each-key-takes-effect) says which.

### 2.1 Scopes

Every call is attributed to a `Scope(provider, account, region, service, operation)`. Its string form is what you see in telemetry: `aws/123456789012/us-east-1/ec2`, with `*` for a missing part and the operation appended when there is one (`aws/123456789012/us-east-1/ec2/DescribeSubnets`).

| Provider | account | region | service | operation |
|---|---|---|---|---|
| AWS | the account id the session was instrumented with; `*` for the base session before role assumption | the client's region | botocore service name (`ec2`, `iam`, `sts`) | API name (`DescribeSubnets`) |
| Azure | subscription id, lowercased; none for Resource Graph | none | resource-provider namespace without `Microsoft.` (`network`, `compute`, `storage`); `resources` for paths without one; `resourcegraph` | none |
| GCP | `projects/<id>`, `organizations/<id>` or `folders/<id>` | none | `cloudasset` | RPC name (`ListAssets`, `SearchAllResources`, `SearchAllIamPolicies`) |

Telemetry is aggregated per service scope (operation removed). Rate-limiter leaf buckets, and the circuit breakers with them, go down to the operation where the service is configured that way (section 2.3).

### 2.2 Classifying errors

`classify(exc)` (in `errors.py`) sorts any exception into one of three kinds. It imports no SDK; it reads the shapes by duck typing.

| Kind | Meaning | Examples |
|---|---|---|
| `THROTTLED` | the provider asked cloudg to slow down | AWS `Throttling`, `ThrottlingException`, `RequestLimitExceeded`, `TooManyRequestsException`, `SlowDown`, `RateExceeded` and the rest of botocore's standard-mode list; Azure `RateLimiting`, `SubscriptionRequestsThrottled`, `TenantRequestsThrottled`; GCP `ResourceExhausted`, `TooManyRequests`, and `ServiceUnavailable`, which carries HTTP 503; any other HTTP 429 or 503 without a more specific code |
| `TRANSIENT` | worth retrying, not a rate signal | HTTP 408, 500, 502, 504; AWS `InternalError`, `ServiceUnavailable` (the error code wins over its 503 status), `RequestTimeout`; GCP `DeadlineExceeded`, `InternalServerError`; connection resets and timeouts from botocore, urllib3, aiohttp, httpx and azure-core |
| `FATAL` | retrying will not help | `AccessDenied`, validation errors, anything else with a provider error code |

Where it looks, in order: the botocore `response["Error"]["Code"]` and HTTP status; azure-core `status_code`, `error.code` and `response.headers`; google-api-core exception class names (along the MRO) and `.code`; urllib `HTTPError.code` and `.headers`; aiohttp `.status`. For wrapped errors it follows `exc.cause` (api_core `RetryError`) and explicit `raise ... from` chains, up to four levels, and never the implicit `__context__`. Only when nothing else matched does it search the message text for phrases such as "rate exceeded", "throttl" or "too many requests".

Two codes need context. AWS `LimitExceededException` is also used for "too many resources" quotas, so it counts as throttling only when the message mentions a rate (`rate`, `throttl`, `too many`, `per second`, `tps`); otherwise it is FATAL. Azure `RetryableErrorDueToAnotherOperation` arrives as a 429 but is a lock conflict, so `classify()` calls it TRANSIENT. The Azure SDK policy ([3.2](#32-azure-resource-manager)) sees only the response status, though, and treats every 429 as throttling.

`retry_after(exc)` returns the delay the server asked for, in seconds, from the first of these it finds: `retry-after-ms` or `x-ms-retry-after-ms` (milliseconds), `Retry-After` as delta-seconds or an HTTP-date, Resource Graph's `x-ms-user-quota-resets-after` as `hh:mm:ss` (used when `x-ms-user-quota-remaining` is `0` or missing, or the status is 429), and gRPC `RetryInfo.retry_delay`. `describe_error(exc)` is `str(exc)` with a `throttled: ` prefix for throttling errors; every coverage record in the collectors goes through it.

`classify_strict(exc)` is `classify()` without the message-text search: it returns `None` when no error code, exception class or HTTP status says anything. `is_provider_answer(exc)` is true when the error carries a provider status or error code, that is, the request reached the service and it answered; cloudg's own errors and local failures are not answers. `cloudg.retry.with_retry` uses the two together, so it retries throttling only when the provider itself said so.

cloudg's own errors (`CircuitOpenError`, `RetryBudgetExhaustedError`, `DeadlineExceededError`) carry `retry_after` and a botocore-shaped `.response`, so existing error-code helpers report them. The first two classify as THROTTLED, the deadline error as TRANSIENT. An instrumented AWS client raises them as `AWSCircuitOpenError` and `AWSRetryBudgetExhaustedError` (in `resilience/aws.py`), which are also botocore `ClientError`s with the code `Throttling`, so code that wraps its calls in `except ClientError` keeps catching them.

### 2.3 Token buckets and levels

`RateLimiter` keeps one token bucket per key. A call takes a token from up to three buckets, most general first, and waits for the slowest:

1. a provider-wide bucket (`global_max_rps`; off for every provider by default);
2. an account bucket (`account_max_rps`; on by default only for Azure, 20 rps per subscription, because ARM's limit is per subscription);
3. a leaf bucket per account x region x service. The leaf goes down to the operation when the service is marked `per_operation` (built in for AWS `ec2`, which throttles each API action separately) or when an override exists for `"<service>.<Operation>"`.

A bucket refills at `rate` tokens per second up to `capacity` (the `burst`, or twice the rate when no burst is given, never below 1). Buckets work by reservation: taking a token never blocks while the limiter's lock is held. The balance may go negative, and the caller gets back the number of seconds to wait before using its token. That queues callers fairly, in arrival order, and lets one limiter serve asyncio code (`await limiter.acquire(scope)`) and worker threads (`limiter.acquire_sync(scope)`) at the same time.

### 2.4 Adaptive rate (AIMD)

Every leaf bucket adjusts its own rate the way TCP congestion control does, additive increase and multiplicative decrease:

- When a call in the scope is throttled, the bucket's rate is halved (`DECREASE_FACTOR = 0.5`), never below the provider's `min_rps`, and its stored burst is drained so queued callers cannot all fire at once. Throttles that arrive within one second of the last decrease (`DECREASE_INTERVAL`) count as the same congestion event, so forty simultaneous 429s halve the rate once, not forty times.
- When the provider sent a Retry-After hint, the bucket is also paused for that long (capped at 300 seconds, `MAX_PAUSE_SECONDS`, to survive bogus headers). Every caller of the scope waits.
- After five seconds without a throttle (`INCREASE_INTERVAL`), each success adds 5% of the configured ceiling back (`INCREASE_STEP`, at least 0.01 rps), at most once per five seconds, until the configured rate is reached. Capacity scales with the rate.

In numbers: an EC2 action at its 20 rps ceiling that gets throttled twice, a second apart, runs at 5 rps. Steady success then adds 1 rps every five seconds, so it is back at 20 rps after about 75 seconds without another throttle. botocore's `adaptive` retry mode does something similar per client; the difference is that this state is shared by every client of the process.

The provider-wide and account buckets do not adapt; only leaves do. `adaptive: false` keeps a provider's rates fixed.

### 2.5 Bulkhead

`Bulkhead` caps the requests in flight per provider x account (`max_concurrency`: AWS 128, Azure 16, GCP 16). It is one slot pool shared by asyncio tasks and threads: async callers await a free slot without blocking the loop, threads block. What holds a slot depends on the integration:

| Integration | One slot is held for |
|---|---|
| AWS hooks | one API call, from `before-call` (after the rate token) until `after-call` or `after-call-error`, so botocore's retries of that call reuse the slot |
| Azure policy | one HTTP attempt, from `on_request` until `on_response` or `on_exception` |
| GCP | one whole Cloud Asset listing, every page included |
| `call_with_resilience` | one attempt |

The SDK hooks keep the slot (a `Slot` object) in the request context. If neither release event fires, for example because the task was cancelled between the SDK's events, the slot is released when the request context is garbage collected. A blocking boto3 or Azure call that runs on an event-loop thread takes a slot only if one is free and otherwise goes ahead without one, so it never blocks the loop.

### 2.6 Circuit breakers

`BreakerRegistry` holds one breaker per breaker scope, which has the same granularity as the scope's leaf bucket: per operation where buckets are per operation (built in for EC2, or any service with `per_operation: true` or an operation key), per service otherwise. A throttled `DescribeSubnets` no longer blocks `DescribeVpcs` in the same account and region. The breaker of a scope moves through three states:

- Closed: calls flow. Each call that still failed with throttling or a transient error after its retries counts as one failure; any success resets the count. Calls the open circuit rejected were never sent and do not count, and neither does a call that stopped because the retry budget ran out: the budget stopped it, not the service.
- Open: after `breaker_threshold` (default 5) consecutive failures, calls are rejected at once with `CircuitOpenError`, whose message is `circuit open for <scope> after repeated throttling; retry in <n>s`, for `breaker_cooldown_seconds` (default 60).
- Half-open: after the cooldown one probe call goes through. Success closes the breaker and restores the base cooldown; failure reopens it with the cooldown doubled, up to 600 seconds. The probe holds a lease of one cooldown: if it never reports back (it was cancelled, or ended before it was sent), the lease runs out and the next call becomes the probe, so a breaker cannot stay half-open with nobody probing.

A FATAL answer from the provider (`AccessDenied`, a 404, a validation error) never counts as a failure, so an `AccessDenied` storm never opens a circuit. It does prove that the service is reachable, so it counts like a success: it resets the failure count and closes a half-open breaker. FATAL errors raised locally, without a provider status or code, leave the breaker alone.

### 2.7 Retries

`call_with_resilience` retries THROTTLED and TRANSIENT errors. The sleep before each retry is decorrelated jitter, `min(cap, uniform(base, 3 x previous))` with `base = 0.5` seconds and `cap = max_backoff_seconds` (60), as described in the AWS Architecture Blog post "Exponential Backoff And Jitter". It is never shorter than the server's Retry-After. Retrying stops at the first of:

- `max_retries` retries (8 by default);
- the per-call deadline (`deadline_seconds`, 900): a backoff or a rate-limit wait that would overrun it ends the call with the original error or `DeadlineExceededError`;
- the provider's retry budget (`retry_budget`, 500): every retry after the first two of a call costs one token, every success refunds 0.1, and when a whole provider is degraded the budget runs dry and cloudg stops retrying instead of multiplying the load. The first two retries of every call are free, so a long run that spent the budget does not leave every later call without a single retry. This is the "retry quota" of the AWS SDKs' standard mode. The budget is shared by every integration of the provider: the SDK hooks draw from it too (section 3), and an empty budget ends the SDK's own retry loop with `RetryBudgetExhaustedError`, recorded as a throttled give-up.

When retrying stops, the original exception is re-raised, the breaker counts a failure, and for throttling the scope is recorded as given up.

### 2.8 Telemetry

`ResilienceStats` counts per service scope: `calls`, `throttled`, `transient_errors`, `retries`, `gave_up`, `rejected` (never attempted because a circuit was open), `breaker_trips`, `waits`, `wait_seconds`, `max_wait_seconds`, the current and lowest adaptive rate, and the last error. `summary()` returns `totals`, one human-readable line per eventful scope in `messages`, the abandoned scopes with their reason in `skipped`, and the full per-scope counters in `scopes`.

The governor writes every event twice: into its lifetime stats, and into the stats object bound to the current context by `stats_scope()`. The binding is a context variable, so asyncio tasks and `asyncio.to_thread` workers started inside the block inherit it, and two runs in one process (two MCP-triggered collections, say) keep separate numbers.

What `calls` counts depends on the integration: one per API call for AWS (botocore retries happen inside the call), one per HTTP attempt for Azure, one per first request and per further page for GCP, and one per attempt for `call_with_resilience`.

### 2.9 Coverage

`ThrottleLedger` is a per-task variant of the stats. The AWS collector binds one around every service task. Many collectors catch per-item errors so one bad resource does not stop the sweep; before 0.6.0 that meant a collector whose calls were all throttled reported SUCCESS with fewer assets. Now the ledger counts two kinds of lost calls: `gave_up` (sent, retried, still throttled) and `skipped` (rejected by an open circuit without being sent). If either is non-zero (`ledger.degraded`), the task's coverage record becomes PARTIAL with a message such as `throttled: 1 call(s) gave up after retries, 2 call(s) skipped (circuit open) (<up to five reasons>)`.

### 2.10 The governor

`Governor` (`governor.py`) owns the limiter, the breakers, the per-provider retry settings and budgets, and the lifetime stats. There is one per process, returned by `get_governor()`. That is deliberate: rates learned while one collection was throttled keep protecting the next one, which is the point when an agent triggers live maps back to back.

`configure(config)` applies a `CloudGConfig`, a `RateLimitConfig` or a plain dict, and is idempotent: buckets and breakers are rebuilt only for providers whose settings changed, and budgets are reset only when retry settings changed. A provider whose settings did not change keeps its learned rates, its breakers, its budget and the concurrency slots its calls hold, so two runs that configure the same governor do not reset each other. `MultiAccountCollector` and `InventoryMapper` both call it (and `InventoryMapper.map_inventory()` reuses a stats scope its caller already bound, so an outer `stats_scope()` sees the whole run), so every entry point picks up `config.ratelimit`, `aws.max_retries` and `aws.retry_mode`. Anything else passed to `configure` (a test double, `None` aside) is ignored. `reset_governor()` replaces the process governor with a fresh default one and forgets everything learned; it exists for tests.

## 3. Provider wiring

### 3.1 AWS

`install_aws_hooks(session, account_id, region, default_config=...)` (`resilience/aws.py`) registers four handlers on a boto3 or aioboto3 session's event emitter. Every client created from that session afterwards is covered, paginators included, without touching the collectors:

| Event | What the hook does |
|---|---|
| `before-call` | Resolves the scope, fails fast with `AWSCircuitOpenError` if the scope's breaker is open, counts the call, takes a limiter token, then a slot of the account's bulkhead |
| `needs-retry` | A throttled attempt halves the scope's rate and honours Retry-After; transient errors are counted. Every retry botocore is about to make, throttled or transient, costs one token of the retry budget, except the first two retries of the call; when the budget is empty the hook raises `AWSRetryBudgetExhaustedError`, which ends botocore's retry loop. A throttled retry also waits for a fresh rate token, on top of botocore's own backoff |
| `after-call` | Releases the bulkhead slot. 2xx/3xx feeds additive recovery and closes the breaker. An error that survived botocore's retries goes to the governor's `on_final_error`: throttling counts toward the breaker and is recorded as given up (stats and the task's ledger), a transient error counts toward the breaker, and a FATAL provider answer counts as proof that the service is reachable |
| `after-call-error` | The same for exceptions (connection errors and the like). A spent retry budget is recorded as given up without a breaker failure, and a call the open circuit refused is not recorded again |

aiobotocore awaits coroutine handlers, so the aioboto3 hooks never block the event loop. Plain boto3 sessions get blocking handlers; when such a call runs on an event-loop thread, the token wait is capped at one second (`MAX_INLINE_WAIT`) so the loop is not stalled. The token is still consumed.

Installation is idempotent (a marker on the botocore session) and never breaks authentication: any error while installing is logged at DEBUG and the session is used as is. Where it is installed:

- `AsyncAWSCollector._get_aio_session()`: the aioboto3 session behind every core and deep collector (all 133 deep collector tasks), the Cloud Control and tagging sweeps and the per-item fan-out, scoped to the collector's account and region.
- `credentials.build_aws_session()`: the base boto3 session (account `*`, since the account is not known yet) and, after STS AssumeRole, the assumed session (with the target account id). That covers STS, Organizations and Control Tower discovery and the per-account sessions of the organization fan-out.

`default_config` becomes the session's default client config when it has none, so clients created without `config=` still get the configured retries.

botocore keeps doing the per-request retrying. Its settings now come from `aws.retry_mode` and `aws.max_retries`, which earlier releases accepted in the config but ignored (cloudg hard-coded adaptive mode and 10). The defaults are unchanged. botocore reads `max_attempts` in the `retries` dict as the number of retries after the first attempt, so the default `max_retries: 10` allows up to 11 attempts per call; the integration tests check exactly that (with `max_retries: 3`, a throttled operation is sent four times). `ratelimit.aws.max_retries`, `max_backoff_seconds` and `deadline_seconds` are different settings: they bound cloudg-level retries in `call_with_resilience`, not botocore's. Per-call time limits on AWS stay botocore's job (its connect and read timeouts together with the retry count).

### 3.2 Azure Resource Manager

Every azure-mgmt client cloudg builds goes through `build_azure_client(cls, ...)` (`resilience/azure.py`): the collector's per-kind clients, `resource_management_client`, `subscription_client` and the Resource Graph client. It adds two keyword arguments to the constructor:

- `retry_policy`: an explicit azure-core `RetryPolicy(retry_total=8, retry_status=8, retry_backoff_max=60, timeout=900)`, taken from `ratelimit.azure.max_retries`, `max_backoff_seconds` and `deadline_seconds`. azure-core's default allows only 3 status retries; its `RetryPolicy` already honours `Retry-After` on 429 and 503. The values were checked on a real ARM client;
- `per_retry_policies=[AzureThrottlePolicy]`, which runs around every HTTP attempt, retries included.

The policy resolves the scope from the request URL (subscription and the last `Microsoft.<Namespace>` segment), fails fast on an open breaker, counts the call, takes a token (subscription bucket, then the resource-provider leaf) and a slot of the subscription's bulkhead. On the response, or on an exception, the slot is released, and then:

- 429 or 503: the scope's rate is halved and paused for `Retry-After`, or for `x-ms-user-quota-resets-after` when that is the only hint;
- 429, 503, 408, 500, 502 or 504: the response costs one token of the retry budget, because azure-core is about to retry it (the first two retries of a request are free). When the budget is empty the policy raises `RetryBudgetExhaustedError`, which ends azure-core's retry loop and is reported as throttling. The token is taken even on the last attempt, which azure-core would not retry;
- other 4xx: nothing;
- success: additive recovery and breaker reset, then two proactive checks. `x-ms-user-quota-remaining: 0` pauses the Resource Graph scope until `x-ms-user-quota-resets-after`. `x-ms-ratelimit-remaining-subscription-reads` below 25 pauses the subscription's aggregate bucket for one second, which holds every call of that subscription, whatever the resource provider, because ARM refills about 25 tokens a second. With no account limit configured, the pause falls back to the resource provider's bucket.

If a client class rejects the extra keyword arguments (an old SDK, a test double), `build_azure_client` logs at DEBUG and builds it plainly. When a service still fails, the collector records `service_errors[name] = describe_error(exc)`; for throttling it also reports the scope as given up so the breaker counts it. `MultiAccountCollector` turns each service error into an `azure_<service>` coverage record with status FAILED and marks `azure_full` PARTIAL.

### 3.3 Azure Resource Graph

Resource Graph allows 15 queries per 5-second window per user, so it has its own scope, `azure/*/*/resourcegraph` (no subscription: the quota follows the caller, not the subscription), at 3 rps with a burst of 15.

`_fetch_page` in `cloudg/inventory/azure_graph/query.py` handles one page:

- Clients from `default_graph_client_factory` are built with `build_azure_client`, so the throttle policy paces every HTTP attempt inside the SDK pipeline and reads the quota headers. `_fetch_page` notices that (`_cloudg_throttle_policy` on the client) and does not take a second token.
- Clients from a custom factory are paced by `_fetch_page` itself: breaker check and one token per page.
- A client built with the throttle policy already retries 429 inside its azure-core pipeline, so a 429 that reaches `_fetch_page` from it is final: it is recorded (`on_final_error`) and raised, not retried a second time.
- For a client from a custom factory, a 429 slows the scope down and is retried up to `QueryLimits.max_retries` (5) times, with a back-off of 2, 4, 8, 16 then 30 seconds. The limiter, which is paused for the server's hint, waits the hint out; with the limiter switched off the back-off itself is stretched to the hint, capped at 300 seconds. After the last retry the query is recorded as given up and the error is raised.

### 3.4 GCP Cloud Asset Inventory

`GCPCollector._iterate` drains one paged call (ListAssets, SearchAllResources or SearchAllIamPolicies) in a worker thread:

1. breaker check, one token and one counted call for `gcp/<parent>/*/cloudasset/<Rpc>`, then one bulkhead slot for the whole listing (`max_concurrency` concurrent listings per project or organization);
2. the call itself, with `retry=gcp_retry(scope, counter=...)`: a google-api-core `Retry` on `ResourceExhausted`, `ServiceUnavailable`, `DeadlineExceeded` and `InternalServerError`, starting at 1 second, doubling, capped at `ratelimit.gcp.max_backoff_seconds` (60), with an overall timeout of `deadline_seconds` (900). Its `on_error` reports each retried error to the governor, so throttling halves the rate and `RetryInfo` delays pause it. It also enforces two limits api_core does not have: each retry after the first two of a page costs a retry-budget token, and at most `ratelimit.gcp.max_retries` (8) consecutive retries are made per page (a `RetryCounter` shared with `paced` resets on every page that arrives). Past either limit, `on_error` raises `RetryBudgetExhaustedError`, chained to the provider error, which ends api_core's retry loop;
3. `paced(...)` around the pager takes a token every `page_size` items, just before the pager fetches the next page. It does not check the breaker again: the breaker was checked once for the whole listing in step 1, so a listing that is a half-open breaker's probe is not rejected by its own breaker on page 2. Pages are fetched lazily while iterating, so this keeps org-wide listings under the per-minute quotas. With short pages it is approximate, never off by more than one page per short page.

If the listing still fails, throttling is recorded as given up and transient errors count toward the breaker. `_iterate` returns what it collected so far plus the error, and the caller records `listing truncated: throttled: ...` (PARTIAL), or FAILED when nothing came back, and falls back to `SearchAllResources` when `ListAssets` is unavailable. `GCPDeepInventoryCollector` labels its IAM policy search the same way.

## 4. Built-in limits

The defaults sit at or just below each provider's documented limits, so they bind only where the provider would throttle anyway. They live in `BUILTIN_LIMITS` in `cloudg/resilience/limiter.py`, with the same sources in comments.

| Provider | Bucket | Rate (rps) | Burst | Source and reasoning |
|---|---|---|---|---|
| AWS | default leaf, per account x region x service | 20 | 40 | general default |
| AWS | `ec2`, one bucket per API action | 20 | 100 | EC2 non-mutating actions: bucket capacity 100, refill 20/s, per action, per account and region ([EC2 API throttling](https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-throttling.html)) |
| AWS | `sts` | 50 | 100 | STS default quota is 600 RPS per account and region; cloudg stays far below it ([IAM and STS quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)) |
| AWS | `lambda` | 15 | 15 | "Rate of control plane API requests" quota, 15/s ([Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)) |
| AWS | `route53` | 5 | 5 | five requests per second per account ([Route 53 limits](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html)) |
| AWS | `resourcegroupstaggingapi` | 5 | 10 | `GetResources` has a low per-account TPS quota; about 10 TPS is commonly observed, there is no published figure, cloudg uses half ([GetResources](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html)) |
| AWS | `organizations`, `cloudformation`, `cloudcontrol` | 5 | 10 | no published TPS, throttle early; conservative |
| AWS | `controltower` | 2 | 5 | same |
| AWS | `iam` | 10 | 40 | same |
| AWS | account, provider-wide | off | | |
| Azure | subscription (account bucket) | 20 | 200 | ARM subscription reads: 250-token bucket refilled at 25/s, per region per principal; 20% headroom ([ARM throttling](https://learn.microsoft.com/azure/azure-resource-manager/management/request-limits-and-throttling)) |
| Azure | default leaf, per subscription x resource provider | 15 | 100 | general default |
| Azure | `network` | 30 | 200 | Microsoft.Network reads: 10,000 per 5 minutes |
| Azure | `storage` | 0.33 | 20 | Storage resource provider list operations: 100 per 5 minutes |
| Azure | `resourcegraph`, per user | 3 | 15 | 15 queries per 5-second window per user ([Resource Graph throttling](https://learn.microsoft.com/azure/governance/resource-graph/concepts/guidance-for-throttled-requests)) |
| GCP | default leaf, per project or organization x API | 10 | 20 | general default |
| GCP | `cloudasset.ListAssets` | 1.5 | 10 | 100 requests per minute per consumer project, 800 per minute per organization ([Asset Inventory quotas](https://cloud.google.com/asset-inventory/docs/quota)) |
| GCP | `cloudasset.SearchAllResources`, `cloudasset.SearchAllIamPolicies` | 6 | 20 | 400 requests per minute per consumer project (same page) |

Other defaults:

| Setting | AWS | Azure | GCP |
|---|---|---|---|
| Adaptive floor (`min_rps`) | 0.2 | 0.1 | 0.05 |
| In-flight requests per account (`max_concurrency`) | 128 | 16 | 16 |
| Breaker threshold / cooldown | 5 / 60 s | 5 / 60 s | 5 / 60 s |
| `max_retries` / `max_backoff_seconds` / `deadline_seconds` | 8 / 60 s / 900 s | same | same |
| Retry budget | 500 | 500 | 500 |
| SDK retries | botocore: `aws.retry_mode` adaptive, `aws.max_retries` 10 | azure-core `RetryPolicy`: 8 total and status retries, 900 s timeout | api_core `Retry`: 900 s timeout, at most 8 consecutive retries per page |

Live operation guard: 120-second cooldown per scope, one live operation per scope, two overall, no per-caller quota, a one-hour operation timeout ([section 7](#7-live-operations-and-the-mcp-layer)).

## 5. Configuration

Everything sits under `ratelimit` in `config.yaml` (`CloudGConfig.ratelimit`, a `RateLimitConfig`). The section is additive: a config without it behaves exactly as the built-in defaults above. Unset (`null`) provider limits fall back to the built-ins; service overrides are merged into the built-in service table key by key.

A key that is not part of the models below, at any level of `ratelimit` (`ratelimit`, `ratelimit.<provider>`, `ratelimit.<provider>.services.<name>`), is ignored with a warning, and the rest of the config still loads:

```text
WARNING cloudg.config: Unknown config key ratelimit.aws.max_rpss is ignored
```

### 5.1 `ratelimit`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. `false` turns off pacing, breakers, cloudg-level retries and the Azure retry overrides for every provider. botocore keeps its own retries from `aws.max_retries` / `aws.retry_mode`, and coverage still labels throttling errors |
| `aws`, `azure`, `gcp` | `ProviderRateLimitConfig` | all defaults | Per-provider settings (5.2) |
| `live_cooldown_seconds` | float >= 0 | `120` | Minimum time between two live collections of the same scope |
| `live_max_concurrent` | int, 1 to 64 | `1` | Live collections allowed at once per scope |
| `live_max_concurrent_total` | int, 1 to 256 | `2` | Live collections allowed at once overall |
| `live_caller_max_operations` | int >= 0 | `0` | New live collections per caller per window; 0 means unlimited |
| `live_caller_window_seconds` | float > 0 | `3600` | Length of that window |
| `live_operation_timeout_seconds` | float > 0 or null | `3600` | A live collection running longer is cancelled and its scopes freed; null means no limit |

### 5.2 `ratelimit.<provider>`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Pace and circuit-break this provider. `false` makes its calls go straight to the SDK |
| `max_rps` | float > 0 or null | built-in (AWS 20, Azure 15, GCP 10) | Default leaf rate per account x region x service |
| `burst` | float > 0 or null | built-in (AWS 40, Azure 100, GCP 20) | Default leaf capacity |
| `account_max_rps` | float > 0 or null | built-in (Azure 20, others off) | Aggregate rate per account, subscription or project |
| `account_burst` | float > 0 or null | built-in (Azure 200), else twice `account_max_rps` | Capacity of the account bucket |
| `global_max_rps` | float > 0 or null | off | Aggregate rate for every call to this provider in the process |
| `global_burst` | float > 0 or null | twice `global_max_rps` | Capacity of the provider-wide bucket |
| `max_concurrency` | int, 1 to 1024, or null | built-in (AWS 128, others 16) | Requests in flight per account (bulkhead, section 2.5) |
| `adaptive` | bool | `true` | Halve a scope's rate on throttling and recover additively |
| `min_rps` | float > 0 or null | built-in (AWS 0.2, Azure 0.1, GCP 0.05) | Floor of the adaptive rate |
| `breaker_threshold` | int, 1 to 1000 | `5` | Consecutive calls that failed on throttling or transient errors after their retries before the circuit opens |
| `breaker_cooldown_seconds` | float >= 0 | `60` | How long an open circuit rejects calls before a probe; doubles on each failed probe up to 600 |
| `max_retries` | int, 0 to 50 | `8` | Retries of a throttled or transient call: azure-core `retry_total` / `retry_status`, consecutive api_core retries per GCP page, `call_with_resilience`. AWS SDK retries use `aws.max_retries` |
| `max_backoff_seconds` | float > 0 | `60` | Cap of one backoff sleep: azure-core `retry_backoff_max`, api_core `Retry(maximum=)`, `call_with_resilience` |
| `deadline_seconds` | float > 0 | `900` | Overall time for one call including retries: azure-core `RetryPolicy(timeout=)`, api_core `Retry(timeout=)`, `call_with_resilience` |
| `retry_budget` | int >= 0 | `500` | Retries per provider, across every integration, before retrying stops; each success refunds 0.1 |
| `services` | map of name to `ServiceRateLimitConfig` | `{}` | Per-service or per-operation overrides (5.3) |
| `live_cooldown_seconds` | float >= 0 or null | null | Overrides `ratelimit.live_cooldown_seconds` for live scopes of this provider |

### 5.3 `ratelimit.<provider>.services.<name>`

The key is the SDK service name (AWS: `ec2`, `iam`, `sts`, `s3`, ...; Azure: `network`, `compute`, `storage`, `resources`, `resourcegraph`, ...; GCP: `cloudasset`) or `<service>.<Operation>` for one operation (`ec2.DescribeImageAttribute`, `cloudasset.ListAssets`). An operation key always gets its own bucket.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `max_rps` | float > 0, required | | Sustained requests per second |
| `burst` | float > 0 or null | twice `max_rps` | Bucket capacity. An override replaces the whole built-in entry, so give the burst again if you want to keep it (the built-in `ec2` burst of 100 becomes 20 if you set only `max_rps: 10`) |
| `per_operation` | bool or null | the built-in choice (true for AWS `ec2`) | One bucket, and one circuit breaker, per API operation instead of one per service |

### 5.4 Where each key takes effect

The four integrations are the AWS hooks (botocore event hooks on every boto3 and aioboto3 session cloudg builds), the Azure policy (the per-attempt pipeline policy plus the explicit `RetryPolicy` on every Azure SDK client, Resource Graph included), the GCP Cloud Asset Inventory listings, and `call_with_resilience` for your own code.

| Key | AWS hooks | Azure policy | GCP listings | `call_with_resilience` |
|---|---|---|---|---|
| `enabled`, `max_rps`, `burst`, `services` (with `per_operation`) | yes | yes | yes | yes |
| `account_max_rps`, `account_burst` | yes | yes (default 20 / 200) | yes | yes |
| `global_max_rps`, `global_burst` | yes | yes | yes | yes |
| `adaptive`, `min_rps` | yes | yes | yes | yes |
| `breaker_threshold`, `breaker_cooldown_seconds` | yes (per operation for EC2) | yes | yes | yes |
| `max_concurrency` | per API call, per account | per HTTP attempt, per subscription | per concurrent listing, per project or organization | per call |
| `retry_budget` | yes, stops botocore's retries | yes, stops azure-core's retries | yes, stops api_core's retries | yes |
| `max_retries` | no: botocore uses `aws.max_retries` | `retry_total` and `retry_status` | consecutive retries per page | yes |
| `max_backoff_seconds` | no: botocore's own backoff | `retry_backoff_max` | api_core `Retry` maximum | yes |
| `deadline_seconds` | no: botocore's timeouts and `aws.max_retries` bound a call | `RetryPolicy` timeout (whole operation) | api_core `Retry` timeout | yes |
| `aws.max_retries`, `aws.retry_mode` | botocore retries (counted after the first attempt; default adaptive, 10) | n/a | n/a | n/a |
| `live_*`, `<provider>.live_cooldown_seconds` | `LiveOperationGuard` only | | | |

In every integration the first two retries of a call (of a page, for GCP) are free and never draw on `retry_budget`.

Resource Graph pages fetched through `_fetch_page` with a client from a custom factory also retry a 429 up to `QueryLimits.max_retries` (5) times themselves; clients cloudg builds leave that to azure-core (section 3.3).

### 5.5 Examples

An organization-wide AWS map with many accounts, plus Azure and GCP estates that other teams also query. This leaves more of each account's quota to everyone else and keeps one account from absorbing the whole run:

```yaml
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
      ec2: {max_rps: 10, burst: 50}            # still one bucket per EC2 action
      iam: {max_rps: 4, burst: 8}
      cloudcontrol: {max_rps: 2, burst: 4}
  azure:
    account_max_rps: 10        # per subscription
    services:
      resourcegraph: {max_rps: 1, burst: 5}
  gcp:
    services:
      cloudasset.ListAssets: {max_rps: 0.5, burst: 5}
  live_cooldown_seconds: 600
```

One noisy service. The tagging API in this account is shared with a cost tool that already uses most of its quota, and one AMI-heavy region needs its attribute calls slowed down without touching the rest of EC2:

```yaml
ratelimit:
  aws:
    services:
      resourcegroupstaggingapi: {max_rps: 1, burst: 2}
      ec2.DescribeImageAttribute: {max_rps: 5, burst: 10}
```

Turning it off, everywhere or for one provider:

```yaml
ratelimit:
  enabled: false
```

```yaml
ratelimit:
  gcp:
    enabled: false
```

All four examples were loaded through `CloudGConfig.model_validate` and `Governor(config)` to check the resulting limits. In code:

```python
from cloudg import CloudGConfig

config = CloudGConfig.model_validate(
    {"ratelimit": {"aws": {"max_rps": 8, "services": {"iam": {"max_rps": 4}}}}}
)
config.ratelimit.live_cooldown_seconds = 600
```

The shipped `config.yaml` has a commented `ratelimit` section with the defaults.

## 6. What you see when a provider throttles

Throttling never fails a map. A service that stayed throttled after its retries is recorded in coverage, the rest of the run continues, and the run's numbers end up in the result.

To produce the output below, a test-style script ran the AWS collector's `vpc` and `subnets` tasks against moto, with every `DescribeSubnets` request answered by `RequestLimitExceeded` and botocore's sleep removed. It used the default `aws.max_retries: 10` and `retry_mode: standard`, wrapped the run in `stats_scope()`, and built an `InventoryResult` from the coverage and `get_governor().summary(stats)`.

botocore sent `DescribeSubnets` 11 times (one attempt plus 10 retries). The subnet collector catches its own errors and returned nothing, and the ledger turned that into PARTIAL:

```json
{"service": "vpc", "status": "SUCCESS", "asset_count": 2, "error": null}
{"service": "subnets", "status": "PARTIAL", "asset_count": 0, "error": "throttled: 1 call(s) gave up after retries (throttled: DescribeSubnets (retries exhausted): RequestLimitExceeded: Request limit exceeded.)"}
```

A collector that lets the error escape is recorded FAILED with `describe_error(exc)`, for example `throttled: An error occurred (RequestLimitExceeded) when calling the DescribeSubnets operation (reached max retries: 10): Request limit exceeded.`. The Azure equivalent is an `azure_<service>` record with status FAILED and `azure_full` PARTIAL; on GCP it is `listing truncated: throttled: ...` on `gcp_list_assets`.

`InventoryResult.throttling` holds the governor summary. It is `None` unless something eventful happened: a throttle, a transient error, a give-up, a rejection, a breaker trip, or at least one second spent waiting for tokens in some scope. `result.summary["throttling"]` carries the short form:

```json
{
  "totals": {
    "calls": 2,
    "throttled": 11,
    "transient_errors": 0,
    "retries": 10,
    "gave_up": 1,
    "rejected": 0,
    "breaker_trips": 0,
    "wait_seconds": 0.949
  },
  "messages": [
    "aws/123456789012/us-east-1/ec2: throttled 11x, slowed to 5.0 rps, 10 retries, 1 calls gave up"
  ],
  "skipped": {
    "aws/123456789012/us-east-1/ec2": "throttled: DescribeSubnets (retries exhausted): RequestLimitExceeded: Request limit exceeded."
  }
}
```

`inventory-map.json` gets the whole summary under a top-level `throttling` key, which `InventoryResult.load()` reads back. The same run, with the part shown above trimmed:

```json
"throttling": {
  "totals": {...},
  "messages": [...],
  "skipped": {...},
  "scopes": {
    "aws/123456789012/us-east-1/ec2": {
      "calls": 2,
      "throttled": 11,
      "transient_errors": 0,
      "retries": 10,
      "gave_up": 1,
      "rejected": 0,
      "breaker_trips": 0,
      "waits": 10,
      "wait_seconds": 0.949,
      "max_wait_seconds": 0.1,
      "rate_rps": 5.0,
      "min_rate_rps": 5.0,
      "last_error": "throttled: DescribeSubnets (retries exhausted): RequestLimitExceeded: Request limit exceeded."
    }
  },
  "breakers": {},
  "slowed_buckets": {
    "aws/123456789012/us-east-1/ec2/DescribeSubnets": {
      "rate_rps": 5.0,
      "ceiling_rps": 20.0,
      "tokens": 0.173,
      "capacity": 25.0,
      "paused_for": 0.0,
      "throttles": 11
    }
  }
}
```

The rate dropped from 20 to 5 rps, not lower, because the 11 throttles arrived within about two seconds and decreases are at most one per second. `slowed_buckets` is keyed per operation because EC2 buckets are per action, and so are EC2 breakers; `scopes` is per service.

`breakers` and `slowed_buckets` come from the process-wide governor at the moment the run ended, not from the run alone. In a process that runs several collections at once they can include other runs' scopes.

Running the same script with `ratelimit.aws.breaker_threshold: 1`, then a second `subnets` task and a second `vpc` task, shows the breaker. It is per EC2 action, so it opened for `DescribeSubnets` only. The second `subnets` task never reached the API and was recorded as skipped, while `DescribeVpcs` went through:

```json
{"service": "subnets_again", "status": "PARTIAL", "asset_count": 0, "error": "throttled: 1 call(s) skipped (circuit open) (throttled: circuit open for aws/123456789012/us-east-1/ec2/DescribeSubnets after repeated throttling; retry in 60s)"}
{"service": "vpc_again", "status": "SUCCESS", "asset_count": 2, "error": null}
```

```text
aws/123456789012/us-east-1/ec2: throttled 11x, slowed to 5.0 rps, 10 retries, circuit opened 1x, 1 calls skipped, 1 calls gave up
```

`cloudg map` logs every message line at WARNING as `Throttling: <line>`. `MultiAccountCollector.resilience_stats` holds the stats object of its last `collect_all()` run (the caller's, when one was already bound).

## 7. Live operations and the MCP layer

### 7.1 The guard

`LiveOperationGuard` (`resilience/guard.py`) is pure asyncio with no MCP or provider imports. It decides whether a live operation may start:

- Single-flight: a call whose key equals an operation already running joins it and gets the same result (or exception) instead of starting a second collection.
- Concurrency caps: at most `max_concurrent_per_scope` live operations per scope and `max_concurrent_total` overall. Extra callers get `LiveOperationBusy`, or wait for a slot with `wait=True`.
- Cooldown: after an operation touching a scope finishes, successfully or not, a new one for that scope is refused for the cooldown with `CooldownActive`. A failure is often throttling, which is why failures cool down too (`cooldown_after_failure=True`).
- Caller quotas: at most `caller_max_operations` new live operations per caller per window (`CallerQuotaExceeded`). Off by default.
- Operation timeout: an operation still running after `operation_timeout_seconds` is cancelled, and every caller waiting for it gets `LiveOperationTimeout`. A running operation is also cancelled when every caller waiting for it has gone (each was cancelled, by a client or a tool timeout), so an abandoned collection cannot keep its scopes busy.

Every rejection subclasses `LiveOperationRejected` and has `reason` (`cooldown`, `busy`, `quota` or `timeout`), `retry_after` and `to_dict()`: `{"reason", "message"}` plus `retry_after_seconds`, `scopes` and `caller` when they are set. A scope is any string; the provider for a per-provider cooldown is the part before the first `/` or `:`. The limits can be passed as keyword arguments or as one `GuardSettings` object (`LiveOperationGuard(GuardSettings(...), clock=...)`, with keyword arguments overriding it; an unknown keyword raises `TypeError`). `LiveOperationGuard.from_config(config)` maps the `ratelimit.live_*` keys, `live_operation_timeout_seconds` (default 3600, `null` for no limit) included, and each provider's `live_cooldown_seconds`. `guard.status()` reports operations in flight, active counts per scope, the seconds left on each cooling scope, and how many operations started and joined.

### 7.2 In the MCP layer

The workspace owns one guard, `workspace.live_guard`, built from `config.ratelimit` on first use. The live tools `map_inventory`, `collect_assets`, `run_pipeline` and `run_scanners` run like this:

1. arguments and the result dataset name are validated;
2. `force=true` is checked: only principals with the `admin` or `operator` role may use it, others get an access error;
3. the credential preflight runs ([MCP guide, section 15](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP.md#15-live-tools-and-the-credential-preflight)); for `run_scanners` only when Prowler or ScoutSuite is enabled, since the other scanners need no cloud access;
4. the collection runs inside `guard.run(...)`. `run_scanners` always runs under the guard, so identical scans share one run; it uses the cloud scopes for cooldowns and caps only when a cloud scanner is enabled.

The guard scopes are derived from the config: `aws/<account>` for each configured account, else `aws/profile:<name>`, else `aws`; `azure/<subscription>` or `azure`; `gcp/<project>`, else `gcp/org:<id>`, else `gcp`. The single-flight key covers the operation, the providers, the scopes and the tool's arguments, so only truly identical calls share a run. A call that joined another gets `"joined": true` and a note in its result.

A refusal is a tool error (`isError: true`) with error code -31029, the code of `RateLimitedError`. Its data is the guard's `to_dict()` plus `use_dataset`: the newest live dataset whose providers include every provider of the refused operation, so an agent refused an AWS map is never pointed at a GCP-only dataset. When there is one, the message tells the agent to query it instead of collecting again; otherwise it suggests `list_datasets`. For a cooldown it also says that an admin or operator can pass `force=true`. `force` only skips the cooldown; the concurrency caps and caller quotas still apply.

Two read-only views show the state without calling any cloud API: the tool `rate_limit_status` and the resource `cloudg://ratelimit`. Both return `{"live_guard": {...}, "throttling": {...}}`: the guard's status plus its cooldown, concurrency and quota settings, and the process governor's lifetime summary, including tripped breakers and slowed buckets. All four live tools run their collection inside its own `stats_scope()`. When the run was throttled, the answer includes a `throttling` block with the totals, up to 20 messages and the skipped scopes, taken from `InventoryResult.throttling` for `map_inventory` and from the run's stats for the others. `map_inventory`, `collect_assets` and `run_pipeline` also keep the full summary in the new dataset's metadata. The per-tool reference is in [MCP_TOOLS.md](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP_TOOLS.md).

This is separate from the MCP policy's own `rate` limits, which count calls per principal and tool (see [MCP_PRIVACY.md](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP_PRIVACY.md)). The policy decides how often someone may call a tool; the guard decides whether the cloud can take another collection right now.

## 8. Python API

Everything below is exported from `cloudg.resilience`. `cloudg.retry` re-exports `call_with_resilience`, `call_with_resilience_sync`, `RetryPolicy`, `Scope`, `classify`, `retry_after` and `ErrorKind` for callers of the old module.

### 8.1 `call_with_resilience`

```python
await call_with_resilience(fn, *args, scope, policy=None, governor=None,
                           sleep=None, clock=None, **kwargs)
call_with_resilience_sync(fn, *args, scope, policy=None, governor=None,
                          sleep=time.sleep, clock=None, **kwargs)
```

The async version awaits `fn` if it is a coroutine function and runs anything else in a worker thread with `asyncio.to_thread`. The sync version is for code that already runs in a worker thread. Both apply the full sequence from [section 2](#2-how-one-call-is-paced) and re-raise the original exception when they give up. When the provider is disabled, `fn` is called directly with no retries.

```python
import asyncio

from cloudg.resilience import Scope, call_with_resilience, get_governor, stats_scope


class TooManyRequests(Exception):
    """Stands in for any SDK error: classify() reads status_code and headers."""

    status_code = 429

    def __init__(self, retry_after: str) -> None:
        super().__init__("429 Too Many Requests")
        self.headers = {"Retry-After": retry_after}


attempts = 0


async def list_widgets(page: int) -> list[str]:
    global attempts
    attempts += 1
    if attempts < 3:
        raise TooManyRequests("1")
    return [f"widget-{page}-{i}" for i in range(3)]


async def main() -> None:
    scope = Scope("aws", "123456789012", "eu-west-1", "widgets")
    with stats_scope() as stats:
        items = await call_with_resilience(list_widgets, 1, scope=scope)
    print(items, "after", attempts, "attempts")
    print(stats.messages())
    print(get_governor().limiter.rate(scope))


asyncio.run(main())
```

```text
['widget-1-0', 'widget-1-1', 'widget-1-2'] after 3 attempts
['aws/123456789012/eu-west-1/widgets: throttled 2x, slowed to 5.0 rps, 2 retries']
5.0
```

`RetryPolicy` overrides the provider's settings for one call. Fields left at `None` use the provider's values:

| Field | Default | Meaning |
|---|---|---|
| `max_retries` | provider's `max_retries` | retries after the first attempt |
| `base_delay` | 0.5 | lower bound of the jitter |
| `max_backoff` | provider's `max_backoff_seconds` | cap of one sleep |
| `deadline` | provider's `deadline_seconds` | overall time; `0` disables |
| `use_budget` | `True` | draw retries from the provider's retry budget |
| `retry_transient` | `True` | `False` retries throttling only |

### 8.2 `@resilient`

The decorator form. `scope` is a `Scope` or a callable that receives the function's arguments and returns one. Coroutine functions get `call_with_resilience`, plain functions `call_with_resilience_sync`.

```python
from cloudg.resilience import RetryPolicy, Scope, resilient


class Busy(Exception):
    status_code = 503


calls = {"n": 0}


@resilient(
    lambda project, **_: Scope("gcp", f"projects/{project}", None, "compute"),
    policy=RetryPolicy(max_retries=4, max_backoff=2.0, deadline=30.0),
)
def list_instances(project: str) -> list[str]:
    calls["n"] += 1
    if calls["n"] == 1:
        raise Busy("service overloaded")
    return ["vm-1", "vm-2"]


print(list_instances("demo-project"), calls["n"], "calls")
```

```text
['vm-1', 'vm-2'] 2 calls
```

The 503 classified as THROTTLED, so besides the retry the `gcp/projects/demo-project/*/compute` scope was slowed down for every other caller in the process.

### 8.3 The governor and run statistics

```python
from cloudg import CloudGConfig
from cloudg.inventory import InventoryMapper
from cloudg.resilience import configure, get_governor, stats_scope

config = CloudGConfig(providers=["aws"])
configure(config)                      # done for you by InventoryMapper / MultiAccountCollector

with stats_scope() as stats:           # also done by InventoryMapper.map_inventory()
    ...                                # any cloudg collection, or your own SDK calls

report = get_governor().summary(stats) # this run: totals, messages, skipped, scopes,
                                       # plus the process's tripped breakers and slowed buckets
lifetime = get_governor().summary()    # everything since the governor was created

result = InventoryMapper(config).map_inventory_sync()
result.throttling                      # the same summary for that run, or None
```

Lower-level pieces: `get_governor().limiter.snapshot()` (every bucket's rate, ceiling, tokens, capacity, pause and throttle count), `get_governor().breakers.snapshot(only_tripped=False)`, `get_governor().budget("aws").remaining`, `get_governor().try_retry(scope)` (take one retry-budget token, `False` when it is spent), `get_governor().breaker_scope(scope)` and `get_governor().limiter.leaf_scope(scope)` (the scope at the granularity of its bucket and breaker), `get_governor().limiter.bulkhead(scope)` (a `Bulkhead` with `acquire()`, `acquire_sync()`, `try_acquire()`, `release()` and `in_use`; `cloudg.resilience.limiter.Slot` wraps one acquired slot that is released exactly once), `classify(exc)`, `retry_after(exc)`, `describe_error(exc)`, `is_throttle(exc)`. Your own boto3 sessions can join the shared limiter with `cloudg.resilience.aws.install_aws_hooks(session, account_id, region)`, your own azure-mgmt clients with `cloudg.resilience.azure.build_azure_client(ClientClass, credential, subscription_id, subscription_id=subscription_id)`.

### 8.4 `LiveOperationGuard`

```python
import asyncio

from cloudg.resilience import CooldownActive, LiveOperationGuard, operation_key


async def collect() -> str:
    await asyncio.sleep(0.2)
    return "dataset-1"


async def main() -> None:
    guard = LiveOperationGuard(cooldown_seconds=120, max_concurrent_per_scope=1)
    key = operation_key("map", ["aws"], ["aws/123456789012"])
    scopes = ["aws/123456789012"]

    # Two identical requests at once: one collection, both get its result
    a, b = await asyncio.gather(
        guard.run(key, collect, scopes=scopes, caller="alice"),
        guard.run(key, collect, scopes=scopes, caller="bob"),
    )
    print(a, b, guard.status()["started"], "started,", guard.status()["joined"], "joined")

    try:
        await guard.run(key, collect, scopes=scopes, caller="alice")
    except CooldownActive as exc:
        print(exc.to_dict())

    # An operator override skips the cooldown (but not the concurrency caps)
    print(await guard.run(key, collect, scopes=scopes, caller="ops", bypass_cooldown=True))


asyncio.run(main())
```

```text
dataset-1 dataset-1 1 started, 1 joined
{'reason': 'cooldown', 'message': 'live collection of aws/123456789012 ran recently; cooling down, retry in 120s or use the cached dataset', 'retry_after_seconds': 120.0, 'scopes': ['aws/123456789012'], 'caller': 'alice'}
dataset-1
```

`run(key, factory, *, scopes=(), caller=None, bypass_cooldown=False, wait=False, timeout=None)` takes a zero-argument factory that returns the awaitable, not the awaitable itself, so a refused call never creates a coroutine. Other members: `check(scopes, caller=..., bypass_cooldown=...)` raises the rejection a new call would get, without side effects; `cooldown_remaining(scope)`; `in_flight(key)`; `reset(scope=None)` clears one cooldown, or every cooldown and quota; `mark_completed(scopes)` starts a cooldown after a collection that ran outside the guard. Construct it with `clock=` to test it without waiting.

## 9. Tuning

Start from the defaults and read the run's `throttling` block before changing anything. A few patterns:

- Throttling on one service only: override that service, not the provider default. For EC2, prefer an operation key (`ec2.DescribeImageAttribute`) over lowering `ec2`, which slows every action.
- Throttling spread over many services of the same account: set `account_max_rps`. For AWS it is off by default, and an organization run with many regions can otherwise send 20 rps per service per region into one account.
- Shared accounts: lower `max_rps` so cloudg leaves headroom for the pipelines and people using the same quota. The cost is a longer run; the adaptive limiter only reacts after the provider has already throttled someone.
- Breakers opening on a flaky service: raise `breaker_threshold` rather than the cooldown. A breaker covers what its bucket covers: one EC2 action, one operation with its own override, or one whole service elsewhere. Set `per_operation: true` on a service to give each of its operations its own breaker.
- Slow maps of AMI-heavy or bucket-heavy accounts: that is the per-item fan-out being held to the documented rates. 1,000 `DescribeImageAttribute` calls in one region take about 50 seconds at 20 rps. Raise the operation's rate only if the account's quota has been increased.
- Agents collecting too often: raise `live_cooldown_seconds`, or set `live_caller_max_operations` and `live_caller_window_seconds` to give each principal a budget. Tell the agent to read `cloudg://ratelimit` before calling a live tool.
- Many accounts mapped from one host: `global_max_rps` caps everything the process sends to one provider, whatever the account. `max_concurrency` limits requests in flight per account; lower it when an account's calls start to time out without any throttling error.
- A provider degraded as a whole: the retry budget stops every integration from retrying once 500 retries have been spent without enough successes to refill it. Lower `retry_budget` to give up sooner.
- Benchmarks or a mock cloud: `ratelimit.enabled: false`, or raise the rates (see section 11).

## 10. Known limitations

- Per-item fan-out is now held to the documented rates, which makes some maps slower than in 0.5.x (where the SDK's own retries absorbed the throttling until they failed).
- Not instrumented yet: the GCP organization-policy and access-context-manager clients outside `_iterate`, the urllib fallback that lists Azure subscriptions, and the single region-discovery call.
- A blocking boto3 or Azure call made on an event-loop thread goes ahead without a bulkhead slot when none is free, so `max_concurrency` is not a hard cap for that path.
- The Azure policy charges a retry-budget token for a retryable response even on the last attempt, which azure-core does not retry.
- Learned rates and breaker state live in memory. A new process, including each `cloudg map` invocation, starts at the configured rates.

## 11. Testing

`tests/test_resilience.py` has 120 tests: classification across SDK shapes (real botocore errors included), Retry-After parsing, token buckets and AIMD on a fake clock, the limiter's levels and overrides, the bulkhead, the breaker state machine and its per-operation scope, unknown config keys, retries, budgets and deadlines, the decorator, the live guard, the config models, and integration tests for each provider. The AWS ones use moto with a `before-send` handler that answers one operation with `RequestLimitExceeded`, and check the attempt count, the coverage status and the stats.

The governor is process-wide state, so `tests/conftest.py` has an autouse fixture, `fresh_resilience_governor`, that calls `reset_governor()` before and after every test. It also raises every built-in rate, burst and account limit to 1,000,000 by swapping `limiter.DEFAULT_LIMITS` for a fast profile. moto never throttles, and its fixtures (hundreds of default AMIs and snapshots) would otherwise make the production per-service rates the bottleneck of the suite. The hooks, limiter, breakers and telemetry still run on every call. `tests/test_resilience.py` has its own autouse fixture that puts `limiter.BUILTIN_LIMITS` back, so the resilience tests see the real defaults.

When you write a test that depends on throttling behaviour, either live in `tests/test_resilience.py` or restore `BUILTIN_LIMITS` the same way, inject a clock (`RateLimiter(clock=...)`, `CircuitBreaker(clock=...)`, `LiveOperationGuard(clock=...)`, `Governor(clock=...)`) and pass `sleep=` to `call_with_resilience` so nothing waits for real. For moto, patch botocore's `ExponentialBackoff.delay_amount` to return 0, as the integration tests do.
