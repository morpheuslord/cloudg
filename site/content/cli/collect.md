---
command: collect
lede: Collects assets and network edges from one provider and saves them as JSON. No graph analysis, no scanners, no reports.
intro: |
  `cloudg collect` is phase 1 of `cloudg run` on its own, for one provider and, on AWS, one region. It is a quick way to test credentials and permissions before a long run. For a full inventory with relationships and dependency analysis, use [cloudg map](/cli/map/).
---

## How it works

`-p/--provider` is required and takes exactly one of `aws`, `azure` or `gcp` (case-insensitive). There is no `all` here.

The command does not read `config.yaml`. Credentials come from the flags on this page, the environment and each provider's default chain, through `CredentialResolver`. That means the config-only methods (direct keys, role ARNs, service principals in config, credential files, impersonation) are not available. Use [cloudg run](/cli/run/) or `cloudg map` with a config file for those.

How each provider resolves its identity:

| Provider | Scope | Credentials |
|---|---|---|
| `aws` | One region: `--region`, default `us-east-1`. The account ID comes from `sts:GetCallerIdentity`. | `--profile`, else `AWS_PROFILE`, else the boto3 default chain (environment keys, SSO cache, instance or task role) |
| `azure` | One subscription: `--subscription-id`, else `AZURE_SUBSCRIPTION_ID`. One of them is required. | A service principal or workload identity when `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` are set together with `AZURE_CLIENT_SECRET` or `AZURE_FEDERATED_TOKEN_FILE`, else `DefaultAzureCredential` (which includes `az login`) |
| `gcp` | One project: `--project-id`, else `GOOGLE_CLOUD_PROJECT`, else the project of the application default credentials | Application default credentials (`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or the metadata server) |

`--region` only matters for AWS, and because it always has a value, `AWS_DEFAULT_REGION` is never used. `--profile` only matters for AWS. `--subscription-id` and `--project-id` only matter for their provider. There is no `--regions`; to collect several AWS regions, run the command once per region with a different `-o`, or use `cloudg run` or `cloudg map`.

The AWS collector here is the standard one used by `cloudg run`. It covers the core services (EC2, S3, RDS, VPCs, subnets, security groups, IAM, Lambda, load balancers, ECS, DynamoDB, CloudFront, Secrets Manager, KMS and a few more). It does not run the deep inventory collectors, the Cloud Control sweep or the relationship linker that `cloudg map` uses.

When collection succeeds, cloudg prints a "Collection Summary" table with the asset and edge counts and the path of the file it wrote.

## Examples

Collect the default AWS region with your current credentials:

```bash
cloudg collect -p aws
```

Collect one AWS region with a named profile:

```bash
cloudg collect -p aws --profile prod --region eu-west-1 -o ./reports/eu-west-1
```

Collect an Azure subscription with your `az login` session:

```bash
cloudg collect -p azure --subscription-id 00000000-0000-0000-0000-000000000000
```

Collect an Azure subscription as a service principal, configured through the environment:

```bash
export AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111
export AZURE_CLIENT_ID=22222222-2222-2222-2222-222222222222
export AZURE_CLIENT_SECRET="$(cat ./sp-secret)"
cloudg collect -p azure --subscription-id 00000000-0000-0000-0000-000000000000
```

Collect a GCP project with a service account key:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=./sa-key.json
cloudg collect -p gcp --project-id my-project
```

Load the result into the MCP server to explore it from an assistant. The file is loaded as a `generic` dataset named after the file:

```bash
cloudg mcp serve --dataset ./reports/inventory-aws.json
```

## Output files

| File | Contents |
|---|---|
| `inventory-<provider>.json` | `{"assets": [...], "edges": [...]}`, each entry a `CloudAsset` or `NetworkEdge` in Pydantic JSON form |

The file is written to `-o/--output` (default `./reports`), and a second run for the same provider overwrites it.

## Exit codes

| Code | When |
|---|---|
| 0 | The inventory file was written |
| 1 | Collection failed: missing SDK extra, no credentials, no Azure subscription or GCP project. cloudg prints a "Collection failed" panel with the reason. |
| 2 | Click rejected an option, for example `-p all` |

## Related

:::links
- [cloudg map](/cli/map/) The full inventory map with relationships and dependencies.
- [cloudg run](/cli/run/) Collection as part of the complete pipeline.
- [Authentication](/guides/authentication/) Every supported identity per provider.
- [Provider and region flags](/cli/provider-flags/) How `--region` and `--regions` differ.
:::
