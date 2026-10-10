---
command: collect
lede: Collects assets and network edges from one provider and saves them as JSON. No graph analysis, no scanners, no reports.
intro: |
  `cloudg collect` is phase 1 of `cloudg run` on its own, for one provider and, on AWS, one region. It is a quick way to test credentials and permissions before a long run. For a full inventory with relationships and dependency analysis, use [cloudg map](/cli/map/).
---

## How it works

`-p/--provider` is required and takes exactly one of `aws`, `azure` or `gcp` (case-insensitive). There is no `all` here.

Credentials and scope come from the flags on this page, then from the provider's section of the config passed with `cloudg -c` (`aws`, `azure` or `gcp`), then from the environment and each provider's default chain, through `CredentialResolver`. Every method the config supports works here: direct keys, `role_arn` and web identity on AWS, a service principal, workload identity or managed identity on Azure, a credentials file or impersonation on GCP. See [Auth flags](/cli/auth-flags/) for the order within each provider.

How each provider resolves its identity:

| Provider | Scope | Credentials |
|---|---|---|
| `aws` | One region: `--region`, else the first of `aws.regions`, else `AWS_DEFAULT_REGION`, else `us-east-1`. The account ID comes from `sts:GetCallerIdentity`. | The `aws` section of the config with `--profile` replacing `aws.profile`: keys, OIDC, profile and `role_arn` as for `cloudg run`. With none set, `AWS_PROFILE`, then the boto3 default chain (environment keys, SSO cache, instance or task role) |
| `azure` | One subscription: `--subscription-id`, else the first of `azure.subscription_ids`, else `AZURE_SUBSCRIPTION_ID`. One of them is required. | The `azure` section of the config; with nothing there, a service principal or workload identity when `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` are set together with `AZURE_CLIENT_SECRET` or `AZURE_FEDERATED_TOKEN_FILE`, else `DefaultAzureCredential` (which includes `az login`) |
| `gcp` | One project: `--project-id`, else the first of `gcp.project_ids`, else `GOOGLE_CLOUD_PROJECT`, else the project of the credentials | The `gcp` section of the config (credentials file, impersonation); with nothing there, application default credentials (`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or the metadata server) |

`--region` only matters for AWS. An `aws.regions` of `ALL` counts as unset for it. `--profile` only matters for AWS. `--subscription-id` and `--project-id` only matter for their provider. There is no `--regions`; to collect several AWS regions, run the command once per region with a different `-o`, or use `cloudg run` or `cloudg map`.

The AWS collector here is the standard one used by `cloudg run`. It covers the core services (EC2, S3, RDS, VPCs, subnets, security groups, IAM, Lambda, load balancers, ECS, DynamoDB, CloudFront, Secrets Manager, KMS and a few more). It does not run the deep inventory collectors, the Cloud Control sweep or the relationship linker that `cloudg map` uses.

When collection succeeds, cloudg prints a "Collection Summary" table with the asset and edge counts and the path of the file it wrote.

## Examples

Collect the default AWS region with your current credentials:

```bash
cloudg collect -p aws
```

Collect with the credentials in your config (a `role_arn`, say) and the first region of `aws.regions`:

```bash
cloudg -c config.yaml collect -p aws
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
