---
title: Authentication
lede: "Every provider has several ways in, tried in a fixed order, so one `config.yaml` works on a laptop, in CI and on cloud compute."
meta:
  - [Code, "`cloudg/credentials.py`"]
  - [Providers, "AWS, Azure, GCP"]
  - [Flags, "[Auth flags](/cli/auth-flags/)"]
source: cloudg/credentials.py
since: "0.6.0"
---

All credential handling lives in three functions in `cloudg/credentials.py`: `build_aws_session`, `build_azure_credential` and `build_gcp_credentials`. `cloudg run`, `cloudg map`, `CloudGEngine`, `InventoryMapper` and the credential preflight of the MCP live tools all call them, so the precedence on this page holds everywhere. Each function walks its list from the top and stops at the first method whose settings are complete. It never tries the next method after a failure, which matters when you debug: if direct keys are set but wrong, cloudg will not fall back to your profile.

You can supply each setting three ways. CLI flags (on `cloudg run`) are copied onto the loaded config before anything resolves, `config.yaml` holds the same keys under `aws`, `azure` and `gcp`, and a handful of environment variables are read directly. The tabs below show all three where they exist.

:::note Which commands take which flags
`cloudg run` has the full set of credential flags listed under [auth flags](/cli/auth-flags/). `cloudg map` has only `--profile`, `--accounts`, `--role-name` and `--org-role`; put everything else in `config.yaml` and pass it with `cloudg -c config.yaml map ...`. `cloudg collect` is the exception: it builds credentials from `--profile` (or `AWS_PROFILE`) and the environment only, and ignores the auth keys in `config.yaml`.
:::

## AWS

```mermaid caption="How build_aws_session picks the base credentials, then the optional AssumeRole hop"
flowchart TD
  A["access_key_id and secret_access_key set?"] -->|yes| K[Direct keys]
  A -->|no| B["role_arn and a web identity token file?"]
  B -->|yes| W[AssumeRoleWithWebIdentity]
  B -->|no| C["profile set?"]
  C -->|yes| P["Named profile, SSO included"]
  C -->|no| D["boto3 default chain"]
  K --> R{"role_arn not used yet?"}
  P --> R
  D --> R
  W --> R
  R -->|yes| S["sts:AssumeRole role_arn, optional ExternalId"]
  R -->|no| M{"account plus role_name?"}
  S --> M
  M -->|yes| T["sts:AssumeRole the member role"]
  M -->|no| Done[Session ready]
  T --> Done
```

| Order | Method | Settings that select it |
|---|---|---|
| 1 | Direct access keys | `access_key_id` and `secret_access_key`, plus `session_token` for temporary keys |
| 2 | OIDC web identity | `role_arn` together with `web_identity_token_file` or `$AWS_WEB_IDENTITY_TOKEN_FILE` |
| 3 | Named profile | `profile` (plain or SSO) |
| 4 | Default provider chain | nothing set: env vars, shared config, container credentials, instance role |
| then | STS AssumeRole | `role_arn` (when not already used by step 2), then, for each account in `accounts`, `role_name` in that account |

Whatever the base method, the session is instrumented with cloudg's rate limiter before it is used, so STS, Organizations and every collector call are paced. See [rate limits](/guides/rate-limits/).

### Direct keys and session tokens

The third-party auditor case: someone hands you an access key pair, or a temporary key pair with a session token. Keys win over everything else, including a profile set in the same config.

```bash tab="CLI"
cloudg run -p aws --regions us-east-1 \
  --aws-key AKIAIOSFODNN7EXAMPLE \
  --aws-secret "$AUDIT_SECRET" \
  --aws-session-token "$AUDIT_SESSION_TOKEN"
```

```yaml tab="config.yaml" title="config.yaml"
aws:
  regions: [us-east-1]
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: REPLACE_ME   # keep this file out of version control
  session_token: null             # only for temporary credentials
```

```bash tab="Environment"
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY="$AUDIT_SECRET"
export AWS_SESSION_TOKEN="$AUDIT_SESSION_TOKEN"
cloudg run -p aws --regions us-east-1
```

The environment tab works through a different door. cloudg does not copy `AWS_ACCESS_KEY_ID` into its config, so resolution falls through to step 4 and boto3's default chain picks the variables up. The effect is the same, and it is the variant to prefer: nothing secret lands in a file or in your shell history.

### OIDC web identity federation

For GitHub Actions, GitLab CI and EKS service accounts: no long-lived keys, only a short-lived token file exchanged for role credentials with `AssumeRoleWithWebIdentity`. cloudg reads the token file itself and names the session after `role_session_name` (default `cloudg-scan`).

```bash tab="CLI"
cloudg run -p aws --regions all \
  --aws-role-arn arn:aws:iam::123456789012:role/cloudg-readonly \
  --aws-web-identity-token-file /var/run/secrets/oidc/token
```

```yaml tab="config.yaml" title="config.yaml"
aws:
  role_arn: arn:aws:iam::123456789012:role/cloudg-readonly
  web_identity_token_file: /var/run/secrets/oidc/token
  role_session_name: cloudg-ci
```

```bash tab="Environment"
# Read by boto3's default chain (step 4), not by cloudg's step 2
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/cloudg-readonly
export AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/oidc/token
cloudg run -p aws --regions all
```

When step 2 succeeds, `role_arn` has been used up as the OIDC target and no second AssumeRole follows. A cross-account hop after federation needs `accounts` plus `role_name` instead.

:::warning The token file variable on EKS
cloudg also reads `$AWS_WEB_IDENTITY_TOKEN_FILE` from the environment, and EKS (IRSA) sets it in every pod. On such a pod, a `role_arn` meant as a second hop becomes the OIDC target instead, and the exchange fails unless that role trusts the cluster's OIDC provider. Either let the pod's own role do the work (no `role_arn`), or reach other accounts with `accounts` plus `role_name`.
:::

A failed exchange raises `RuntimeError: AssumeRoleWithWebIdentity failed for <arn>: ...`. The usual causes are a trust policy whose `sub` condition does not match the branch or environment, or a token minted for the wrong audience (AWS expects `sts.amazonaws.com`).

### Profiles and SSO

A named profile from `~/.aws/config`, plain or SSO. Log in first; cloudg uses the cached SSO token the AWS CLI writes.

```bash tab="CLI"
aws sso login --profile prod-audit
cloudg map -p aws --profile prod-audit --regions all
```

```yaml tab="config.yaml" title="config.yaml"
aws:
  profile: prod-audit
```

```bash tab="Environment"
export AWS_PROFILE=prod-audit
cloudg map -p aws --regions all
```

An expired SSO session shows up as a `TokenRetrievalError` or `UnauthorizedSSOTokenError` from botocore on the first call. Run `aws sso login` again.

### Instance roles and the default chain

With nothing configured, boto3 resolves credentials the usual way: environment variables, the shared credentials and config files, ECS and EKS container credentials, then the EC2 instance metadata service. This is the mode for cloudg running on EC2, ECS or Lambda under its own role, and the mode the CI examples in [CI and automation](/guides/ci-automation/) rely on. Nothing to pass:

```bash
cloudg run -p aws --regions all
```

### Role assumption and external IDs

STS `AssumeRole` sits on top of whichever base method won. It runs in two situations, and both can apply at once:

- `role_arn` is set and step 2 did not consume it. On its own this is a single-account hop, for example from your own account into a customer's audit role.
- cloudg is collecting a specific account from `accounts`. It builds `arn:aws:iam::<account>:role/<role_name>` and assumes it, from the `role_arn` session when there is one (role chaining). `role_arn` never replaces the member role, so a hub role in a security account can fan out to member roles that trust it.

`accounts` needs `role_name`: `cloudg run` and `cloudg map` stop with exit status 2 when the list is set without one (unless `--org` is on, where the member role defaults to `AWSControlTowerExecution`).

`external_id` is passed as `ExternalId` when set, which is the standard confused-deputy protection for third-party auditors. Sessions last 3600 seconds (fixed in the code) and use `role_session_name`.

```bash tab="CLI"
cloudg run -p aws --regions eu-west-1 \
  --profile auditor \
  --aws-role-arn arn:aws:iam::210987654321:role/ThirdPartyAudit \
  --aws-external-id 7f2c1a9e-audit-2026
```

```yaml tab="config.yaml" title="config.yaml"
aws:
  profile: auditor
  role_arn: arn:aws:iam::210987654321:role/ThirdPartyAudit
  external_id: 7f2c1a9e-audit-2026
  role_session_name: acme-audit
```

For fan-out across accounts, list them and name the role:

```yaml title="config.yaml"
aws:
  regions: [us-east-1, eu-west-1]
  accounts: ["111111111111", "222222222222", "333333333333"]
  role_name: cloudg-readonly
```

When `accounts` is set, cloudg first calls `GetCallerIdentity` to learn its own account (with `role_arn` set, that is the role's account). If that account is in the list it is collected with that session, without the member role, because roles such as `AWSControlTowerExecution` do not exist in the management account. For whole organizations, `cloudg map --org` discovers the account list for you; see [AWS Organizations](/guides/aws-organizations/).

A failed AssumeRole does not stop the run. The account and region get a coverage record for `sts_assume_role` with status FAILED and the STS error, and the other accounts carry on. Check the coverage table at the end of `cloudg run`, or `coverage` in the result, before trusting a quiet map.

### What the scanners receive

The collectors use the resolved session. Prowler and ScoutSuite are separate processes, so cloudg resolves the same credentials for them in the same order and passes them on. With `role_arn` (directly or through web identity), cloudg assumes the role and exports its temporary keys and session token. With direct keys, it exports the keys and `session_token`. Otherwise `aws.profile` becomes `-p` for Prowler and `--profile` for ScoutSuite, and with no profile they use the default chain. Explicit regions go to Prowler as `-f` and to ScoutSuite as `--regions`, and `AWS_DEFAULT_REGION` is never `ALL`.

The scanners run once per provider, against the account those credentials reach: the caller's, or `role_arn`'s. They do not repeat per member account of `accounts` or `--org`; only collection fans out.

## Azure

`build_azure_credential` returns one `azure.identity` credential for the whole run. Steps 1 to 3 all need a tenant and a client ID, taken from the config or from `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`.

| Order | Method | Settings that select it | Credential class |
|---|---|---|---|
| 1 | Workload identity federation | tenant + client + `federated_token_file` or `$AZURE_FEDERATED_TOKEN_FILE` | `WorkloadIdentityCredential` |
| 2 | Service principal secret | tenant + client + `client_secret` or `$AZURE_CLIENT_SECRET` | `ClientSecretCredential` |
| 3 | Service principal certificate | tenant + client + `certificate_path` (config or flag only) | `CertificateCredential` |
| 4 | Managed identity | `use_managed_identity: true`, optional `managed_identity_client_id` | `ManagedIdentityCredential` |
| 5 | Default chain | nothing above | `DefaultAzureCredential` |

The Azure CLI is not a numbered step. `az login` works through step 5, because `DefaultAzureCredential` tries environment credentials, workload identity, managed identity and then the Azure CLI. On a laptop that is the simplest path:

```bash tab="CLI"
az login
cloudg map -p azure
```

```yaml tab="config.yaml" title="config.yaml"
providers: [azure]
azure:
  subscription_ids: []      # empty: every Enabled subscription you can see
```

```bash tab="Environment"
az login
export AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
cloudg collect -p azure    # collect reads the subscription from the env var
```

Service principals and federation:

```bash tab="CLI"
# Secret
cloudg run -p azure \
  --azure-tenant-id "$TENANT" --azure-client-id "$APP_ID" \
  --azure-client-secret "$SP_SECRET"
# Certificate
cloudg run -p azure \
  --azure-tenant-id "$TENANT" --azure-client-id "$APP_ID" \
  --azure-cert-path ./cloudg-sp.pem
# Federated token (AKS workload identity, GitHub OIDC)
cloudg run -p azure \
  --azure-tenant-id "$TENANT" --azure-client-id "$APP_ID" \
  --azure-federated-token-file /var/run/secrets/azure/tokens/azure-identity-token
# Managed identity of the VM, App Service or AKS node
cloudg run -p azure --azure-managed-identity
```

```yaml tab="config.yaml" title="config.yaml"
azure:
  tenant_id: 11111111-2222-3333-4444-555555555555
  client_id: 66666666-7777-8888-9999-000000000000
  client_secret: null          # 2. secret
  certificate_path: null       # 3. PEM or PKCS12
  federated_token_file: null   # 1. wins over 2 and 3
  use_managed_identity: false  # 4.
  managed_identity_client_id: null   # for a user-assigned identity
```

```bash tab="Environment"
export AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555
export AZURE_CLIENT_ID=66666666-7777-8888-9999-000000000000
export AZURE_CLIENT_SECRET="$SP_SECRET"            # or:
export AZURE_FEDERATED_TOKEN_FILE=/path/to/token   # takes precedence over the secret
cloudg run -p azure
```

Two interactions catch people out. AKS workload identity injects `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE` into the pod, so step 1 fires even when you set `use_managed_identity: true`. And a stale `AZURE_CLIENT_SECRET` in a shell silently beats your `az login` session. When the identity is not what you expect, run with `-v`: cloudg logs the method it chose, for example `Azure auth: service principal (client 6666...)`.

Subscriptions come from `subscription_ids` (or `--subscription-id` on `run` and `map`). When the list is empty and `all_subscriptions` is true, cloudg lists every Enabled subscription the credential can see; with `all_subscriptions: false` it takes only the first.

## GCP

| Order | Method | Settings that select it |
|---|---|---|
| 1 | Credentials file | `credentials_file` in config or `--gcp-credentials-file`: a service account key JSON or an `external_account` workload identity federation config |
| 2 | Application Default Credentials | nothing above: `$GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or the GCE/GKE metadata server |
| then | Service account impersonation | `impersonate_service_account` or `--gcp-impersonate-sa`, on top of 1 or 2 |

All three request the `cloud-platform` scope. `GOOGLE_APPLICATION_CREDENTIALS` is handled by step 2 rather than step 1, which makes no practical difference: ADC loads the same file.

```bash tab="CLI"
gcloud auth application-default login
cloudg map -p gcp --project-id prod-app-123
# or a key / federation file, with impersonation on top
cloudg run -p gcp --project-id prod-app-123 \
  --gcp-credentials-file ./wif-config.json \
  --gcp-impersonate-sa cloudg-reader@sec-tools.iam.gserviceaccount.com
```

```yaml tab="config.yaml" title="config.yaml"
providers: [gcp]
gcp:
  project_ids: [prod-app-123, prod-data-456]
  organization_id: null        # set it for one org-wide listing
  credentials_file: null
  impersonate_service_account: cloudg-reader@sec-tools.iam.gserviceaccount.com
```

```bash tab="Environment"
export GOOGLE_APPLICATION_CREDENTIALS=$HOME/keys/cloudg-reader.json
export GOOGLE_CLOUD_PROJECT=prod-app-123
cloudg map -p gcp
```

Impersonation is the clean way to keep keys off disk: your own ADC identity (or the CI's federated identity) needs only `roles/iam.serviceAccountTokenCreator` on one reader service account, and every API call runs as that account.

The project list is `project_ids`. When it is empty, cloudg uses the default project the credentials carry (ADC reads it from `GOOGLE_CLOUD_PROJECT` or the gcloud config). With neither, collection fails with `no GCP project to scan: set gcp.project_ids or gcp.organization_id, or use credentials that carry a default project`. With `organization_id` set and `collection_scope: auto`, one Cloud Asset Inventory listing at `organizations/<id>` covers every project, and `project_ids` only filter it.

## Least-privilege permissions

cloudg only reads. Grant read-only roles at the widest scope you want mapped, and nothing else.

| Provider | Grant | Notes |
|---|---|---|
| AWS | `arn:aws:iam::aws:policy/SecurityAudit` and `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess` | Together they cover the describe, list and get-policy calls of the collectors and the Cloud Control sweep |
| AWS, organizations | `organizations:Describe*`, `organizations:List*`, `controltower:List*`, `controltower:Get*` in the management account | Plus a read-only member role in every account, for example deployed with a StackSet. `AWSControlTowerExecution` works but is admin |
| AWS, EKS workloads | An EKS access entry for the role with `AmazonEKSViewPolicy` | Only when `inventory.kubernetes` is on |
| Azure | `Reader` on each subscription, or on a management group to cover everything below it | Management group and Azure Policy mapping needs Reader at the management groups themselves |
| GCP | `roles/cloudasset.viewer` on the organization, folder or project | Covers resource, IAM policy, org policy and access policy listings. The Cloud Asset API must be enabled in the project that makes the calls |
| GCP, impersonation | `roles/iam.serviceAccountTokenCreator` on the target service account | Granted to the caller, not to the target |

Scanners have their own requirements. Prowler documents extra permissions on top of `SecurityAudit` and `ViewOnlyAccess`, and Prowler and ScoutSuite on Azure also read Microsoft Graph. Check each scanner's documentation before you blame cloudg for an `AccessDenied` in their output.

:::danger Never point cloudg at admin credentials for convenience
Nothing in cloudg writes to your cloud, but its reports and the RAG and ontology exports describe your estate in detail, and the MCP live tools run with whatever identity the server has. A read-only role keeps a leaked report or a misconfigured agent from becoming a write path.
:::

## Checking which identity cloudg used

Run any command with `-v`. Each provider logs the branch it took:

```console
$ cloudg -v map -p aws --profile prod-audit --regions us-east-1
INFO  AWS auth: profile 'prod-audit' (region us-east-1)
```

Other messages you may see are `AWS auth: direct access keys`, `AWS auth: web identity federation into <arn>`, `AWS auth: default provider chain`, `AWS auth: assuming role <arn>`, `Azure auth: workload identity federation (client ...)`, `Azure auth: DefaultAzureCredential chain`, `GCP auth: file-based identity (...)`, `GCP auth: application default credentials` and `GCP auth: impersonating <email>`.

:::links
- [Auth flags](/cli/auth-flags/) Every credential flag of `cloudg run`.
- [AWS Organizations](/guides/aws-organizations/) Mapping every account from the management account.
- [CI and automation](/guides/ci-automation/) OIDC from GitHub Actions and GitLab CI.
- [Docker](/guides/docker/) Mounting credentials into the container.
:::
