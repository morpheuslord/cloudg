---
title: AWS Organizations
lede: "With `--org`, `cloudg map` starts at the management account, finds every member account and maps them all, with the OU tree, SCPs and Control Tower around them."
meta:
  - [Command, "`cloudg map --org`"]
  - [Runs from, "Management account or delegated administrator"]
source: cloudg/inventory/organization.py
---

Mapping one account at a time misses what holds an organization together: which OU an account sits in, which SCPs restrict it, which Control Tower controls apply, and which roles in one account trust another. `cloudg map --org` reads the organization first, picks the accounts you asked for, assumes a role in each one, and maps all of them into a single [inventory map](/guides/inventory-mapping/). Accounts hang under their OUs, SCPs and controls point at what they govern, and cross-account trust becomes an edge you can query with [`cloudg deps`](/guides/dependencies/).

Every call cloudg makes here is read-only: `Describe*`, `List*` and `Get*` against Organizations and Control Tower, then the usual read calls inside each member account.

## What happens during discovery

```mermaid caption="Organization discovery, then one role assumption per member account and region"
sequenceDiagram
  participant C as cloudg
  participant S as STS
  participant O as Organizations
  participant T as Control Tower
  participant M as Member account
  C->>S: GetCallerIdentity
  C->>O: DescribeOrganization, ListRoots
  C->>O: Walk OUs and accounts, list policies and targets
  C->>O: Trusted services, delegated administrators
  C->>T: ListLandingZones, probing likely home regions
  T-->>C: Landing zone, enabled controls and baselines
  Note over C: Filter accounts by OU, exclusions, status
  loop Each selected account and region
    C->>S: AssumeRole into the member role
    S-->>C: Temporary credentials
    C->>M: Deep collectors (read-only)
  end
```

In order:

1. `sts:GetCallerIdentity` records which account is running the discovery, and `organizations:DescribeOrganization` returns the organization ID, the management account and the feature set. If this fails, the caller is not in an organization or can't read it.
2. From each root, cloudg walks down with `ListAccountsForParent` and `ListOrganizationalUnitsForParent`, recording every account's parent and OU path, like `Root/Workloads/Prod`.
3. For each policy type enabled on the root (SCPs, RCPs, tag, backup and AI services opt-out policies), it lists the policies and the roots, OUs and accounts each one is attached to.
4. It lists trusted service access and the delegated administrators of GuardDuty, Security Hub, Inspector, Config, Access Analyzer, Macie, Detective, Firewall Manager and IAM Identity Center. An access denial ends that loop quietly.
5. With Control Tower detection on, it looks for a landing zone (see [Control Tower](#control-tower-and-regions) below). The landing zone manifest is parsed for governed regions and the log archive, audit, Config aggregator and backup accounts, then dropped.
6. The account list is filtered, and collection fans out with one AssumeRole per account and region.

If discovery fails, the map doesn't stop. cloudg records `organizations: FAILED` in coverage, logs the reason, and maps the caller's account alone. The CLI's failed-collectors warning at the end of the run names it.

## Permissions for the caller

Run `cloudg map --org` with credentials for the management account. Organizations discovery also works from a delegated administrator, but the Control Tower APIs only answer in the management account.

```json title="cloudg-org-discovery-policy.json"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOrganization",
      "Effect": "Allow",
      "Action": [
        "organizations:Describe*",
        "organizations:List*",
        "controltower:List*",
        "controltower:Get*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AssumeMemberRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/cloudg-readonly"
    }
  ]
}
```

The caller's own account is mapped too, with the caller's credentials and not through a member role (member roles such as `AWSControlTowerExecution` don't exist in the management account). So the caller also needs read access in its own account; attaching `SecurityAudit` and `ViewOnlyAccess` to it is the simplest way.

## Deploy a read-only member role

cloudg assumes one role, by name, in every member account. The default is `AWSControlTowerExecution`, because Control Tower creates it in every account it enrolls.

:::warning AWSControlTowerExecution has admin rights
`AWSControlTowerExecution` carries administrator permissions. cloudg only reads, but anything that can run cloudg with management-account credentials could do more with that role. The read-only role Control Tower creates, `aws-controltower-ReadOnlyExecutionRole`, can't be used instead: it only trusts a role in the audit account. For production, deploy your own read-only role to every account and pass it with `--org-role`.
:::

A service-managed CloudFormation StackSet deploys the role to every account in the OUs you target, and to accounts that join those OUs later.

::::steps
### Save the template

```yaml title="cloudg-readonly-role.yaml"
AWSTemplateFormatVersion: "2010-09-09"
Description: Read-only role that cloudg assumes to map this account

Parameters:
  ManagementAccountId:
    Type: String
    AllowedPattern: '^[0-9]{12}$'
    Description: Account that runs cloudg map --org

Resources:
  CloudgReadOnlyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: cloudg-readonly
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${ManagementAccountId}:root"
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/job-function/ViewOnlyAccess

Outputs:
  RoleArn:
    Value: !GetAtt CloudgReadOnlyRole.Arn
```

Keep the role at the root path. cloudg builds the ARN as `arn:aws:iam::<account>:role/<name>`, so a role created under a path such as `/audit/` would not be found by its bare name.

The trust policy above lets any principal in the management account that has `sts:AssumeRole` permission assume the role. To pin it to the one role cloudg runs as, add a `Condition` with `ArnEquals` on `aws:PrincipalArn`.

### Turn on trusted access for StackSets

Run this once, in the management account:

```bash
aws cloudformation activate-organizations-access
```

### Create the stack set

```bash
aws cloudformation create-stack-set \
  --stack-set-name cloudg-readonly \
  --template-body file://cloudg-readonly-role.yaml \
  --parameters ParameterKey=ManagementAccountId,ParameterValue=123456789012 \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false
```

### Deploy it to your OUs

IAM roles are global, so deploy to a single region. Targeting the root ID (`r-...`) covers every OU; list OU IDs instead to limit it.

```bash
aws cloudformation create-stack-instances \
  --stack-set-name cloudg-readonly \
  --deployment-targets OrganizationalUnitIds=r-7h3o \
  --regions us-east-1
aws cloudformation list-stack-instances --stack-set-name cloudg-readonly
```

Service-managed StackSets never deploy to the management account itself. cloudg doesn't need them to, since it maps the management account with the caller's own credentials.
::::

To map Kubernetes workloads inside EKS clusters as well, each cluster needs an access entry for `cloudg-readonly` with the `AmazonEKSViewPolicy`. The [inventory mapping guide](/guides/inventory-mapping/#kubernetes-inside-eks) has the two `aws eks` commands.

## Map the organization

```bash tab="CLI"
cloudg map -p aws --profile management --org --org-role cloudg-readonly --regions all
```

```python tab="Python" title="map_org.py"
from cloudg import CloudGConfig
from cloudg.inventory import InventoryMapper

config = CloudGConfig(providers=["aws"])
config.aws.profile = "management"
config.aws.regions = ["ALL"]

org = config.aws.organization
org.enabled = True
org.role_name = "cloudg-readonly"
org.include_ous = ["Workloads"]
org.exclude_accounts = ["111122223333"]

mapper = InventoryMapper(config)
inventory = mapper.map_inventory_sync()
paths = inventory.export("./reports")

topology = mapper.organization          # None when discovery failed
if topology is not None:
    print(topology.organization_id, len(topology.accounts), "accounts")
    print("Control Tower:", topology.control_tower_enabled, topology.governed_regions)
print(paths.get("organization"))
```

```bash tab="Docker"
docker run --rm \
  -v ~/.aws:/home/cloudg/.aws:ro \
  -v "$PWD/reports:/app/reports" \
  ghcr.io/morpheuslord/cloudg:latest \
  map -p aws --profile management --org --org-role cloudg-readonly --regions all
```

With `--org`, the CLI's configuration panel shows "Organization: discover all accounts" (plus the OU filter, if any) and the member role it will use. After the run an "Organization" table lists the organization ID, the number of accounts and OUs, whether Control Tower was found and the governed regions, ahead of the usual inventory summary.

## Choose the accounts

By default every `ACTIVE` account in the organization is mapped, the management account included. These flags narrow it down:

| Flag | Config key | Effect |
|---|---|---|
| `--ou` | `aws.organization.include_ous` | Only accounts under this OU, nested OUs included. Takes an OU ID, an OU ARN, or a name (case-insensitive). Repeatable. |
| `--exclude-account` | `aws.organization.exclude_accounts` | Skip this account ID. Repeatable. |
| `--accounts` | `aws.accounts` | Comma-separated IDs. With `--org`, the discovered list is intersected with this one. |
| none | `aws.organization.include_management_account` | `true` by default. |
| none | `aws.organization.include_suspended` | `false` by default, so `SUSPENDED` and `PENDING_CLOSURE` accounts are skipped. |

```bash
# the Workloads OU and everything below it, minus one sandbox
cloudg map -p aws --org --org-role cloudg-readonly --ou Workloads --exclude-account 111122223333
# two OUs by ID
cloudg map -p aws --org --org-role cloudg-readonly --ou ou-7h3o-ljevwujv --ou ou-7h3o-bqhq9yxz
```

OU names are matched against the whole tree and the first match wins. If two OUs share a name (a `Prod` under `Workloads` and another under `Sandbox`), pass the ID. A name that matches no OU is logged as a warning and ignored, and if none of your `--ou` values match, no account is selected and cloudg falls back to mapping the caller's own account. Run with `-v` when the account count looks wrong.

## Control Tower and regions

Control Tower detection is on by default (`aws.organization.control_tower`). cloudg calls `controltower:ListLandingZones` region by region until it finds one: first the region given with `--ct-home-region`, then the session's region, then the usual home regions in this order: `us-east-1`, `us-east-2`, `us-west-2`, `eu-west-1`, `eu-central-1`, `eu-west-2`, `ap-southeast-2`, `ap-northeast-1`, `ap-southeast-1`, `ca-central-1`, `ap-south-1`, `eu-north-1`, `sa-east-1`. If your home region isn't on that list, pass it:

```bash
cloudg map -p aws --org --org-role cloudg-readonly --ct-home-region eu-south-1 --regions all
```

`--ct-home-region` also sets the region of the discovery session. Without it, regions where the lookup fails are only logged at debug level. With `--ct-home-region` set, every failed lookup is kept in the topology's `errors` list and coverage shows `controltower: PARTIAL`.

When a landing zone is found and you passed `--regions all`, cloudg maps only the governed regions instead of every enabled region (`aws.organization.use_governed_regions`, on by default). An explicit region list is always used as given, and so is the default `us-east-1` when you pass no `--regions` at all.

## What lands on the map

With `aws.organization.map_structure` on (the default), the topology becomes assets and edges next to the collected resources:

| Asset | Type | Edges |
|---|---|---|
| The organization | `ORGANIZATION` | the management account `MANAGES` it |
| Each root and OU | `ORG_UNIT` | its parent `CONTAINS` it |
| Each account | `CLOUD_ACCOUNT` | its OU `CONTAINS` it (`ORG_CONTAINS_ACCOUNT`) |
| Each SCP, RCP, tag, backup or AI opt-out policy | `ORG_POLICY` | `GOVERNS` each target; `SCP_RESTRICTS` for SCPs |
| The landing zone | `LANDING_ZONE` | `MANAGES` the organization and each shared account |
| Each enabled control and baseline | `GUARDRAIL` | `GOVERNS` the OU it is enabled on |

Account nodes use `arn:aws:iam::<id>:root` as their identifier, the same string IAM trust policies and resource policies use for an account principal. So when a role in one account trusts another account of the organization, the `IAM_TRUST` edge starts at that account's node on the map instead of at an external placeholder, and `cloudg deps` lists it among the cross-account edges. Account metadata records whether it is the management account, its Control Tower role (`log_archive`, `audit` and so on) and the services it is delegated administrator for.

## How member accounts are assumed

For each selected account and each region, cloudg builds a session from your base credentials (profile, keys, web identity or the default chain) and then calls `sts:AssumeRole` on `arn:aws:iam::<account>:role/<role>`. The role name comes from `--org-role`, else `aws.organization.role_name`, else `--role-name` / `aws.role_name`, else `AWSControlTowerExecution`. The session name is `aws.role_session_name` (`cloudg-scan` by default), the duration one hour, and `aws.external_id` is sent when set.

An account whose role can't be assumed records `sts_assume_role: FAILED` for that region, and nothing else is collected there. The rest of the organization carries on.

:::note
`aws.role_arn` takes precedence over the member role when it is set without a web identity token file: every account would then be collected through that single role, which is not what you want for an organization. Leave `aws.role_arn` unset with `--org`, or use it together with `aws.web_identity_token_file` (the GitHub Actions and GitLab CI pattern), where it is the role the pipeline starts from and the member role is assumed on top.
:::

## inventory-organization.json

A map made with `--org` writes the whole topology to `inventory-organization.json`, and `InventoryResult.load()` reads it back as `inventory.organization`. Abridged:

```json title="reports/inventory-organization.json"
{
  "organization_id": "o-1wietecbs4",
  "management_account_id": "123456789012",
  "caller_account_id": "123456789012",
  "feature_set": "ALL",
  "ous": {
    "ou-7h3o-bqhq9yxz": {"id": "ou-7h3o-bqhq9yxz", "name": "Prod", "parent_id": "ou-7h3o-ljevwujv",
                         "path": ["Root", "Workloads", "Prod"], "is_root": false}
  },
  "accounts": {
    "552289857375": {"id": "552289857375", "name": "prod-app", "status": "ACTIVE",
                     "parent_id": "ou-7h3o-bqhq9yxz", "ou_path": ["Root", "Workloads", "Prod"]}
  },
  "policies": [
    {"id": "p-FullAWSAccess", "name": "FullAWSAccess", "type": "SERVICE_CONTROL_POLICY",
     "aws_managed": true, "targets": ["r-7h3o"]}
  ],
  "delegated_administrators": {"guardduty": ["333333333333"]},
  "landing_zone": {"version": "3.3", "status": "ACTIVE", "driftStatus": {"status": "IN_SYNC"}},
  "governed_regions": ["us-east-1", "eu-west-1"],
  "shared_accounts": {"log_archive": "222222222222", "audit": "333333333333"},
  "enabled_controls": [],
  "control_tower_region": "us-east-1",
  "errors": [],
  "control_tower_enabled": true
}
```

`accounts` holds every account in the organization, before any filter, so the file doubles as an account inventory. A quick listing by OU:

```python title="accounts_by_ou.py"
import json
from collections import defaultdict

with open("./reports/inventory-organization.json") as f:
    org = json.load(f)

by_ou = defaultdict(list)
for account in org["accounts"].values():
    by_ou["/".join(account["ou_path"])].append(f'{account["id"]} {account["name"]} {account["status"]}')

for path in sorted(by_ou):
    print(path)
    for line in sorted(by_ou[path]):
        print("  ", line)
```

## Configuration

The same settings live under `aws.organization` in `config.yaml`, for runs that pass `-c config.yaml`. The flags override them.

```yaml title="config.yaml"
aws:
  profile: management
  regions: [ALL]
  organization:
    enabled: true
    role_name: cloudg-readonly     # default: aws.role_name, then AWSControlTowerExecution
    include_ous: [Workloads]       # OU IDs, ARNs or names, nested OUs included
    exclude_accounts: ["111122223333"]
    include_management_account: true
    include_suspended: false
    use_governed_regions: true     # regions [ALL] -> Control Tower governed regions
    control_tower: true            # map the landing zone, controls and baselines
    home_region: null              # Control Tower home region, auto-detected
    map_structure: true            # org, OU, account, SCP and control nodes on the map
```

| Key | Default | Flag |
|---|---|---|
| `enabled` | `false` | `--org / --no-org` |
| `role_name` | `null` | `--org-role` |
| `include_ous` | `[]` | `--ou` |
| `exclude_accounts` | `[]` | `--exclude-account` |
| `include_management_account` | `true` | none |
| `include_suspended` | `false` | none |
| `use_governed_regions` | `true` | none |
| `control_tower` | `true` | none |
| `home_region` | `null` | `--ct-home-region` |
| `map_structure` | `true` | none |

## Discovery on its own

`discover_organization()` works without a mapping run. It takes a boto3 session and returns an `OrganizationTopology`:

```python title="org_topology.py"
import boto3

from cloudg.inventory import discover_organization

session = boto3.Session(profile_name="management", region_name="us-east-1")
topology = discover_organization(session, control_tower=True)

print(topology.organization_id, "managed by", topology.management_account_id)
print("Control Tower:", topology.control_tower_enabled, topology.governed_regions)

for account in topology.accounts.values():
    print(account.id, account.name, account.status, "/".join(account.ou_path))

for policy in topology.policies:
    print(policy.type, policy.name, "->", policy.targets)

workloads = topology.target_accounts(include_ous=["Workloads"], include_management_account=False)
print("would map:", workloads)

assets = topology.to_assets()      # organization, OUs, accounts, policies, landing zone, controls
```

It raises `RuntimeError` when the caller can't describe or list the organization. Other failures, such as a Control Tower call that was denied, end up in `topology.errors`.

## Troubleshooting

| What you see | Likely cause | Fix |
|---|---|---|
| Only one account mapped, `organizations` in the failed-collectors line | the credentials aren't from the management account or a delegated administrator, or lack `organizations:List*` | run with management-account credentials |
| `sts_assume_role` failed for some accounts | the member role is missing there, or its trust policy doesn't name the caller's account | check the StackSet instances for those accounts |
| `sts_assume_role` failed for the management account when running from a delegated administrator | the StackSet never deploys to the management account, and `AWSControlTowerExecution` doesn't exist there | `--exclude-account` it, set `include_management_account: false`, or create the role there by hand |
| Control Tower reported as absent | running from a delegated administrator, or the home region isn't in the probe list | run from the management account; pass `--ct-home-region` |
| Far fewer accounts than expected | an `--ou` value matched nothing, or matched a different OU of the same name | use OU IDs; run with `-v` to see the warning |
| Fewer regions than `--regions all` would give | Control Tower governed regions replaced `all` | set `use_governed_regions: false`, or pass the regions explicitly |

:::links
- [Inventory mapping](/guides/inventory-mapping/) What a mapping run collects in each account.
- [Dependencies and blast radius](/guides/dependencies/) Query cross-account edges on the finished map.
- [Authentication](/guides/authentication/) Profiles, OIDC and role assumption for the base credentials.
- [cloudg map](/cli/map/) Every option of the command.
:::
