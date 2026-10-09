"""A small but realistic multi-cloud estate for the MCP layer tests.

AWS organization ``o-sample`` with a ``prod`` account (VPC, public /
private subnets, ALB behind a WAF, web tier, bastion with SSH open to the
world, RDS, S3, KMS, Lambda behind API Gateway, roles), a
``shared-services`` account whose deploy role is trusted by the prod app
role *and* by an external vendor account, plus a few Azure (jump VM with
RDP open, Key Vault, Blob) and GCP (public bucket, BigQuery, worker VM)
assets. Findings cover every severity, several tools and compliance
frameworks, one suppressed finding and one finding on an unmapped
resource. All ids are fixed so tests can refer to them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    ComplianceResult,
    ComplianceStatus,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)

PROD = "111111111111"
SHARED = "222222222222"
VENDOR = "999999999999"
AZ_SUB = "00000000-aaaa-bbbb-cccc-000000000001"
GCP_PROJECT = "proj-analytics"
INTERNET = "0.0.0.0/0"
TS = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)

T = AssetType
P = CloudProvider


def _aws(
    aid: str,
    name: str,
    t: AssetType,
    arn: str,
    account: str = PROD,
    region: str = "us-east-1",
    **kw: Any,
) -> CloudAsset:
    return CloudAsset(
        id=aid,
        name=name,
        asset_type=t,
        provider=P.AWS,
        arn=arn,
        account_id=account,
        region=region,
        collected_at=TS,
        **kw,
    )


def assets() -> list[CloudAsset]:
    a = [
        # organization
        _aws(
            "org",
            "sample-org",
            T.ORGANIZATION,
            "arn:aws:organizations::111111111111:organization/o-sample",
            region="global",
        ),
        _aws(
            "ou-workloads",
            "Workloads",
            T.ORG_UNIT,
            "arn:aws:organizations::111111111111:ou/o-sample/ou-work",
            region="global",
        ),
        _aws("acct-prod", "prod", T.CLOUD_ACCOUNT, f"arn:aws:iam::{PROD}:root", region="global"),
        _aws(
            "acct-shared",
            "shared-services",
            T.CLOUD_ACCOUNT,
            f"arn:aws:iam::{SHARED}:root",
            account=SHARED,
            region="global",
        ),
        _aws(
            "acct-vendor",
            "vendor-co",
            T.CLOUD_ACCOUNT,
            f"arn:aws:iam::{VENDOR}:root",
            account=VENDOR,
            region="global",
            metadata={"external": True},
        ),
        _aws(
            "scp-deny-regions",
            "deny-unapproved-regions",
            T.ORG_POLICY,
            "arn:aws:organizations::111111111111:policy/o-sample/service_control_policy/p-1",
            region="global",
        ),
        # prod network
        _aws(
            "vpc-prod",
            "prod-vpc",
            T.VPC,
            f"arn:aws:ec2:us-east-1:{PROD}:vpc/vpc-0prod",
            tags={"env": "prod", "owner": "platform"},
        ),
        _aws(
            "subnet-public",
            "prod-public-a",
            T.SUBNET,
            f"arn:aws:ec2:us-east-1:{PROD}:subnet/subnet-0pub",
            tags={"env": "prod"},
        ),
        _aws(
            "subnet-private",
            "prod-private-a",
            T.SUBNET,
            f"arn:aws:ec2:us-east-1:{PROD}:subnet/subnet-0priv",
            tags={"env": "prod"},
        ),
        _aws(
            "sg-web",
            "sg-web",
            T.SECURITY_GROUP,
            f"arn:aws:ec2:us-east-1:{PROD}:security-group/sg-0web",
        ),
        _aws(
            "sg-admin",
            "sg-admin",
            T.SECURITY_GROUP,
            f"arn:aws:ec2:us-east-1:{PROD}:security-group/sg-0admin",
        ),
        _aws(
            "sg-app",
            "sg-app",
            T.SECURITY_GROUP,
            f"arn:aws:ec2:us-east-1:{PROD}:security-group/sg-0app",
        ),
        _aws(
            "sg-db",
            "sg-db",
            T.SECURITY_GROUP,
            f"arn:aws:ec2:us-east-1:{PROD}:security-group/sg-0db",
        ),
        _aws(
            "alb-web",
            "web-alb",
            T.LOAD_BALANCER,
            f"arn:aws:elasticloadbalancing:us-east-1:{PROD}:loadbalancer/app/web-alb/abc",
            is_internet_exposed=True,
            tags={"env": "prod", "owner": "web-team"},
        ),
        _aws(
            "tg-web",
            "web-tg",
            T.TARGET_GROUP,
            f"arn:aws:elasticloadbalancing:us-east-1:{PROD}:targetgroup/web-tg/def",
        ),
        _aws(
            "web-1",
            "web-1",
            T.EC2,
            f"arn:aws:ec2:us-east-1:{PROD}:instance/i-0web1",
            tags={"env": "prod", "owner": "web-team"},
            metadata={
                "instance_type": "t3.large",
                "imds_v2": False,
                "user_data": "export DB_PASSWORD=hunter2",
            },
        ),
        _aws(
            "web-2",
            "web-2",
            T.EC2,
            f"arn:aws:ec2:us-east-1:{PROD}:instance/i-0web2",
            tags={"env": "prod", "owner": "web-team"},
            metadata={"instance_type": "t3.large"},
        ),
        _aws(
            "bastion",
            "bastion",
            T.EC2,
            f"arn:aws:ec2:us-east-1:{PROD}:instance/i-0bast",
            is_internet_exposed=True,
            tags={"env": "prod", "owner": "platform"},
            metadata={"public_ip": "203.0.113.10"},
        ),
        _aws(
            "orders-db",
            "orders-db",
            T.RDS_INSTANCE,
            f"arn:aws:rds:us-east-1:{PROD}:db:orders-db",
            tags={"env": "prod", "data": "pii"},
            metadata={"engine": "postgres", "backup_retention": 1},
        ),
        _aws(
            "data-bucket",
            "prod-data",
            T.S3_BUCKET,
            "arn:aws:s3:::prod-data",
            region="us-east-1",
            tags={"data": "pii"},
        ),
        _aws(
            "logs-bucket",
            "prod-logs",
            T.S3_BUCKET,
            "arn:aws:s3:::prod-logs",
            is_internet_exposed=True,
        ),
        _aws("kms-main", "prod-main-key", T.KMS_KEY, f"arn:aws:kms:us-east-1:{PROD}:key/1111-2222"),
        _aws(
            "db-secret",
            "orders-db-credentials",
            T.SECRET,
            f"arn:aws:secretsmanager:us-east-1:{PROD}:secret:orders-db-credentials-AbC",
        ),
        _aws(
            "app-role",
            "app-role",
            T.IAM_ROLE,
            f"arn:aws:iam::{PROD}:role/app-role",
            region="global",
            metadata={"policies": ["s3:GetObject", "rds-db:connect"]},
        ),
        _aws(
            "admin-role",
            "bastion-admin",
            T.IAM_ROLE,
            f"arn:aws:iam::{PROD}:role/bastion-admin",
            region="global",
        ),
        _aws(
            "lambda-role",
            "api-lambda-role",
            T.IAM_ROLE,
            f"arn:aws:iam::{PROD}:role/api-lambda-role",
            region="global",
        ),
        _aws(
            "api-gw",
            "public-api",
            T.API_GATEWAY,
            "arn:aws:apigateway:us-east-1::/restapis/a1b2c3",
            is_internet_exposed=True,
        ),
        _aws(
            "api-handler",
            "api-handler",
            T.LAMBDA_FUNCTION,
            f"arn:aws:lambda:us-east-1:{PROD}:function:api-handler",
            tags={"owner": "api-team"},
            metadata={"runtime": "python3.8"},
        ),
        _aws(
            "log-group",
            "/aws/lambda/api-handler",
            T.LOG_GROUP,
            f"arn:aws:logs:us-east-1:{PROD}:log-group:/aws/lambda/api-handler",
        ),
        _aws(
            "waf-web",
            "web-acl",
            T.WAF_WEB_ACL,
            f"arn:aws:wafv2:us-east-1:{PROD}:regional/webacl/web-acl/1",
        ),
        _aws(
            "guardduty",
            "guardduty-detector",
            T.THREAT_DETECTOR,
            f"arn:aws:guardduty:us-east-1:{PROD}:detector/d1",
            metadata={"security_service": "guardduty", "enabled": True},
        ),
        _aws(
            "securityhub",
            "security-hub",
            T.SECURITY_HUB,
            f"arn:aws:securityhub:us-east-1:{PROD}:hub/default",
            metadata={"security_service": "securityhub", "enabled": False},
        ),
        _aws(
            "inspector",
            "inspector",
            T.VULNERABILITY_SCANNER,
            f"arn:aws:inspector2:us-east-1:{PROD}:inspector",
            metadata={"security_service": "inspector", "enabled": True},
        ),
        # shared services
        _aws(
            "deploy-role",
            "deploy-role",
            T.IAM_ROLE,
            f"arn:aws:iam::{SHARED}:role/deploy-role",
            account=SHARED,
            region="global",
        ),
        _aws(
            "artifacts-bucket",
            "shared-artifacts",
            T.S3_BUCKET,
            "arn:aws:s3:::shared-artifacts",
            account=SHARED,
            region="eu-west-1",
        ),
        _aws(
            "ecr-repo",
            "app-images",
            T.CONTAINER_REGISTRY,
            f"arn:aws:ecr:eu-west-1:{SHARED}:repository/app-images",
            account=SHARED,
            region="eu-west-1",
        ),
        # Azure
        CloudAsset(
            id="az-vnet",
            name="hub-vnet",
            asset_type=T.VNET,
            provider=P.AZURE,
            arn=f"/subscriptions/{AZ_SUB}/resourceGroups/rg-hub/providers/"
            "Microsoft.Network/virtualNetworks/hub-vnet",
            account_id=AZ_SUB,
            region="westeurope",
            collected_at=TS,
        ),
        CloudAsset(
            id="az-nsg",
            name="jump-nsg",
            asset_type=T.NSG,
            provider=P.AZURE,
            arn=f"/subscriptions/{AZ_SUB}/resourceGroups/rg-hub/providers/"
            "Microsoft.Network/networkSecurityGroups/jump-nsg",
            account_id=AZ_SUB,
            region="westeurope",
            collected_at=TS,
        ),
        CloudAsset(
            id="az-vm",
            name="jump-vm",
            asset_type=T.VIRTUAL_MACHINE,
            provider=P.AZURE,
            arn=f"/subscriptions/{AZ_SUB}/resourceGroups/rg-hub/providers/"
            "Microsoft.Compute/virtualMachines/jump-vm",
            account_id=AZ_SUB,
            region="westeurope",
            is_internet_exposed=True,
            collected_at=TS,
            tags={"owner": "it-ops"},
        ),
        CloudAsset(
            id="az-kv",
            name="hub-kv",
            asset_type=T.KEY_VAULT,
            provider=P.AZURE,
            arn=f"/subscriptions/{AZ_SUB}/resourceGroups/rg-hub/providers/"
            "Microsoft.KeyVault/vaults/hub-kv",
            account_id=AZ_SUB,
            region="westeurope",
            collected_at=TS,
        ),
        CloudAsset(
            id="az-blob",
            name="archive",
            asset_type=T.BLOB_STORAGE,
            provider=P.AZURE,
            arn=f"/subscriptions/{AZ_SUB}/resourceGroups/rg-hub/providers/"
            "Microsoft.Storage/storageAccounts/archive",
            account_id=AZ_SUB,
            region="westeurope",
            collected_at=TS,
        ),
        # GCP
        CloudAsset(
            id="gcp-gcs",
            name="raw-uploads",
            asset_type=T.GCS_BUCKET,
            provider=P.GCP,
            arn="//storage.googleapis.com/projects/_/buckets/raw-uploads",
            account_id=GCP_PROJECT,
            region="europe-west1",
            is_internet_exposed=True,
            collected_at=TS,
        ),
        CloudAsset(
            id="gcp-bq",
            name="analytics",
            asset_type=T.DATA_WAREHOUSE,
            provider=P.GCP,
            arn=f"//bigquery.googleapis.com/projects/{GCP_PROJECT}/datasets/analytics",
            account_id=GCP_PROJECT,
            region="europe-west1",
            collected_at=TS,
        ),
        CloudAsset(
            id="gcp-vm",
            name="worker-1",
            asset_type=T.GCE_INSTANCE,
            provider=P.GCP,
            arn=f"//compute.googleapis.com/projects/{GCP_PROJECT}/zones/europe-west1-b/"
            "instances/worker-1",
            account_id=GCP_PROJECT,
            region="europe-west1",
            collected_at=TS,
        ),
    ]
    return a


def _e(eid: str, s: str, t: str, et: EdgeType, **kw: Any) -> NetworkEdge:
    return NetworkEdge(id=eid, source_id=s, target_id=t, edge_type=et, **kw)


def edges() -> list[NetworkEdge]:
    E = EdgeType
    return [
        # hierarchy
        _e("e-org-ou", "org", "ou-workloads", E.CONTAINS, properties={"hierarchy": True}),
        _e("e-ou-prod", "ou-workloads", "acct-prod", E.CONTAINS, properties={"hierarchy": True}),
        _e(
            "e-ou-shared", "ou-workloads", "acct-shared", E.CONTAINS, properties={"hierarchy": True}
        ),
        _e("e-scp", "scp-deny-regions", "ou-workloads", E.GOVERNS),
        _e("e-acct-vpc", "acct-prod", "vpc-prod", E.CONTAINS, properties={"hierarchy": True}),
        # network fabric
        _e("e-vpc-pub", "vpc-prod", "subnet-public", E.CONTAINS),
        _e("e-vpc-priv", "vpc-prod", "subnet-private", E.CONTAINS),
        _e("e-pub-alb", "subnet-public", "alb-web", E.CONTAINS),
        _e("e-pub-bastion", "subnet-public", "bastion", E.CONTAINS),
        _e("e-priv-web1", "subnet-private", "web-1", E.CONTAINS),
        _e("e-priv-web2", "subnet-private", "web-2", E.CONTAINS),
        _e("e-priv-db", "subnet-private", "orders-db", E.CONTAINS),
        _e(
            "e-inet-sgweb",
            INTERNET,
            "sg-web",
            E.SECURITY_GROUP_RULE,
            cidr=INTERNET,
            ports=[443, 80],
            port_range="80,443",
            protocol="TCP",
            direction="ingress",
        ),
        _e(
            "e-inet-sgadmin",
            INTERNET,
            "sg-admin",
            E.SECURITY_GROUP_RULE,
            cidr=INTERNET,
            ports=[22],
            port_range="22",
            protocol="TCP",
            direction="ingress",
        ),
        _e(
            "e-inet-alb",
            INTERNET,
            "alb-web",
            E.INTERNET_EXPOSED,
            cidr=INTERNET,
            port_range="443",
            relationship="INTERNET_REACHABLE",
        ),
        _e(
            "e-inet-api",
            INTERNET,
            "api-gw",
            E.INTERNET_EXPOSED,
            cidr=INTERNET,
            port_range="443",
            relationship="INTERNET_REACHABLE",
        ),
        _e(
            "e-inet-logs",
            INTERNET,
            "logs-bucket",
            E.INTERNET_EXPOSED,
            cidr=INTERNET,
            relationship="INTERNET_REACHABLE",
            description="bucket policy Principal *",
        ),
        _e("e-alb-sg", "alb-web", "sg-web", E.ATTACHED_TO),
        _e("e-bastion-sg", "bastion", "sg-admin", E.ATTACHED_TO),
        _e("e-web1-sg", "web-1", "sg-app", E.ATTACHED_TO),
        _e("e-web2-sg", "web-2", "sg-app", E.ATTACHED_TO),
        _e("e-db-sg", "orders-db", "sg-db", E.ATTACHED_TO),
        _e(
            "e-sgapp-sgdb",
            "sg-app",
            "sg-db",
            E.SECURITY_GROUP_RULE,
            ports=[5432],
            port_range="5432",
            protocol="TCP",
            direction="ingress",
        ),
        _e("e-alb-tg", "alb-web", "tg-web", E.LOAD_BALANCER_TARGET),
        _e("e-tg-web1", "tg-web", "web-1", E.LOAD_BALANCER_TARGET, port_range="8080"),
        _e("e-tg-web2", "tg-web", "web-2", E.LOAD_BALANCER_TARGET, port_range="8080"),
        _e("e-waf-alb", "waf-web", "alb-web", E.PROTECTS),
        # identity
        _e("e-web1-role", "web-1", "app-role", E.ASSUMES_ROLE),
        _e("e-web2-role", "web-2", "app-role", E.ASSUMES_ROLE),
        _e("e-bastion-role", "bastion", "admin-role", E.ASSUMES_ROLE),
        _e("e-role-data", "app-role", "data-bucket", E.GRANTS_ACCESS, relationship="READS_FROM"),
        _e("e-role-db", "app-role", "orders-db", E.GRANTS_ACCESS),
        _e("e-admin-secret", "admin-role", "db-secret", E.GRANTS_ACCESS),
        _e(
            "e-app-deploy",
            "app-role",
            "deploy-role",
            E.IAM_TRUST,
            relationship="CROSS_ACCOUNT_TRUST",
        ),
        _e(
            "e-vendor-deploy",
            "acct-vendor",
            "deploy-role",
            E.IAM_TRUST,
            relationship="CROSS_ACCOUNT_TRUST",
            properties={"cross_account": True},
        ),
        _e("e-deploy-artifacts", "deploy-role", "artifacts-bucket", E.GRANTS_ACCESS),
        _e("e-deploy-ecr", "deploy-role", "ecr-repo", E.GRANTS_ACCESS),
        # serverless
        _e("e-api-lambda", "api-gw", "api-handler", E.INVOKES),
        _e("e-data-lambda", "data-bucket", "api-handler", E.INVOKES, relationship="TRIGGERED_BY"),
        _e("e-lambda-role", "api-handler", "lambda-role", E.ASSUMES_ROLE),
        _e("e-lrole-secret", "lambda-role", "db-secret", E.GRANTS_ACCESS),
        _e("e-lambda-logs", "api-handler", "log-group", E.LOGS_TO),
        _e(
            "e-lambda-kms", "api-handler", "kms-main", E.REFERENCES, relationship="ENCRYPTED_BY_KMS"
        ),
        _e("e-data-kms", "data-bucket", "kms-main", E.REFERENCES, relationship="ENCRYPTED_BY_KMS"),
        _e("e-db-kms", "orders-db", "kms-main", E.REFERENCES, relationship="ENCRYPTED_BY_KMS"),
        _e("e-secret-kms", "db-secret", "kms-main", E.REFERENCES, relationship="ENCRYPTED_BY_KMS"),
        _e("e-ecr-lambda", "api-handler", "ecr-repo", E.USES_IMAGE),
        _e("e-inspector-web1", "inspector", "web-1", E.MONITORS),
        # Azure
        _e(
            "e-inet-nsg",
            INTERNET,
            "az-nsg",
            E.SECURITY_GROUP_RULE,
            cidr=INTERNET,
            ports=[3389],
            port_range="3389",
            protocol="TCP",
            direction="ingress",
        ),
        _e("e-vm-nsg", "az-vm", "az-nsg", E.ATTACHED_TO),
        _e("e-vnet-vm", "az-vnet", "az-vm", E.CONTAINS),
        _e("e-vm-kv", "az-vm", "az-kv", E.GRANTS_ACCESS),
        _e("e-vm-blob", "az-vm", "az-blob", E.GRANTS_ACCESS),
        # GCP
        _e(
            "e-inet-gcs",
            INTERNET,
            "gcp-gcs",
            E.INTERNET_EXPOSED,
            cidr=INTERNET,
            relationship="INTERNET_REACHABLE",
        ),
        _e("e-gce-gcs", "gcp-vm", "gcp-gcs", E.GRANTS_ACCESS),
        _e("e-gce-bq", "gcp-vm", "gcp-bq", E.REFERENCES),
    ]


def _f(
    fid: str,
    res: str,
    arn: str | None,
    sev: Severity,
    title: str,
    tool: str,
    fws: list[str],
    **kw: Any,
) -> Finding:
    return Finding(
        id=fid,
        resource_id=res,
        resource_arn=arn,
        severity=sev,
        title=title,
        description=kw.pop("description", f"{title}."),
        source_tool=tool,
        compliance_frameworks=fws,
        detected_at=TS,
        **kw,
    )


def findings() -> list[Finding]:
    S = Severity
    return [
        _f(
            "f-ssh-open",
            "sg-admin",
            f"arn:aws:ec2:us-east-1:{PROD}:security-group/sg-0admin",
            S.CRITICAL,
            "Security group allows SSH (22) from 0.0.0.0/0",
            "prowler",
            ["CIS-AWS", "PCI-DSS"],
            source_finding_id="prowler-aws-ec2_sg_open_22-1",
            evidence="IpPermissions 0.0.0.0/0 tcp 22",
            remediation="Restrict 22 to the VPN.",
        ),
        _f(
            "f-bastion-imds",
            "bastion",
            None,
            S.HIGH,
            "EC2 instance allows IMDSv1",
            "prowler",
            ["CIS-AWS"],
            remediation="Require IMDSv2.",
        ),
        _f(
            "f-db-backup",
            f"arn:aws:rds:us-east-1:{PROD}:db:orders-db",
            None,
            S.MEDIUM,
            "RDS backup retention below 7 days",
            "prowler",
            ["CIS-AWS", "NIST-800-53"],
        ),
        _f(
            "f-logs-public",
            "prod-logs",
            "arn:aws:s3:::prod-logs",
            S.HIGH,
            "S3 bucket allows public read",
            "scoutsuite",
            ["CIS-AWS", "PCI-DSS", "NIST-800-53"],
        ),
        _f(
            "f-web-cve",
            "web-1",
            None,
            S.HIGH,
            "CVE-2024-1234 in openssl 3.0.1",
            "trivy",
            ["PCI-DSS"],
            cvss_score=8.1,
            source_finding_id="CVE-2024-1234",
        ),
        _f(
            "f-lambda-runtime",
            "api-handler",
            None,
            S.LOW,
            "Lambda runtime python3.8 is deprecated",
            "checkov",
            [],
            source_finding_id="CKV_AWS_363",
        ),
        _f(
            "f-deploy-trust",
            "deploy-role",
            f"arn:aws:iam::{SHARED}:role/deploy-role",
            S.HIGH,
            "Role trusts an external account without ExternalId",
            "iam",
            ["CIS-AWS"],
        ),
        _f(
            "f-rdp-open",
            "az-nsg",
            None,
            S.CRITICAL,
            "NSG allows RDP (3389) from Internet",
            "scoutsuite",
            ["CIS-Azure"],
        ),
        _f(
            "f-gcs-public",
            "gcp-gcs",
            None,
            S.HIGH,
            "Bucket is publicly readable (allUsers)",
            "prowler",
            ["CIS-GCP"],
        ),
        _f("f-default-vpc", "vpc-prod", None, S.INFO, "VPC flow logs not enabled", "prowler", []),
        _f(
            "f-ghost",
            "arn:aws:s3:::ghost-bucket",
            "arn:aws:s3:::ghost-bucket",
            S.MEDIUM,
            "Bucket without lifecycle policy",
            "scoutsuite",
            ["CIS-AWS"],
        ),
        _f(
            "f-versioning",
            "data-bucket",
            None,
            S.LOW,
            "S3 versioning disabled",
            "prowler",
            ["CIS-AWS"],
            is_suppressed=True,
        ),
    ]


def compliance() -> list[ComplianceResult]:
    C = ComplianceStatus
    return [
        ComplianceResult(
            id="c-cis-5.2",
            framework="CIS-AWS",
            control_id="5.2",
            control_title="No SG allows 0.0.0.0/0 to admin ports",
            status=C.FAIL,
            finding_ids=["f-ssh-open"],
        ),
        ComplianceResult(
            id="c-cis-2.1.4",
            framework="CIS-AWS",
            control_id="2.1.4",
            control_title="S3 Block Public Access",
            status=C.FAIL,
            finding_ids=["f-logs-public"],
        ),
        ComplianceResult(
            id="c-cis-1.16",
            framework="CIS-AWS",
            control_id="1.16",
            control_title="IAM trust least privilege",
            status=C.FAIL,
            finding_ids=["f-deploy-trust"],
        ),
        ComplianceResult(
            id="c-cis-3.1",
            framework="CIS-AWS",
            control_id="3.1",
            control_title="CloudTrail enabled",
            status=C.PASS,
            finding_ids=[],
        ),
        ComplianceResult(
            id="c-pci-1.3.1",
            framework="PCI-DSS",
            control_id="1.3.1",
            control_title="Inbound traffic restricted",
            status=C.FAIL,
            finding_ids=["f-ssh-open", "f-logs-public"],
        ),
        ComplianceResult(
            id="c-nist-cp9",
            framework="NIST-800-53",
            control_id="CP-9",
            control_title="System backup",
            status=C.FAIL,
            finding_ids=["f-db-backup"],
        ),
        ComplianceResult(
            id="c-az-6.1",
            framework="CIS-Azure",
            control_id="6.1",
            control_title="RDP restricted from the Internet",
            status=C.FAIL,
            finding_ids=["f-rdp-open"],
        ),
        ComplianceResult(
            id="c-gcp-5.1",
            framework="CIS-GCP",
            control_id="5.1",
            control_title="Buckets not anonymously accessible",
            status=C.FAIL,
            finding_ids=["f-gcs-public"],
        ),
    ]


def coverage() -> list[CollectionCoverage]:
    cov = CollectionCoverage(provider="aws", region="us-east-1", account_id=PROD)
    cov.record("ec2", ServiceStatus.SUCCESS, 9)
    cov.record("s3", ServiceStatus.SUCCESS, 3)
    cov.record("rds", ServiceStatus.FAILED, error="AccessDenied: rds:DescribeDBInstances")
    return [cov]


def organization() -> dict[str, Any]:
    return {
        "organization_id": "o-sample",
        "organization_arn": "arn:aws:organizations::111111111111:organization/o-sample",
        "management_account_id": PROD,
        "feature_set": "ALL",
        "roots": [
            {
                "id": "r-root",
                "name": "Root",
                "arn": "arn:root",
                "parent_id": None,
                "path": [],
                "is_root": True,
            }
        ],
        "ous": {
            "ou-work": {
                "id": "ou-work",
                "name": "Workloads",
                "arn": "arn:ou",
                "parent_id": "r-root",
                "path": ["Root", "Workloads"],
                "is_root": False,
            }
        },
        "accounts": {
            PROD: {
                "id": PROD,
                "name": "prod",
                "arn": "arn:acct:prod",
                "status": "ACTIVE",
                "parent_id": "ou-work",
                "ou_path": ["Root", "Workloads"],
            },
            SHARED: {
                "id": SHARED,
                "name": "shared-services",
                "arn": "arn:acct:shared",
                "status": "ACTIVE",
                "parent_id": "ou-work",
                "ou_path": ["Root", "Workloads"],
            },
        },
        "policies": [
            {
                "id": "p-1",
                "name": "deny-unapproved-regions",
                "arn": "arn:p-1",
                "type": "SERVICE_CONTROL_POLICY",
                "aws_managed": False,
                "targets": ["ou-work"],
            }
        ],
        "landing_zone": {"version": "3.3", "drift": False},
        "governed_regions": ["us-east-1", "eu-west-1"],
        "control_tower_enabled": True,
    }


def unresolved() -> list[dict[str, Any]]:
    return [
        {
            "source": "web-1",
            "source_type": "EC2",
            "target": f"arn:aws:iam::{PROD}:role/missing-role",
            "edge": "ASSUMES_ROLE",
        }
    ]


def build_inventory() -> Any:
    from cloudg.inventory.mapper_result import InventoryResult

    return InventoryResult(
        assets=assets(),
        edges=edges(),
        coverage=coverage(),
        providers=["aws", "azure", "gcp"],
        regions={
            "aws": ["us-east-1", "eu-west-1"],
            "azure": ["westeurope"],
            "gcp": ["europe-west1"],
        },
        organization=organization(),
        unresolved_references=unresolved(),
    )


def write_estate(root: Path) -> dict[str, Path]:
    """Write inventory + findings files under ``root``; returns their paths."""
    from cloudg.renderers.json_export import JSONExporter
    from cloudg.schema.models import ScanResult

    inv_dir = root / "inventory"
    inv = build_inventory()
    inv.export(inv_dir)
    sr = ScanResult(assets=assets(), edges=edges(), findings=findings(), compliance=compliance())
    JSONExporter(output_dir=str(inv_dir)).export(sr)
    report_dir = root / "report"
    from cloudg.graph.builder import GraphBuilder

    b = GraphBuilder()
    b.build(sr.assets, sr.edges)
    JSONExporter(output_dir=str(report_dir)).export(sr, graph_json=b.to_d3_json())
    return {
        "root": root,
        "inventory_dir": inv_dir,
        "inventory_map": inv_dir / "inventory-map.json",
        "findings": inv_dir / "findings.json",
        "report_dir": report_dir,
        "report": report_dir / "findings.json",
    }
