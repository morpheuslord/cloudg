"""Tests for the governance / sharing / data-protection collectors:
Identity Center, RAM, Service Catalog, StackSets, IAM extras, KMS, Secrets
Manager, DynamoDB, snapshots and AMIs, S3 access points and Cognito."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from cloudg.coverage import ServiceStatus
from cloudg.inventory.aws_deep import SERVICE_FAMILIES, AWSDeepInventoryCollector
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

ACCOUNT = "123456789012"
EXTERNAL = "999999999999"


@pytest.fixture
def aws_credentials(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def skip_crc32(monkeypatch):
    """DynamoDB responses carry x-amz-crc32; aiobotocore awaits moto's
    (synchronous) body to verify it. Skip the check under moto."""
    from aiobotocore import retryhandler
    from aiobotocore.retries import special

    async def _no_check(self, attempt_number, response):
        return None

    async def _not_retryable(self, context):
        return False

    monkeypatch.setattr(retryhandler.AioCRC32Checker, "_check_response", _no_check)
    monkeypatch.setattr(special.AioRetryDDBChecksumError, "is_retryable", _not_retryable)


def _collector(
    services: list[str], region: str = "us-east-1", **kwargs: Any
) -> AWSDeepInventoryCollector:
    return AWSDeepInventoryCollector(
        session=boto3.Session(region_name=region),
        region=region,
        account_id=ACCOUNT,
        kubernetes=False,
        tagging_sweep=False,
        services=services,
        **kwargs,
    )


def _run(collector: AWSDeepInventoryCollector) -> list[CloudAsset]:
    return asyncio.run(collector.collect())


def _status(collector: AWSDeepInventoryCollector) -> dict[str, ServiceStatus]:
    return {s.service: s.status for s in collector.coverage.services}


def _account(acct: str = ACCOUNT) -> CloudAsset:
    return CloudAsset(
        arn=f"arn:aws:iam::{acct}:root",
        name=f"account {acct}",
        asset_type=AssetType.CLOUD_ACCOUNT,
        provider=CloudProvider.AWS,
        region="global",
        account_id=acct,
        metadata={"account_id": acct},
    )


def _edge(edges, src, dst, edge_type=None, relationship=None):
    return [
        e
        for e in edges
        if e.source_id == src.id
        and e.target_id == dst.id
        and (edge_type is None or e.edge_type == edge_type)
        and (relationship is None or e.relationship == relationship)
    ]


def _one(assets, asset_type, name=None):
    found = [a for a in assets if a.asset_type == asset_type and (name is None or a.name == name)]
    assert len(found) == 1, (asset_type, name, [a.name for a in found])
    return found[0]


def _policy(principal: str, action: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Owner",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                    "Action": "*",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": action,
                    "Resource": "*",
                },
            ],
        }
    )


# ── Fake async clients for operations moto does not implement ──


class FakeClient:
    """Minimal async stand-in for an aiobotocore client.

    ``responses`` maps operation name -> response dict, callable(**kwargs)
    or exception. Missing operations raise ResourceNotFoundException.
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def _respond(self, op: str, kwargs: dict) -> Any:
        self.calls.append((op, kwargs))
        r = self._responses.get(op)
        if r is None:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": op}}, op)
        if isinstance(r, Exception):
            raise r
        return r(**kwargs) if callable(r) else r

    def get_paginator(self, op: str) -> Any:
        client = self

        class _Paginator:
            def paginate(self, **kwargs: Any) -> Any:
                async def pages():
                    yield client._respond(op, kwargs)

                return pages()

        return _Paginator()

    def __getattr__(self, op: str) -> Any:
        if op.startswith("_"):
            raise AttributeError(op)

        async def call(**kwargs: Any) -> Any:
            return self._respond(op, kwargs)

        return call


def _use_fakes(monkeypatch, collector, clients: dict[Any, FakeClient]) -> None:
    def client(service: str, region: str | None = None) -> FakeClient:
        return clients.get((service, region)) or clients[service]

    monkeypatch.setattr(collector, "_client", client)


# ── Registration ──


class TestRegistration:
    def test_task_names_and_families(self):
        tasks = _collector(["all"])._governance_tasks()
        base = {"kms", "secretsmanager", "dynamodb", "iam", "s3", "rds", "cloudformation"}
        assert not base & set(tasks)
        assert tasks["identity_center"][1:] == ("identity", True)
        assert tasks["ram_shares"][1:] == ("governance", False)
        assert tasks["s3_multi_region_access_points"][2] is True

    def test_global_tasks_skip_non_primary_region(self, aws_credentials):
        names = _collector(["all"], is_primary_region=False)._service_tasks()
        assert "identity_center" not in names and "iam_access_keys" not in names
        assert "ram_shares" in names and "kms" in names
        assert SERVICE_FAMILIES["stack_sets"] == "governance"

    def test_overrides_replace_base_collectors(self):
        collector = _collector(["all"])
        from cloudg.collectors.aws import AsyncAWSCollector
        from cloudg.inventory.aws_services.governance import GovernanceCollectorsMixin

        for name in ("_collect_kms", "_collect_secrets_manager", "_collect_dynamodb"):
            assert getattr(type(collector), name) is getattr(GovernanceCollectorsMixin, name)
            assert getattr(type(collector), name) is not getattr(AsyncAWSCollector, name)


# ── IAM Identity Center ──


@mock_aws
class TestIdentityCenter:
    def test_permission_sets_assignments_and_identity_store(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        sso = session.client("sso-admin")
        inst = sso.list_instances()["Instances"][0]
        ps = sso.create_permission_set(InstanceArn=inst["InstanceArn"], Name="Admin")[
            "PermissionSet"
        ]["PermissionSetArn"]
        sso.attach_managed_policy_to_permission_set(
            InstanceArn=inst["InstanceArn"],
            PermissionSetArn=ps,
            ManagedPolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        sso.attach_customer_managed_policy_reference_to_permission_set(
            InstanceArn=inst["InstanceArn"],
            PermissionSetArn=ps,
            CustomerManagedPolicyReference={"Name": "baseline", "Path": "/"},
        )
        ids = session.client("identitystore")
        store = inst["IdentityStoreId"]
        uid = ids.create_user(
            IdentityStoreId=store,
            UserName="alice",
            DisplayName="Alice",
            Name={"GivenName": "A", "FamilyName": "B"},
            Emails=[{"Value": "alice@example.com"}],
        )["UserId"]
        gid = ids.create_group(IdentityStoreId=store, DisplayName="admins")["GroupId"]
        ids.create_group_membership(IdentityStoreId=store, GroupId=gid, MemberId={"UserId": uid})
        sso.create_account_assignment(
            InstanceArn=inst["InstanceArn"],
            TargetId=ACCOUNT,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=ps,
            PrincipalType="GROUP",
            PrincipalId=gid,
        )
        sso.provision_permission_set(
            InstanceArn=inst["InstanceArn"],
            PermissionSetArn=ps,
            TargetType="ALL_PROVISIONED_ACCOUNTS",
        )

        collector = _collector(["identity_center"])
        assets = _run(collector)
        assert _status(collector) == {"identity_center": ServiceStatus.SUCCESS}

        pset = _one(assets, AssetType.PERMISSION_SET, "Admin")
        group = _one(assets, AssetType.IDENTITY_GROUP, "admins")
        user = _one(assets, AssetType.IDENTITY_USER, "alice")
        instance = _one(assets, AssetType.IDENTITY_PROVIDER)
        assert instance.metadata["home_region"] == "us-east-1"
        assert pset.metadata["is_admin"] is True
        assert pset.metadata["customer_managed_policies"] == ["/baseline"]
        assert pset.metadata["provisioned_accounts"] == [ACCOUNT]
        assert pset.metadata["provisioned_role_prefix"] == "AWSReservedSSO_Admin_"
        # contact details never collected
        assert "alice@example.com" not in json.dumps(user.metadata) + json.dumps(user.raw_data)

        account = _account()
        edges = RelationshipLinker(assets + [account]).link()
        assert _edge(edges, group, account, EdgeType.GRANTS_ACCESS)
        assert _edge(edges, group, pset, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, group, user, EdgeType.CONTAINS)
        assert _edge(edges, pset, account, EdgeType.MANAGES, "OWNED_BY")
        assert _edge(edges, instance, pset, EdgeType.CONTAINS)
        grant = _edge(edges, group, account, EdgeType.GRANTS_ACCESS)[0]
        assert grant.properties["permission_sets"] == ["Admin"]

    def test_home_region_fallback(self, monkeypatch):
        collector = _collector(["identity_center"], region="eu-west-3")
        inst = {
            "InstanceArn": "arn:aws:sso:::instance/ssoins-1",
            "IdentityStoreId": "d-1",
            "Status": "ACTIVE",
        }
        clients = {
            ("sso-admin", "eu-west-3"): FakeClient({"list_instances": {"Instances": []}}),
            ("sso-admin", "us-east-1"): FakeClient({"list_instances": {"Instances": []}}),
            ("sso-admin", "us-east-2"): FakeClient(
                {
                    "list_instances": {"Instances": [inst]},
                    "list_permission_sets": {"PermissionSets": []},
                }
            ),
            "sso-admin": FakeClient({"list_instances": {"Instances": []}}),
            "identitystore": FakeClient(
                {"list_users": {"Users": []}, "list_groups": {"Groups": []}}
            ),
        }
        _use_fakes(monkeypatch, collector, clients)
        assets = _run(collector)
        assert _status(collector)["identity_center"] == ServiceStatus.SUCCESS
        idp = _one(assets, AssetType.IDENTITY_PROVIDER)
        assert idp.metadata["home_region"] == "us-east-2" and idp.region == "us-east-2"


# ── IAM extras ──


@mock_aws
class TestIamExtras:
    def test_saml_provider_resolves_trust_and_access_keys(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam")
        saml = iam.create_saml_provider(Name="okta", SAMLMetadataDocument="x" * 1200)[
            "SAMLProviderArn"
        ]
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": saml},
                    "Action": "sts:AssumeRoleWithSAML",
                }
            ],
        }
        iam.create_role(RoleName="sso-admin", AssumeRolePolicyDocument=json.dumps(trust))
        iam.create_user(UserName="bob")
        key = iam.create_access_key(UserName="bob")["AccessKey"]

        collector = _collector(["iam", "iam_saml_providers", "iam_access_keys"])
        assets = _run(collector)
        status = _status(collector)
        assert status["iam_saml_providers"] == ServiceStatus.SUCCESS
        assert status["iam_access_keys"] == ServiceStatus.SUCCESS

        provider = _one(assets, AssetType.IDENTITY_PROVIDER, "okta")
        role = _one(assets, AssetType.IAM_ROLE, "sso-admin")
        user = _one(assets, AssetType.IAM_USER, "bob")
        access_key = _one(assets, AssetType.ACCESS_KEY)
        assert access_key.metadata["access_key_id"] == key["AccessKeyId"]
        assert access_key.metadata["status"] == "Active"
        assert access_key.metadata["never_used"] in (True, False)
        assert key["SecretAccessKey"] not in json.dumps(access_key.metadata, default=str)

        edges = RelationshipLinker(assets).link()
        assert _edge(edges, provider, role, EdgeType.IAM_TRUST)
        assert _edge(edges, user, access_key, EdgeType.CONTAINS)

    def test_roles_anywhere(self, monkeypatch):
        collector = _collector(["rolesanywhere"])
        anchor_arn = f"arn:aws:rolesanywhere:us-east-1:{ACCOUNT}:trust-anchor/ta-1"
        role_arn = f"arn:aws:iam::{ACCOUNT}:role/onprem"
        fake = FakeClient(
            {
                "list_trust_anchors": {
                    "trustAnchors": [
                        {
                            "trustAnchorArn": anchor_arn,
                            "trustAnchorId": "ta-1",
                            "name": "corp-ca",
                            "enabled": True,
                            "source": {
                                "sourceType": "CERTIFICATE_BUNDLE",
                                "sourceData": {"x509CertificateData": "PEM"},
                            },
                        }
                    ]
                },
                "list_profiles": {
                    "profiles": [
                        {
                            "profileArn": f"arn:aws:rolesanywhere:us-east-1:{ACCOUNT}:profile/p-1",
                            "profileId": "p-1",
                            "name": "servers",
                            "enabled": True,
                            "roleArns": [role_arn],
                            "sessionPolicy": "{}",
                        }
                    ]
                },
            }
        )
        _use_fakes(monkeypatch, collector, {"rolesanywhere": fake})
        assets = _run(collector)
        assert _status(collector)["rolesanywhere"] == ServiceStatus.SUCCESS
        anchor = _one(assets, AssetType.IDENTITY_PROVIDER, "corp-ca")
        profile = _one(assets, AssetType.PERMISSION_SET, "servers")
        assert "PEM" not in json.dumps(anchor.metadata)
        assert profile.metadata["has_session_policy"] is True
        role = CloudAsset(
            arn=role_arn,
            name="onprem",
            asset_type=AssetType.IAM_ROLE,
            provider=CloudProvider.AWS,
            region="global",
            account_id=ACCOUNT,
        )
        edges = RelationshipLinker(assets + [role]).link()
        assert _edge(edges, profile, role, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, anchor, profile, EdgeType.IAM_TRUST)


# ── KMS, Secrets Manager, DynamoDB ──


@mock_aws
class TestDataProtection:
    def _key(self, session):
        kms = session.client("kms")
        key = kms.create_key(Policy=_policy(f"arn:aws:iam::{EXTERNAL}:root", "kms:Decrypt"))[
            "KeyMetadata"
        ]
        kms.create_alias(AliasName="alias/app", TargetKeyId=key["KeyId"])
        kms.enable_key_rotation(KeyId=key["KeyId"])
        return key

    def test_kms_aliases_rotation_policy_and_grants(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        key = self._key(session)
        iam = session.client("iam")
        bob = iam.create_user(UserName="bob")["User"]["Arn"]
        session.client("kms").create_grant(
            KeyId=key["KeyId"], GranteePrincipal=bob, Operations=["Decrypt"]
        )
        session.client("secretsmanager").create_secret(
            Name="db", SecretString="hunter2", KmsKeyId="alias/app"
        )

        collector = _collector(["kms", "secretsmanager", "iam"])
        assets = _run(collector)
        status = _status(collector)
        assert (
            status["kms"] == ServiceStatus.SUCCESS
            and status["secretsmanager"] == ServiceStatus.SUCCESS
        )

        kms_key = _one(assets, AssetType.KMS_KEY)
        secret = _one(assets, AssetType.SECRET, "db")
        user = _one(assets, AssetType.IAM_USER, "bob")
        # backward-compatible keys plus the rotation fix
        for k in ("key_state", "key_usage", "key_manager", "origin"):
            assert k in kms_key.metadata
        assert kms_key.metadata["rotation_enabled"] is True
        assert "alias/app" in kms_key.metadata["aliases"]
        assert kms_key.metadata["external_accounts"] == [EXTERNAL]
        assert "hunter2" not in json.dumps(secret.metadata, default=str)

        linker = RelationshipLinker(assets)
        edges = linker.link()
        assert _edge(
            edges, secret, kms_key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"
        )  # via alias/app
        assert _edge(edges, user, kms_key, EdgeType.GRANTS_ACCESS)  # KMS grant
        external = next(a for a in linker.external_assets if a.account_id == EXTERNAL)
        assert _edge(edges, external, kms_key, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST")

    def test_secret_rotation_policy_and_replicas(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        sm = session.client("secretsmanager")
        arn = sm.create_secret(Name="api", SecretString="s3cr3t")["ARN"]
        rotation_fn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:rotate"
        try:
            sm.rotate_secret(
                SecretId="api",
                RotationLambdaARN=rotation_fn,
                RotationRules={"AutomaticallyAfterDays": 30},
            )
        except ClientError:
            pass  # moto validates the function but still records the rotation config
        sm.put_resource_policy(
            SecretId="api",
            ResourcePolicy=_policy(
                f"arn:aws:iam::{EXTERNAL}:root", "secretsmanager:GetSecretValue"
            ),
        )
        sm.replicate_secret_to_regions(SecretId="api", AddReplicaRegions=[{"Region": "eu-west-1"}])

        collector = _collector(["secretsmanager"])
        assets = _run(collector)
        assert _status(collector)["secretsmanager"] == ServiceStatus.SUCCESS
        secret = _one(assets, AssetType.SECRET, "api")
        md = secret.metadata
        assert md["rotation_enabled"] is True and md["rotation_lambda"] == rotation_fn
        assert md["replica_regions"] == ["eu-west-1"]
        assert md["external_accounts"] == [EXTERNAL]
        assert "s3cr3t" not in json.dumps(md, default=str) + json.dumps(
            secret.raw_data, default=str
        )
        rels = {(r["target"], r["edge"], r.get("relationship")) for r in md["relations"]}
        assert (rotation_fn, "INVOKES", "ROTATES_SECRET") in rels
        assert (arn.replace("us-east-1", "eu-west-1"), "REFERENCES", "REPLICATES_TO") in rels

        fn = CloudAsset(
            arn=rotation_fn,
            name="rotate",
            asset_type=AssetType.LAMBDA_FUNCTION,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
        )
        edges = RelationshipLinker(assets + [fn]).link()
        assert _edge(edges, secret, fn, EdgeType.INVOKES, "ROTATES_SECRET")

    def test_dynamodb_kms_streams_pitr_and_policy(self, aws_credentials, skip_crc32):
        session = boto3.Session(region_name="us-east-1")
        key = self._key(session)
        ddb = session.client("dynamodb")
        table = ddb.create_table(
            TableName="orders",
            KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
            SSESpecification={"Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": key["Arn"]},
        )["TableDescription"]
        ddb.update_continuous_backups(
            TableName="orders",
            PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
        )
        ddb.put_resource_policy(
            ResourceArn=table["TableArn"],
            Policy=_policy(f"arn:aws:iam::{EXTERNAL}:root", "dynamodb:GetItem"),
        )

        collector = _collector(["dynamodb", "kms"])
        assets = _run(collector)
        assert _status(collector)["dynamodb"] == ServiceStatus.SUCCESS
        tbl = _one(assets, AssetType.DYNAMODB_TABLE, "orders")
        kms_key = _one(assets, AssetType.KMS_KEY)
        md = tbl.metadata
        for k in ("status", "item_count", "size_bytes", "billing_mode", "encryption"):
            assert k in md
        assert md["billing_mode"] == "PAY_PER_REQUEST"
        assert md["pitr_enabled"] is True
        assert md["stream_enabled"] is True and md["stream_arn"]
        assert md["external_accounts"] == [EXTERNAL]

        # An event source mapping that names the stream ARN resolves to the table
        consumer = CloudAsset(
            arn=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:consumer",
            name="consumer",
            asset_type=AssetType.LAMBDA_FUNCTION,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
            metadata={
                "relations": [{"target": md["stream_arn"], "edge": "INVOKES", "reverse": True}]
            },
        )
        edges = RelationshipLinker(assets + [consumer]).link()
        assert _edge(edges, tbl, kms_key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        assert _edge(edges, tbl, consumer, EdgeType.INVOKES)

    def test_dynamodb_replicas_and_kinesis_destination(self, monkeypatch):
        collector = _collector(["dynamodb"])
        table_arn = f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/events"
        stream_arn = f"arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/cdc"
        fake = FakeClient(
            {
                "list_tables": {"TableNames": ["events"]},
                "describe_table": {
                    "Table": {
                        "TableName": "events",
                        "TableArn": table_arn,
                        "TableStatus": "ACTIVE",
                        "Replicas": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}],
                        "GlobalTableVersion": "2019.11.21",
                    }
                },
                "describe_continuous_backups": {
                    "ContinuousBackupsDescription": {
                        "ContinuousBackupsStatus": "ENABLED",
                        "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"},
                    }
                },
                "describe_kinesis_streaming_destination": {
                    "KinesisDataStreamDestinations": [
                        {"StreamArn": stream_arn, "DestinationStatus": "ACTIVE"}
                    ]
                },
                "list_tags_of_resource": {"Tags": []},
            }
        )
        _use_fakes(monkeypatch, collector, {"dynamodb": fake})
        assets = _run(collector)
        tbl = _one(assets, AssetType.DYNAMODB_TABLE, "events")
        assert tbl.metadata["replica_regions"] == ["us-east-1", "eu-west-1"]
        assert tbl.metadata["pitr_enabled"] is False
        stream = CloudAsset(
            arn=stream_arn,
            name="cdc",
            asset_type=AssetType.DATA_STREAM,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
        )
        replica = CloudAsset(
            arn=table_arn.replace("us-east-1", "eu-west-1"),
            name="events",
            asset_type=AssetType.DYNAMODB_TABLE,
            provider=CloudProvider.AWS,
            region="eu-west-1",
            account_id=ACCOUNT,
        )
        edges = RelationshipLinker(assets + [stream, replica]).link()
        assert _edge(edges, tbl, stream, EdgeType.REFERENCES, "STREAMS_TO")
        assert _edge(edges, tbl, replica, EdgeType.REFERENCES, "REPLICATES_TO")


# ── Snapshots and AMIs ──


@mock_aws
class TestSnapshotsAndImages:
    def test_ebs_snapshot_and_ami_sharing(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2")
        vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)["VolumeId"]
        snap = ec2.create_snapshot(VolumeId=vol)["SnapshotId"]
        ec2.modify_snapshot_attribute(
            SnapshotId=snap,
            Attribute="createVolumePermission",
            OperationType="add",
            GroupNames=["all"],
        )
        instance = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)["Instances"][
            0
        ]["InstanceId"]
        image = ec2.create_image(InstanceId=instance, Name="golden")["ImageId"]
        ec2.modify_image_attribute(ImageId=image, LaunchPermission={"Add": [{"UserId": EXTERNAL}]})

        collector = _collector(["ebs_snapshots", "machine_images", "ebs_volumes"])
        assets = _run(collector)
        status = _status(collector)
        assert status["ebs_snapshots"] == ServiceStatus.SUCCESS
        assert status["machine_images"] == ServiceStatus.SUCCESS

        snapshot = next(a for a in assets if a.asset_type == AssetType.SNAPSHOT and a.name == snap)
        ami = _one(assets, AssetType.MACHINE_IMAGE, "golden")
        volume = next(
            a
            for a in assets
            if a.asset_type == AssetType.EBS_VOLUME and a.metadata["volume_id"] == vol
        )
        assert snapshot.is_internet_exposed and snapshot.metadata["public"] is True
        assert snapshot.metadata["source_volume_id"] == vol
        assert ami.metadata["shared_accounts"] == [EXTERNAL]
        assert not ami.is_internet_exposed

        linker = RelationshipLinker(assets)
        edges = linker.link()
        assert _edge(edges, snapshot, volume, EdgeType.REFERENCES)
        external = next(a for a in linker.external_assets if a.account_id == EXTERNAL)
        assert _edge(edges, external, ami, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST")
        backing = ami.metadata["snapshots"][0]
        backing_asset = next((a for a in assets if a.name == backing), None)
        if backing_asset is not None:  # moto owns AMI snapshots as "self"
            assert _edge(edges, ami, backing_asset, EdgeType.REFERENCES, "DEPENDS_ON")

    def test_rds_manual_snapshot_sharing(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        rds = session.client("rds")
        rds.create_db_instance(
            DBInstanceIdentifier="db1",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
        )
        rds.create_db_snapshot(DBInstanceIdentifier="db1", DBSnapshotIdentifier="db1-manual")
        rds.modify_db_snapshot_attribute(
            DBSnapshotIdentifier="db1-manual", AttributeName="restore", ValuesToAdd=[EXTERNAL]
        )
        rds.create_db_cluster(
            DBClusterIdentifier="c1",
            Engine="aurora-postgresql",
            MasterUsername="admin",
            MasterUserPassword="password123",
        )
        rds.create_db_cluster_snapshot(
            DBClusterIdentifier="c1", DBClusterSnapshotIdentifier="c1-manual"
        )
        rds.modify_db_cluster_snapshot_attribute(
            DBClusterSnapshotIdentifier="c1-manual", AttributeName="restore", ValuesToAdd=["all"]
        )

        collector = _collector(["rds_snapshots", "rds"])
        assets = _run(collector)
        assert _status(collector)["rds_snapshots"] == ServiceStatus.SUCCESS
        inst_snap = _one(assets, AssetType.SNAPSHOT, "db1-manual")
        cluster_snap = _one(assets, AssetType.SNAPSHOT, "c1-manual")
        db = _one(assets, AssetType.RDS_INSTANCE, "db1")
        assert (
            inst_snap.metadata["shared_accounts"] == [EXTERNAL]
            and not inst_snap.is_internet_exposed
        )
        assert cluster_snap.metadata["public"] is True and cluster_snap.is_internet_exposed
        assert "MasterUsername" not in inst_snap.raw_data

        linker = RelationshipLinker(assets)
        edges = linker.link()
        assert _edge(edges, inst_snap, db, EdgeType.REFERENCES)
        external = next(a for a in linker.external_assets if a.account_id == EXTERNAL)
        assert _edge(edges, external, inst_snap, EdgeType.GRANTS_ACCESS)


# ── S3 access points ──


@mock_aws
class TestS3AccessPoints:
    def test_access_points_and_multi_region_access_points(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        session.client("s3").create_bucket(Bucket="data-lake")
        s3c = session.client("s3control")
        s3c.put_public_access_block(
            AccountId=ACCOUNT,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3c.create_access_point(
            AccountId=ACCOUNT,
            Name="analytics",
            Bucket="data-lake",
            VpcConfiguration={"VpcId": "vpc-12345678"},
        )
        s3c.create_multi_region_access_point(
            AccountId=ACCOUNT,
            ClientToken="t",
            Details={"Name": "global-lake", "Regions": [{"Bucket": "data-lake"}]},
        )

        collector = _collector(["s3_access_points", "s3_multi_region_access_points", "s3"])
        assets = _run(collector)
        status = _status(collector)
        assert status["s3_access_points"] == ServiceStatus.SUCCESS
        assert status["s3_multi_region_access_points"] == ServiceStatus.SUCCESS

        ap = _one(assets, AssetType.ACCESS_POINT, "analytics")
        mrap = _one(assets, AssetType.ACCESS_POINT, "global-lake")
        bucket = _one(assets, AssetType.S3_BUCKET, "data-lake")
        assert ap.metadata["endpoint_kind"] == "s3_access_point"
        assert ap.metadata["network_origin"] == "VPC" and ap.metadata["vpc_id"] == "vpc-12345678"
        assert ap.metadata["account_public_access_block"]["RestrictPublicBuckets"] is True
        assert not ap.is_internet_exposed
        assert mrap.region == "global" and mrap.metadata["regions"] == ["us-east-1"]

        vpc = CloudAsset(
            arn=f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/vpc-12345678",
            name="vpc-12345678",
            asset_type=AssetType.VPC,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
            metadata={"vpc_id": "vpc-12345678"},
        )
        edges = RelationshipLinker(assets + [vpc]).link()
        assert _edge(edges, ap, bucket, EdgeType.REFERENCES, "READS_FROM")
        assert _edge(edges, ap, vpc, EdgeType.ATTACHED_TO)
        assert _edge(edges, mrap, bucket, EdgeType.REFERENCES, "READS_FROM")


# ── StackSets ──


@mock_aws
class TestStackSets:
    def test_control_tower_stack_set_manages_instances(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        cfn = session.client("cloudformation")
        template = {
            "Resources": {"T": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": "baseline"}}}
        }
        cfn.create_stack_set(
            StackSetName="AWSControlTowerBP-BASELINE-CONFIG",
            TemplateBody=json.dumps(template),
            Parameters=[{"ParameterKey": "Secret", "ParameterValue": "do-not-store"}],
        )
        cfn.create_stack_instances(
            StackSetName="AWSControlTowerBP-BASELINE-CONFIG",
            Accounts=[ACCOUNT],
            Regions=["us-east-1"],
        )

        collector = _collector(["stack_sets"])
        assets = _run(collector)
        assert _status(collector)["stack_sets"] == ServiceStatus.SUCCESS
        ss = _one(assets, AssetType.STACK_SET)
        assert ss.metadata["control_tower"] is True
        assert ss.metadata["accounts"] == [ACCOUNT] and ss.metadata["instance_count"] == 1
        assert "do-not-store" not in json.dumps(ss.metadata, default=str) + json.dumps(
            ss.raw_data, default=str
        )

        # moto mints a fresh StackId on every ListStackInstances call: take it from the relation
        stack_id = next(
            r["target"]
            for r in ss.metadata["relations"]
            if r.get("description") == "stack instance"
        )
        assert stack_id.startswith(f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/StackSet-")
        stack = CloudAsset(
            arn=stack_id,
            name="StackSet-baseline",
            asset_type=AssetType.IAC_STACK,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
        )
        account = _account()
        edges = RelationshipLinker(assets + [stack, account]).link()
        assert _edge(edges, ss, stack, EdgeType.MANAGES, "OWNED_BY")
        assert _edge(edges, ss, account, EdgeType.MANAGES, "OWNED_BY")


# ── RAM, Service Catalog (fake clients: moto lacks the operations) ──


class TestSharingFakes:
    def test_ram_outgoing_and_incoming_shares(self, monkeypatch):
        collector = _collector(["ram_shares"])
        out_arn = f"arn:aws:ram:us-east-1:{ACCOUNT}:resource-share/out-1"
        in_arn = f"arn:aws:ram:us-east-1:{EXTERNAL}:resource-share/in-1"
        subnet_arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-0123456789abcdef0"
        org_ou = "arn:aws:organizations::111111111111:ou/o-abc/ou-1"
        tgw_arn = f"arn:aws:ec2:us-east-1:{EXTERNAL}:transit-gateway/tgw-0123456789abcdef0"

        def shares(resourceOwner, **_):
            if resourceOwner == "SELF":
                return {
                    "resourceShares": [
                        {
                            "resourceShareArn": out_arn,
                            "name": "network",
                            "owningAccountId": ACCOUNT,
                            "status": "ACTIVE",
                            "allowExternalPrincipals": True,
                        }
                    ]
                }
            return {
                "resourceShares": [
                    {
                        "resourceShareArn": in_arn,
                        "name": "shared-tgw",
                        "owningAccountId": EXTERNAL,
                        "status": "ACTIVE",
                    }
                ]
            }

        def resources(resourceOwner, **_):
            if resourceOwner == "SELF":
                return {
                    "resources": [
                        {"arn": subnet_arn, "type": "ec2:Subnet", "resourceShareArn": out_arn}
                    ]
                }
            return {
                "resources": [
                    {"arn": tgw_arn, "type": "ec2:TransitGateway", "resourceShareArn": in_arn}
                ]
            }

        def principals(resourceOwner, **_):
            if resourceOwner == "SELF":
                return {
                    "principals": [
                        {"id": "444455556666", "resourceShareArn": out_arn, "external": True},
                        {"id": org_ou, "resourceShareArn": out_arn, "external": False},
                    ]
                }
            return {"principals": [{"id": ACCOUNT, "resourceShareArn": in_arn}]}

        fake = FakeClient(
            {
                "get_resource_shares": shares,
                "list_resources": resources,
                "list_principals": principals,
            }
        )
        _use_fakes(monkeypatch, collector, {"ram": fake})
        assets = _run(collector)
        assert _status(collector)["ram_shares"] == ServiceStatus.SUCCESS
        out = _one(assets, AssetType.RESOURCE_SHARE, "network")
        incoming = _one(assets, AssetType.RESOURCE_SHARE, "shared-tgw")
        assert (
            out.metadata["direction"] == "outgoing" and out.metadata["external_principals"] is True
        )
        assert incoming.metadata["direction"] == "incoming"
        assert incoming.metadata["owning_account_id"] == EXTERNAL

        subnet = CloudAsset(
            arn=subnet_arn,
            name="shared",
            asset_type=AssetType.SUBNET,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
        )
        ou = CloudAsset(
            arn=org_ou,
            name="Workloads",
            asset_type=AssetType.ORG_UNIT,
            provider=CloudProvider.AWS,
            region="global",
            account_id="111111111111",
        )
        account = _account()
        linker = RelationshipLinker(assets + [subnet, ou, account])
        edges = linker.link()
        assert _edge(edges, out, subnet, EdgeType.GRANTS_ACCESS)
        assert _edge(edges, ou, out, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST")
        partner = next(a for a in linker.external_assets if a.account_id == "444455556666")
        assert _edge(edges, partner, out, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST")
        assert _edge(edges, account, incoming, EdgeType.GRANTS_ACCESS)
        owner = next(a for a in linker.external_assets if a.account_id == EXTERNAL)
        assert _edge(edges, owner, incoming, EdgeType.MANAGES, "OWNED_BY")

    def test_service_catalog_account_factory(self, monkeypatch):
        collector = _collector(["service_catalog"])
        vended = "222233334444"
        portfolio_arn = f"arn:aws:catalog:us-east-1:{ACCOUNT}:portfolio/port-1"
        stack_arn = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/SC-{ACCOUNT}-pp-1/abc"
        launch_role = f"arn:aws:iam::{ACCOUNT}:role/AWSControlTowerAdmin"
        fake = FakeClient(
            {
                "list_portfolios": {
                    "PortfolioDetails": [
                        {
                            "Id": "port-1",
                            "ARN": portfolio_arn,
                            "DisplayName": "AWS Control Tower Account Factory Portfolio",
                            "ProviderName": "AWS Control Tower",
                        }
                    ]
                },
                "list_principals_for_portfolio": {
                    "Principals": [
                        {
                            "PrincipalARN": f"arn:aws:iam::{ACCOUNT}:role/AWSControlTowerAdmin",
                            "PrincipalType": "IAM",
                        }
                    ]
                },
                "list_portfolio_access": {"AccountIds": []},
                "search_products_as_admin": {
                    "ProductViewDetails": [
                        {
                            "ProductViewSummary": {
                                "ProductId": "prod-1",
                                "Name": "AWS Control Tower Account Factory",
                            }
                        }
                    ]
                },
                "search_provisioned_products": {
                    "ProvisionedProducts": [
                        {
                            "Name": "workload-prod",
                            "Id": "pp-1",
                            "Arn": f"arn:aws:servicecatalog:us-east-1:{ACCOUNT}:stack/workload-prod/pp-1",
                            "Type": "CFN_STACK",
                            "Status": "AVAILABLE",
                            "PhysicalId": stack_arn,
                            "ProductId": "prod-1",
                            "ProductName": "AWS Control Tower Account Factory",
                        }
                    ]
                },
                "describe_provisioned_product": {
                    "ProvisionedProductDetail": {"Id": "pp-1", "LaunchRoleArn": launch_role}
                },
                "get_provisioned_product_outputs": {
                    "Outputs": [
                        {"OutputKey": "AccountId", "OutputValue": vended},
                        {"OutputKey": "AccountEmail", "OutputValue": "owner@example.com"},
                        {
                            "OutputKey": "SSOUserPortal",
                            "OutputValue": "https://d-1.awsapps.com/start",
                        },
                    ]
                },
            }
        )
        _use_fakes(monkeypatch, collector, {"servicecatalog": fake})
        assets = _run(collector)
        assert _status(collector)["service_catalog"] == ServiceStatus.SUCCESS
        portfolio = _one(assets, AssetType.PRODUCT_PORTFOLIO)
        product = _one(assets, AssetType.PROVISIONED_PRODUCT, "workload-prod")
        assert portfolio.metadata["control_tower"] is True
        assert product.metadata["control_tower_account_factory"] is True
        assert product.metadata["vended_account_id"] == vended
        assert "owner@example.com" not in json.dumps(product.metadata)

        stack = CloudAsset(
            arn=stack_arn,
            name="SC-stack",
            asset_type=AssetType.IAC_STACK,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
        )
        role = CloudAsset(
            arn=launch_role,
            name="AWSControlTowerAdmin",
            asset_type=AssetType.IAM_ROLE,
            provider=CloudProvider.AWS,
            region="global",
            account_id=ACCOUNT,
        )
        vended_account = _account(vended)
        edges = RelationshipLinker(assets + [stack, role, vended_account]).link()
        assert _edge(edges, product, vended_account, EdgeType.MANAGES, "OWNED_BY")
        assert _edge(edges, product, stack, EdgeType.MANAGES, "OWNED_BY")
        assert _edge(edges, product, role, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, product, portfolio, EdgeType.REFERENCES)
        assert _edge(edges, role, portfolio, EdgeType.GRANTS_ACCESS)

    def test_service_catalog_total_failure_is_reported(self, monkeypatch):
        collector = _collector(["service_catalog"])
        _use_fakes(monkeypatch, collector, {"servicecatalog": FakeClient({})})
        _run(collector)
        assert _status(collector)["service_catalog"] == ServiceStatus.FAILED


# ── Cognito ──


@mock_aws
class TestCognito:
    def test_user_pool_triggers_and_identity_pool_link(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        trigger = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:pre-signup"
        idp = session.client("cognito-idp")
        pool = idp.create_user_pool(
            PoolName="customers",
            LambdaConfig={"PreSignUp": trigger},
            AdminCreateUserConfig={"AllowAdminCreateUserOnly": False},
        )["UserPool"]
        client_id = idp.create_user_pool_client(UserPoolId=pool["Id"], ClientName="web")[
            "UserPoolClient"
        ]["ClientId"]
        session.client("cognito-identity").create_identity_pool(
            IdentityPoolName="app",
            AllowUnauthenticatedIdentities=False,
            CognitoIdentityProviders=[
                {
                    "ProviderName": f"cognito-idp.us-east-1.amazonaws.com/{pool['Id']}",
                    "ClientId": client_id,
                }
            ],
        )

        collector = _collector(["cognito_user_pools", "cognito_identity_pools"])
        assets = _run(collector)
        status = _status(collector)
        assert status["cognito_user_pools"] == ServiceStatus.SUCCESS
        assert status["cognito_identity_pools"] == ServiceStatus.SUCCESS
        user_pool = _one(assets, AssetType.USER_POOL, "customers")
        identity_pool = _one(assets, AssetType.IDENTITY_POOL, "app")
        assert user_pool.metadata["app_client_count"] == 1
        assert user_pool.metadata["lambda_triggers"] == {"PreSignUp": trigger}
        assert user_pool.metadata["self_signup_enabled"] is True

        fn = CloudAsset(
            arn=trigger,
            name="pre-signup",
            asset_type=AssetType.LAMBDA_FUNCTION,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id=ACCOUNT,
        )
        edges = RelationshipLinker(assets + [fn]).link()
        assert _edge(edges, user_pool, fn, EdgeType.INVOKES)
        assert _edge(edges, identity_pool, user_pool, EdgeType.REFERENCES, "DEPENDS_ON")

    def test_identity_pool_roles_and_guest_exposure(self, monkeypatch):
        collector = _collector(["cognito_identity_pools"])
        auth = f"arn:aws:iam::{ACCOUNT}:role/cognito-auth"
        guest = f"arn:aws:iam::{ACCOUNT}:role/cognito-guest"
        fake = FakeClient(
            {
                "list_identity_pools": {
                    "IdentityPools": [
                        {"IdentityPoolId": "us-east-1:abc", "IdentityPoolName": "app"}
                    ]
                },
                "describe_identity_pool": {
                    "IdentityPoolId": "us-east-1:abc",
                    "IdentityPoolName": "app",
                    "AllowUnauthenticatedIdentities": True,
                },
                "get_identity_pool_roles": {
                    "Roles": {"authenticated": auth, "unauthenticated": guest}
                },
            }
        )
        _use_fakes(monkeypatch, collector, {"cognito-identity": fake})
        assets = _run(collector)
        pool = _one(assets, AssetType.IDENTITY_POOL, "app")
        assert pool.is_internet_exposed and pool.metadata["unauthenticated_role"] == guest
        roles = [
            CloudAsset(
                arn=arn,
                name=arn.rsplit("/", 1)[-1],
                asset_type=AssetType.IAM_ROLE,
                provider=CloudProvider.AWS,
                region="global",
                account_id=ACCOUNT,
            )
            for arn in (auth, guest)
        ]
        edges = RelationshipLinker(assets + roles).link()
        assert _edge(edges, pool, roles[0], EdgeType.ASSUMES_ROLE)
        assert _edge(edges, pool, roles[1], EdgeType.ASSUMES_ROLE)
