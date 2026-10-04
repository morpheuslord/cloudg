"""Tests for the YAML reference catalogs and the Cloud Control breadth sweep."""

from __future__ import annotations

import asyncio
import json

import boto3
import pytest

from cloudg.inventory import catalogs
from cloudg.inventory.aws_deep import AWSDeepInventoryCollector, asset_type_from_arn
from cloudg.inventory.aws_services import cloudcontrol
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, EdgeType


@pytest.fixture
def aws_credentials(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(key, value)


class TestCatalogs:
    def test_packaged_catalogs_validate(self):
        cc = catalogs.load_catalog("aws_cloudcontrol")
        assert "AWS::EC2::Instance" in catalogs.flatten(cc["covered_types"])
        mapped = catalogs.asset_type_map(cc["asset_types"], "aws_cloudcontrol")
        assert mapped["AWS::SSO::PermissionSet"] == AssetType.PERMISSION_SET
        arn = catalogs.load_catalog("aws_arn_types")
        assert catalogs.asset_type_map(arn["arn_types"])["sqs"] == AssetType.MESSAGE_QUEUE

    def test_unknown_asset_type_is_rejected(self):
        with pytest.raises(ValueError, match="NOT_A_TYPE"):
            catalogs.asset_type_map({"AWS::X::Y": "NOT_A_TYPE"}, "test")

    def test_overlay_merges(self, monkeypatch, tmp_path):
        (tmp_path / "aws_arn_types.yaml").write_text(
            'arn_types:\n  "braket": OTHER\n  "custom:widget": ML_MODEL\n'
        )
        monkeypatch.setenv("CLOUDG_CATALOG_DIR", str(tmp_path))
        catalogs.load_catalog.cache_clear()
        try:
            data = catalogs.load_catalog("aws_arn_types")["arn_types"]
            assert data["custom:widget"] == "ML_MODEL"
            assert data["sqs"] == "MESSAGE_QUEUE"  # packaged entries kept
        finally:
            catalogs.load_catalog.cache_clear()

    def test_flatten(self):
        assert catalogs.flatten({"a": ["x"], "b": ["y", "z"]}) == ["x", "y", "z"]
        assert catalogs.flatten(["x"]) == ["x"]

    def test_arn_classifier_from_catalog(self):
        assert (
            asset_type_from_arn("arn:aws:ecr:us-east-1:1:repository/app")
            == AssetType.CONTAINER_REGISTRY
        )


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    async def _gen(self):
        for page in self._pages:
            yield page

    def paginate(self, **kwargs):
        return self._gen()


class _FakeCC:
    def __init__(self, data, failing=()):
        self._data = data
        self._failing = set(failing)

    def get_paginator(self, op):
        assert op == "list_resources"
        outer = self

        class P:
            def paginate(self, TypeName, **kwargs):
                if TypeName in outer._failing:

                    async def boom():
                        raise RuntimeError("UnsupportedActionException")
                        yield  # pragma: no cover

                    return boom()
                return _Paginator(
                    [{"ResourceDescriptions": outer._data.get(TypeName, [])}]
                ).paginate()

        return P()


class _Ctx:
    def __init__(self, client):
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *exc):
        return False


def _collector(monkeypatch, fake, types, primary=True):
    session = boto3.Session(region_name="us-east-1")
    collector = AWSDeepInventoryCollector(
        session=session,
        region="us-east-1",
        account_id="123456789012",
        kubernetes=False,
        tagging_sweep=False,
        services=["sweep"],
        is_primary_region=primary,
    )
    monkeypatch.setattr(collector, "_client", lambda service, region=None: _Ctx(fake))
    monkeypatch.setattr(
        cloudcontrol, "_types_cache", [{"type": t, "requires": r} for t, r in types]
    )
    return collector


class TestCloudControlSweep:
    def test_lists_uncovered_types_and_links(self, monkeypatch, aws_credentials):
        queue_arn = "arn:aws:sqs:us-east-1:123456789012:jobs"
        fake = _FakeCC(
            {
                "AWS::Timestream::ScheduledQuery": [
                    {
                        "Identifier": "nightly",
                        "Properties": json.dumps(
                            {
                                "Arn": "arn:aws:timestream:us-east-1:123456789012:scheduled-query/nightly",
                                "Name": "nightly",
                                "Target": {
                                    "Arn": queue_arn,
                                    "RoleArn": "arn:aws:iam::123456789012:role/sched",
                                },
                            }
                        ),
                    }
                ],
                "AWS::AppConfig::HostedConfigurationVersion": [
                    {
                        "Identifier": "app|profile|1",
                        "Properties": json.dumps(
                            {
                                "ApplicationId": "app",
                                "Content": "db_host=10.0.0.5",
                                "ContentType": "text/plain",
                            }
                        ),
                    }
                ],
                "AWS::Amplify::App": [
                    {
                        "Identifier": "jdbc",
                        "Properties": json.dumps(
                            {
                                "Name": "web",
                                "BasicAuthConfig": {"Password": "x", "Username": "u"},
                                "AccessToken": "t",
                            }
                        ),
                    }
                ],
            }
        )
        types = [
            ("AWS::Timestream::ScheduledQuery", []),
            ("AWS::AppConfig::HostedConfigurationVersion", []),
            ("AWS::Amplify::App", []),
            ("AWS::EC2::Instance", []),  # covered by a deep collector
            ("AWS::EKS::AddOn", ["ClusterName"]),  # needs a parent identifier
        ]
        collector = _collector(monkeypatch, fake, types)
        assets = asyncio.run(collector.collect())
        by_type = {a.metadata.get("resource_type"): a for a in assets}
        assert set(by_type) == {
            "AWS::Timestream::ScheduledQuery",
            "AWS::AppConfig::HostedConfigurationVersion",
            "AWS::Amplify::App",
        }

        schedule = by_type["AWS::Timestream::ScheduledQuery"]
        assert schedule.asset_type == AssetType.OTHER  # unmapped type, unmapped ARN service
        assert schedule.arn.endswith("scheduled-query/nightly")
        param = by_type["AWS::AppConfig::HostedConfigurationVersion"]
        assert "Content" not in param.metadata["properties"]  # never copy configuration content
        assert param.arn.startswith(
            "cloudcontrol:AWS::AppConfig::HostedConfigurationVersion:us-east-1:123456789012:"
        )
        app = by_type["AWS::Amplify::App"]
        props = json.dumps(app.metadata["properties"])
        assert "Password" not in props and "AccessToken" not in props

        from cloudg.schema.models import CloudAsset, CloudProvider

        queue = CloudAsset(
            arn=queue_arn,
            name="jobs",
            asset_type=AssetType.MESSAGE_QUEUE,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id="123456789012",
        )
        edges = RelationshipLinker(assets + [queue]).link()
        assert any(
            e.source_id == schedule.id
            and e.target_id == queue.id
            and e.edge_type == EdgeType.REFERENCES
            for e in edges
        )

    def test_global_types_only_in_primary_region(self, monkeypatch, aws_credentials):
        fake = _FakeCC(
            {
                "AWS::Route53Resolver::ResolverRule": [],
                "AWS::Organizations::Policy": [
                    {"Identifier": "p-1", "Properties": json.dumps({"Name": "scp"})}
                ],
            }
        )
        types = [("AWS::Organizations::Policy", []), ("AWS::Route53Resolver::ResolverRule", [])]
        assert asyncio.run(_collector(monkeypatch, fake, types, primary=False).collect()) == []
        hits = asyncio.run(_collector(monkeypatch, fake, types, primary=True).collect())
        assert [a.region for a in hits] == ["global"]

    def test_failing_types_are_skipped_not_fatal(self, monkeypatch, aws_credentials):
        fake = _FakeCC(
            {"AWS::IoT::Thing": [{"Identifier": "q", "Properties": "{}"}]},
            failing={"AWS::Connect::Instance"},
        )
        collector = _collector(
            monkeypatch, fake, [("AWS::Connect::Instance", []), ("AWS::IoT::Thing", [])]
        )
        assets = asyncio.run(collector.collect())
        assert [a.metadata["resource_type"] for a in assets] == ["AWS::IoT::Thing"]
        records = {s.service: s for s in collector.coverage.services}
        assert records["cloud_control"].status.value == "SUCCESS"
        assert records["cloud_control_skipped_types"].asset_count == 1

    def test_sweep_hit_deduped_against_detailed_asset(self, monkeypatch, aws_credentials):
        arn = "arn:aws:states:us-east-1:123456789012:stateMachine:flow"
        fake = _FakeCC({"AWS::StepFunctions::Activity": [{"Identifier": arn, "Properties": "{}"}]})
        collector = _collector(monkeypatch, fake, [("AWS::StepFunctions::Activity", [])])

        async def detailed():
            return [collector._asset(arn=arn, name="flow", asset_type=AssetType.STATE_MACHINE)]

        monkeypatch.setattr(
            collector,
            "_service_tasks",
            lambda: {"stepfunctions": detailed, "cloud_control": collector._collect_cloud_control},
        )
        assets = asyncio.run(collector.collect())
        assert len(assets) == 1 and assets[0].asset_type == AssetType.STATE_MACHINE

    def test_redact(self):
        out = cloudcontrol.redact(
            {
                "Name": "x",
                "MasterUserPassword": "p",
                "SecretArn": "arn:aws:secretsmanager:x",
                "Nested": [{"AuthToken": "t", "Port": 1}],
            }
        )
        assert out == {
            "Name": "x",
            "SecretArn": "arn:aws:secretsmanager:x",
            "Nested": [{"Port": 1}],
        }
