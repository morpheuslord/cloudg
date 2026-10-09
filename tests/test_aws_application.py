"""Tests for the application / operations / integration collectors:
CI/CD, Systems Manager, AWS Backup, ECS extras and Cloud Map, Lambda
aliases, EventBridge Scheduler / Pipes / API destinations, CloudWatch Logs
subscriptions and OAM, CloudWatch alarms, Firehose, Batch, App Runner and
Elastic Beanstalk."""

from __future__ import annotations

import asyncio
import io
import json
import zipfile
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from cloudg.coverage import ServiceStatus
from cloudg.inventory.aws_deep import SERVICE_FAMILIES, AWSDeepInventoryCollector
from cloudg.inventory.linker import RelationshipLinker
from cloudg.inventory.mapper import deduplicate
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

ACCOUNT = "123456789012"
REGION = "us-east-1"
TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


@pytest.fixture
def aws_credentials(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
    }.items():
        monkeypatch.setenv(key, value)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


class _FakePaginator:
    def __init__(self, client: _FakeClient, op: str) -> None:
        self._client, self._op = client, op

    async def paginate(self, **kwargs: Any):
        yield await getattr(self._client, self._op)(**kwargs)


class _FakeClient:
    """Async stand-in for an aiobotocore client; unknown operations fail
    like AccessDenied so tolerance paths are exercised."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    def get_paginator(self, op: str) -> _FakePaginator:
        return _FakePaginator(self, op)

    def __getattr__(self, op: str) -> Any:
        if op.startswith("_"):
            raise AttributeError(op)

        async def call(**kwargs: Any) -> Any:
            self.calls.append((op, kwargs))
            if op not in self._responses:
                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": op}}, op)
            resp = self._responses[op]
            return resp(**kwargs) if callable(resp) else resp

        return call


def _collector(
    services: list[str], fakes: dict[str, _FakeClient] | None = None
) -> AWSDeepInventoryCollector:
    collector = AWSDeepInventoryCollector(
        session=boto3.Session(region_name=REGION),
        region=REGION,
        account_id=ACCOUNT,
        kubernetes=False,
        tagging_sweep=False,
        services=services,
    )
    if fakes:
        real = collector._client

        def client(service: str, region: str | None = None) -> Any:
            return fakes[service] if service in fakes else real(service, region)

        collector._client = client  # type: ignore[method-assign]
    return collector


def _run(collector: AWSDeepInventoryCollector) -> list[CloudAsset]:
    return asyncio.run(collector.collect())


def _status(collector: AWSDeepInventoryCollector) -> dict[str, ServiceStatus]:
    return {s.service: s.status for s in collector.coverage.services}


def _assert_success(collector: AWSDeepInventoryCollector, *names: str) -> None:
    status = _status(collector)
    for name in names:
        assert status.get(name) == ServiceStatus.SUCCESS, (
            name,
            status,
            collector.coverage.services,
        )


def _asset(name: str, asset_type: AssetType, arn: str, metadata: dict | None = None) -> CloudAsset:
    return CloudAsset(
        name=name,
        asset_type=asset_type,
        provider=CloudProvider.AWS,
        arn=arn,
        metadata=metadata or {},
        account_id=ACCOUNT,
        region=REGION,
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


def _one(assets: list[CloudAsset], asset_type: AssetType, **md: Any) -> CloudAsset:
    found = [
        a
        for a in assets
        if a.asset_type == asset_type and all(a.metadata.get(k) == v for k, v in md.items())
    ]
    assert len(found) == 1, (asset_type, md, [a.name for a in assets if a.asset_type == asset_type])
    return found[0]


def _by_arn(assets: list[CloudAsset]) -> dict[str, CloudAsset]:
    return {a.arn: a for a in assets}


def _dump(assets: list[CloudAsset]) -> str:
    return json.dumps([a.model_dump(mode="json") for a in assets])


def _lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("h.py", "def h(e, c):\n    return None\n")
    return buf.getvalue()


def _role(session, name: str = "app") -> str:
    return session.client("iam").create_role(RoleName=name, AssumeRolePolicyDocument=TRUST)["Role"][
        "Arn"
    ]


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def test_application_tasks_are_registered_with_families():
    collector = _collector(["all"])
    tasks = collector._service_tasks()
    registry = collector._application_tasks()
    for name, (_, family, is_global) in registry.items():
        assert name in tasks
        assert SERVICE_FAMILIES[name] == family
        assert is_global is False
    assert {
        "codepipeline",
        "ssm_parameters",
        "backup_vaults",
        "lambda_aliases",
        "firehose",
        "batch",
    } <= set(registry)
    # Narrowing by family selects the new collectors
    cicd = set(_collector(["cicd"])._service_tasks())
    assert cicd == {"codepipeline", "codebuild", "codedeploy", "codeconnections"}


# ----------------------------------------------------------------------
# CI/CD
# ----------------------------------------------------------------------


@mock_aws
def test_codepipeline_codebuild_and_parameters(aws_credentials):
    session = boto3.Session(region_name=REGION)
    role = _role(session)
    session.client("s3").create_bucket(Bucket="artifacts")
    repo = session.client("ecr").create_repository(repositoryName="builder")["repository"]
    session.client("ssm").put_parameter(Name="/app/db", Value="sekrit-value", Type="SecureString")
    session.client("codebuild").create_project(
        name="build",
        source={"type": "S3", "location": "artifacts/src.zip"},
        artifacts={"type": "S3", "location": "artifacts"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": repo["repositoryUri"] + ":latest",
            "computeType": "BUILD_GENERAL1_SMALL",
            "environmentVariables": [
                {"name": "DB_PASS", "value": "/app/db", "type": "PARAMETER_STORE"},
                {"name": "TOKEN", "value": "hunter2-plaintext", "type": "PLAINTEXT"},
            ],
        },
        serviceRole=role,
    )
    session.client("codepipeline").create_pipeline(
        pipeline={
            "name": "deliver",
            "roleArn": role,
            "artifactStore": {"type": "S3", "location": "artifacts"},
            "stages": [
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "src",
                            "actionTypeId": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "configuration": {"S3Bucket": "artifacts", "S3ObjectKey": "src.zip"},
                            "outputArtifacts": [{"name": "o"}],
                        }
                    ],
                },
                {
                    "name": "Build",
                    "actions": [
                        {
                            "name": "b",
                            "actionTypeId": {
                                "category": "Build",
                                "owner": "AWS",
                                "provider": "CodeBuild",
                                "version": "1",
                            },
                            "configuration": {"ProjectName": "build"},
                            "inputArtifacts": [{"name": "o"}],
                            "roleArn": "arn:aws:iam::999999999999:role/cross-build",
                        }
                    ],
                },
            ],
        }
    )

    collector = _collector(["codepipeline", "codebuild", "ssm_parameters", "iam", "s3", "ecr"])
    assets = _run(collector)
    _assert_success(collector, "codepipeline", "codebuild", "ssm_parameters")

    pipeline = _one(assets, AssetType.CI_PIPELINE)
    project = _one(assets, AssetType.BUILD_PROJECT)
    param = _one(assets, AssetType.PARAMETER)
    by_arn = _by_arn(assets)
    role_asset, bucket = by_arn[role], by_arn["arn:aws:s3:::artifacts"]
    repo_asset = by_arn[repo["repositoryArn"]]

    linker = RelationshipLinker(assets)
    edges = linker.link()
    assert _edge(edges, pipeline, project, EdgeType.INVOKES)
    assert _edge(edges, pipeline, role_asset, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, pipeline, bucket, EdgeType.REFERENCES, "WRITES_TO")
    assert _edge(edges, project, role_asset, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, project, repo_asset, EdgeType.USES_IMAGE)
    assert _edge(edges, project, param, EdgeType.REFERENCES, "READS_FROM")
    assert _edge(edges, project, bucket, EdgeType.REFERENCES, "READS_FROM")
    # Cross-account action role becomes an external account node
    external = {a.metadata.get("account_id") for a in linker.external_assets}
    assert "999999999999" in external
    assert pipeline.metadata["cross_account_actions"] == 1

    assert project.metadata["environment_variable_names"] == ["DB_PASS", "TOKEN"]
    assert param.metadata["type"] == "SecureString"
    dumped = _dump(assets)
    assert "hunter2-plaintext" not in dumped
    assert "sekrit-value" not in dumped


def test_codedeploy_and_connections_with_fake_clients():
    group = {
        "applicationName": "web",
        "deploymentGroupName": "prod",
        "deploymentGroupId": "dg-1",
        "serviceRoleArn": f"arn:aws:iam::{ACCOUNT}:role/codedeploy",
        "autoScalingGroups": [{"name": "web-asg"}],
        "ecsServices": [{"clusterName": "main", "serviceName": "api"}],
        "loadBalancerInfo": {
            "targetGroupPairInfoList": [{"targetGroups": [{"name": "blue"}, {"name": "green"}]}]
        },
        "triggerConfigurations": [
            {"triggerName": "t", "triggerTargetArn": f"arn:aws:sns:{REGION}:{ACCOUNT}:deploys"}
        ],
        "alarmConfiguration": {"alarms": [{"name": "5xx"}]},
        "computePlatform": "ECS",
    }
    codedeploy = _FakeClient(
        {
            "list_applications": {"applications": ["web"]},
            "batch_get_applications": {
                "applicationsInfo": [{"applicationName": "web", "computePlatform": "ECS"}]
            },
            "list_deployment_groups": {"deploymentGroups": ["prod"]},
            "batch_get_deployment_groups": {"deploymentGroupsInfo": [group]},
        }
    )
    conn_arn = f"arn:aws:codeconnections:{REGION}:{ACCOUNT}:connection/abc-123"
    connections = _FakeClient(
        {
            "list_connections": {
                "Connections": [
                    {
                        "ConnectionName": "github",
                        "ConnectionArn": conn_arn,
                        "ProviderType": "GitHub",
                        "OwnerAccountId": ACCOUNT,
                        "ConnectionStatus": "AVAILABLE",
                    }
                ]
            }
        }
    )
    collector = _collector(
        ["codedeploy", "codeconnections"],
        {"codedeploy": codedeploy, "codeconnections": connections},
    )
    assets = _run(collector)
    _assert_success(collector, "codedeploy", "codeconnections")

    dg = _one(assets, AssetType.DEPLOYMENT_GROUP)
    assert dg.arn == f"arn:aws:codedeploy:{REGION}:{ACCOUNT}:deploymentgroup:web/prod"
    conn = _one(assets, AssetType.SOURCE_CONNECTION, kind="source_connection")
    assert conn.metadata["aliases"] == [
        conn_arn.replace(":codeconnections:", ":codestar-connections:")
    ]

    asg = _asset(
        "web-asg",
        AssetType.AUTOSCALING_GROUP,
        f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:x:autoScalingGroupName/web-asg",
    )
    svc = _asset(
        "api", AssetType.CONTAINER_SERVICE, f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/main/api"
    )
    blue = _asset(
        "blue",
        AssetType.TARGET_GROUP,
        f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/blue/1",
    )
    role = _asset("codedeploy", AssetType.IAM_ROLE, f"arn:aws:iam::{ACCOUNT}:role/codedeploy")
    topic = _asset(
        "deploys", AssetType.NOTIFICATION_TOPIC, f"arn:aws:sns:{REGION}:{ACCOUNT}:deploys"
    )
    alarm = _asset("5xx", AssetType.ALARM, f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:5xx")
    pipeline = _asset(
        "p",
        AssetType.CI_PIPELINE,
        f"arn:aws:codepipeline:{REGION}:{ACCOUNT}:p",
        {
            "relations": [
                {
                    "target": "arn:aws:codestar-connections:us-east-1:123456789012:connection/abc-123",
                    "edge": "REFERENCES",
                    "relationship": "READS_FROM",
                }
            ]
        },
    )
    edges = RelationshipLinker(assets + [asg, svc, blue, role, topic, alarm, pipeline]).link()
    assert _edge(edges, dg, asg, EdgeType.MANAGES)
    assert _edge(edges, dg, svc, EdgeType.MANAGES)
    assert _edge(edges, dg, blue, EdgeType.MANAGES)
    assert _edge(edges, dg, role, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, dg, topic, EdgeType.INVOKES)
    assert _edge(edges, dg, alarm, EdgeType.REFERENCES, "MONITORED_BY")
    # Legacy codestar-connections ARN resolves through the alias
    assert _edge(edges, pipeline, conn, EdgeType.REFERENCES)


# ----------------------------------------------------------------------
# Systems Manager
# ----------------------------------------------------------------------


@mock_aws
def test_ssm_documents_and_maintenance_windows(aws_credentials):
    session = boto3.Session(region_name=REGION)
    role = _role(session)
    ssm = session.client("ssm")
    ssm.create_document(
        Name="Bootstrap",
        Content=json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "d",
                "mainSteps": [
                    {
                        "action": "aws:runShellScript",
                        "name": "x",
                        "inputs": {"runCommand": ["echo"]},
                    }
                ],
            }
        ),
        DocumentType="Command",
    )
    ssm.modify_document_permission(
        Name="Bootstrap", PermissionType="Share", AccountIdsToAdd=["222222222222"]
    )
    wid = ssm.create_maintenance_window(
        Name="patch",
        Schedule="cron(0 2 ? * SUN *)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=False,
    )["WindowId"]
    ssm.register_target_with_maintenance_window(
        WindowId=wid,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
    )
    ssm.register_task_with_maintenance_window(
        WindowId=wid,
        TaskArn="Bootstrap",
        TaskType="RUN_COMMAND",
        Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
        ServiceRoleArn=role,
        MaxConcurrency="1",
        MaxErrors="1",
    )

    collector = _collector(["ssm_documents", "ssm_maintenance_windows", "iam"])
    assets = _run(collector)
    _assert_success(collector, "ssm_documents", "ssm_maintenance_windows")

    doc = _one(assets, AssetType.RUNBOOK, kind="ssm_document")
    window = _one(assets, AssetType.SCHEDULE, kind="maintenance_window")
    assert doc.metadata["shared_with_accounts"] == ["222222222222"]
    assert not doc.is_internet_exposed
    instance = _asset(
        "web", AssetType.EC2, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
    )
    linker = RelationshipLinker(assets + [instance])
    edges = linker.link()
    shared = next(
        a for a in linker.external_assets if a.metadata.get("account_id") == "222222222222"
    )
    assert _edge(edges, shared, doc, EdgeType.GRANTS_ACCESS)
    assert _edge(edges, window, instance, EdgeType.MANAGES)
    assert _edge(edges, window, doc, EdgeType.REFERENCES)
    assert _edge(edges, window, _by_arn(assets)[role], EdgeType.ASSUMES_ROLE)


def test_ssm_fleet_and_associations_with_fake_client():
    ssm = _FakeClient(
        {
            "describe_instance_information": {
                "InstanceInformationList": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "PingStatus": "Online",
                        "PlatformType": "Linux",
                        "AgentVersion": "3.3",
                    },
                    {
                        "InstanceId": "mi-0123456789abcdef0",
                        "PingStatus": "ConnectionLost",
                        "PlatformType": "Windows",
                        "IamRole": "SSMServiceRole",
                        "IPAddress": "10.0.0.5",
                        "ComputerName": "onprem-1",
                        "IsLatestVersion": False,
                    },
                ]
            },
            "list_associations": {
                "Associations": [
                    {
                        "Name": "AWS-RunPatchBaseline",
                        "AssociationId": "assoc-1",
                        "AssociationName": "patching",
                        "Targets": [{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
                        "ScheduleExpression": "rate(1 day)",
                    }
                ]
            },
        }
    )
    collector = _collector(["ssm_managed_instances", "ssm_associations"], {"ssm": ssm})
    assets = _run(collector)
    _assert_success(collector, "ssm_managed_instances", "ssm_associations")

    fleet = _one(assets, AssetType.OTHER, kind="managed_fleet")
    hybrid = _one(assets, AssetType.VIRTUAL_MACHINE)
    assoc = _one(assets, AssetType.SCHEDULE, kind="ssm_association")
    assert fleet.metadata["outdated_agents"] == 1 and fleet.metadata["hybrid_nodes"] == 1
    instance = _asset(
        "web", AssetType.EC2, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
    )
    role = _asset(
        "SSMServiceRole", AssetType.IAM_ROLE, f"arn:aws:iam::{ACCOUNT}:role/SSMServiceRole"
    )
    edges = RelationshipLinker(assets + [instance, role]).link()
    assert _edge(edges, fleet, instance, EdgeType.MANAGES)
    assert _edge(edges, fleet, hybrid, EdgeType.MANAGES)
    assert _edge(edges, hybrid, role, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, assoc, instance, EdgeType.MANAGES, "SCHEDULED_BY")
    # AWS-owned documents are not declared as (unresolvable) references
    assert not [r for r in assoc.metadata["relations"] if "document/" in r["target"]]


# ----------------------------------------------------------------------
# AWS Backup
# ----------------------------------------------------------------------


@mock_aws
def test_backup_plans_and_vaults(aws_credentials):
    session = boto3.Session(region_name=REGION)
    backup = session.client("backup")
    backup.create_backup_vault(BackupVaultName="primary")
    backup.create_backup_plan(
        BackupPlan={
            "BackupPlanName": "daily",
            "Rules": [
                {
                    "RuleName": "nightly",
                    "TargetBackupVaultName": "primary",
                    "ScheduleExpression": "cron(0 5 * * ? *)",
                    "CopyActions": [
                        {
                            "DestinationBackupVaultArn": "arn:aws:backup:us-west-2:333333333333:backup-vault:dr"
                        }
                    ],
                }
            ],
        }
    )

    collector = _collector(["backup"])
    assets = _run(collector)
    _assert_success(collector, "backup_plans", "backup_vaults")

    plan = _one(assets, AssetType.BACKUP_PLAN)
    vault = _one(assets, AssetType.BACKUP_VAULT)
    linker = RelationshipLinker(assets)
    edges = linker.link()
    assert _edge(edges, plan, vault, EdgeType.REFERENCES, "BACKUP_TO")
    dr = next(a for a in linker.external_assets if a.metadata.get("account_id") == "333333333333")
    assert _edge(edges, plan, dr, EdgeType.REFERENCES, "BACKUP_TO")
    copy = plan.metadata["rules"][0]["copy_actions"][0]
    assert copy["cross_account"] and copy["cross_region"]


def test_backup_selections_policy_and_protected_resources_with_fake_client():
    vault_arn = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:primary"
    table = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"
    backup = _FakeClient(
        {
            "list_backup_plans": {
                "BackupPlansList": [
                    {
                        "BackupPlanId": "p1",
                        "BackupPlanName": "daily",
                        "BackupPlanArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:p1",
                    }
                ]
            },
            "get_backup_plan": {"BackupPlan": {"BackupPlanName": "daily", "Rules": []}},
            "list_backup_selections": {
                "BackupSelectionsList": [
                    {
                        "SelectionId": "s1",
                        "SelectionName": "tables",
                        "IamRoleArn": f"arn:aws:iam::{ACCOUNT}:role/backup",
                    }
                ]
            },
            "get_backup_selection": {
                "BackupSelection": {
                    "SelectionName": "tables",
                    "IamRoleArn": f"arn:aws:iam::{ACCOUNT}:role/backup",
                    "Resources": [table, "arn:aws:ec2:*:*:volume/*"],
                    "ListOfTags": [
                        {
                            "ConditionType": "STRINGEQUALS",
                            "ConditionKey": "backup",
                            "ConditionValue": "yes",
                        }
                    ],
                }
            },
            "list_backup_vaults": {
                "BackupVaultList": [
                    {
                        "BackupVaultName": "primary",
                        "BackupVaultArn": vault_arn,
                        "EncryptionKeyArn": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/k1",
                        "Locked": True,
                    }
                ]
            },
            "get_backup_vault_access_policy": {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::444444444444:root"},
                                "Action": "backup:CopyIntoBackupVault",
                                "Resource": "*",
                            }
                        ]
                    }
                )
            },
            "list_protected_resources": {
                "Results": [
                    {
                        "ResourceArn": table,
                        "ResourceType": "DynamoDB",
                        "LastBackupVaultArn": vault_arn,
                    }
                ]
            },
        }
    )
    collector = _collector(["backup"], {"backup": backup})
    assets = _run(collector)
    _assert_success(collector, "backup_plans", "backup_vaults")
    plan = _one(assets, AssetType.BACKUP_PLAN)
    vault = _one(assets, AssetType.BACKUP_VAULT)
    assert vault.metadata["locked"] and vault.metadata["protected_resources"] == 1
    assert plan.metadata["selections"][0]["tag_conditions"][0]["key"] == "backup"

    orders = _asset("orders", AssetType.DYNAMODB_TABLE, table)
    role = _asset("backup", AssetType.IAM_ROLE, f"arn:aws:iam::{ACCOUNT}:role/backup")
    key = _asset("k1", AssetType.KMS_KEY, f"arn:aws:kms:{REGION}:{ACCOUNT}:key/k1")
    linker = RelationshipLinker(assets + [orders, role, key])
    edges = linker.link()
    assert _edge(edges, plan, orders, EdgeType.MANAGES, "BACKUP_TO")
    assert _edge(edges, plan, role, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, orders, vault, EdgeType.REFERENCES, "BACKUP_TO")
    assert _edge(edges, vault, key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
    other = next(
        a for a in linker.external_assets if a.metadata.get("account_id") == "444444444444"
    )
    assert _edge(edges, other, vault, EdgeType.GRANTS_ACCESS)


# ----------------------------------------------------------------------
# ECS extras and Cloud Map
# ----------------------------------------------------------------------


def test_ecs_capacity_providers_and_container_instances_with_fake_client():
    cluster_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
    asg_arn = (
        f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:u:autoScalingGroupName/ecs-asg"
    )
    ci_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/prod/abc"
    ecs = _FakeClient(
        {
            "describe_capacity_providers": {
                "capacityProviders": [
                    {
                        "capacityProviderArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:capacity-provider/ec2cp",
                        "name": "ec2cp",
                        "status": "ACTIVE",
                        "autoScalingGroupProvider": {
                            "autoScalingGroupArn": asg_arn,
                            "managedScaling": {"status": "ENABLED", "targetCapacity": 90},
                        },
                    },
                    {
                        "capacityProviderArn": "arn:aws:ecs:::capacity-provider/FARGATE",
                        "name": "FARGATE",
                        "status": "ACTIVE",
                    },
                ]
            },
            "list_clusters": {"clusterArns": [cluster_arn]},
            "describe_clusters": {
                "clusters": [
                    {
                        "clusterArn": cluster_arn,
                        "clusterName": "prod",
                        "capacityProviders": ["ec2cp"],
                    }
                ]
            },
            "list_container_instances": {"containerInstanceArns": [ci_arn]},
            "describe_container_instances": {
                "containerInstances": [
                    {
                        "containerInstanceArn": ci_arn,
                        "ec2InstanceId": "i-0123456789abcdef0",
                        "status": "ACTIVE",
                        "agentConnected": True,
                    }
                ]
            },
        }
    )
    collector = _collector(["ecs_capacity_providers", "ecs_container_instances"], {"ecs": ecs})
    assets = _run(collector)
    _assert_success(collector, "ecs_capacity_providers", "ecs_container_instances")

    provider = _one(assets, AssetType.CAPACITY_PROVIDER)
    stub = _one(assets, AssetType.ECS_CLUSTER)
    assert stub.metadata["discovered_via"] == "ecs container instances"
    cluster = _asset("prod", AssetType.ECS_CLUSTER, cluster_arn, {"status": "ACTIVE"})
    asg = _asset("ecs-asg", AssetType.AUTOSCALING_GROUP, asg_arn)
    instance = _asset(
        "node", AssetType.EC2, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
    )
    merged, _ = deduplicate([cluster, *assets, asg, instance], [])
    assert len([a for a in merged if a.arn == cluster_arn]) == 1
    edges = RelationshipLinker(merged).link()
    assert _edge(edges, provider, asg, EdgeType.MANAGES, "SCALES_WITH")
    assert _edge(edges, cluster, provider, EdgeType.REFERENCES, "SCALES_WITH")
    assert _edge(edges, cluster, instance, EdgeType.CONTAINS)


@mock_aws
def test_cloudmap_namespaces_and_services(aws_credentials):
    session = boto3.Session(region_name=REGION)
    sd = session.client("servicediscovery")
    sd.create_private_dns_namespace(Name="internal.local", Vpc="vpc-12345678")
    ns_id = sd.list_namespaces()["Namespaces"][0]["Id"]
    svc_arn = sd.create_service(
        Name="api", NamespaceId=ns_id, DnsConfig={"DnsRecords": [{"Type": "A", "TTL": 60}]}
    )["Service"]["Arn"]

    collector = _collector(["cloudmap"])
    assets = _run(collector)
    _assert_success(collector, "cloudmap")
    ns = _one(assets, AssetType.DNS_ZONE, kind="cloudmap_namespace")
    svc = _by_arn(assets)[svc_arn]
    assert svc.metadata["namespace_id"] == ns_id
    ecs_service = _asset(
        "api",
        AssetType.CONTAINER_SERVICE,
        f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/prod/api",
        {"relations": [{"target": svc_arn, "edge": "REFERENCES", "relationship": "DNS_RESOLVED"}]},
    )
    edges = RelationshipLinker(assets + [ecs_service]).link()
    assert _edge(edges, ns, svc, EdgeType.CONTAINS)
    assert _edge(edges, ecs_service, svc, EdgeType.REFERENCES)


# ----------------------------------------------------------------------
# Lambda aliases
# ----------------------------------------------------------------------


@mock_aws
def test_lambda_aliases(aws_credentials):
    session = boto3.Session(region_name=REGION)
    role = _role(session)
    lam = session.client("lambda")
    fn = lam.create_function(
        FunctionName="worker",
        Runtime="python3.12",
        Role=role,
        Handler="h.h",
        Code={"ZipFile": _lambda_zip()},
    )["FunctionArn"]
    version = lam.publish_version(FunctionName="worker")["Version"]
    lam.create_alias(FunctionName="worker", Name="live", FunctionVersion=version)
    topic = session.client("sns").create_topic(Name="jobs")["TopicArn"]
    lam.add_permission(
        FunctionName="worker",
        Qualifier="live",
        StatementId="sns",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic,
    )

    collector = _collector(["lambda", "lambda_aliases", "sns"])
    assets = _run(collector)
    _assert_success(collector, "lambda_aliases")
    by_arn = _by_arn(assets)
    alias = by_arn[f"{fn}:live"]
    assert alias.asset_type == AssetType.LAMBDA_FUNCTION and alias.metadata["alias"] is True
    assert alias.metadata["function_version"] == version
    edges = RelationshipLinker(assets).link()
    assert _edge(edges, alias, by_arn[fn], EdgeType.REFERENCES, "DEPENDS_ON")
    assert _edge(edges, by_arn[topic], alias, EdgeType.INVOKES)


# ----------------------------------------------------------------------
# EventBridge Scheduler, Pipes, API destinations, archives
# ----------------------------------------------------------------------


@mock_aws
def test_scheduler_pipes_and_api_destinations(aws_credentials):
    session = boto3.Session(region_name=REGION)
    role = _role(session)
    lam = session.client("lambda")
    fn = lam.create_function(
        FunctionName="worker",
        Runtime="python3.12",
        Role=role,
        Handler="h.h",
        Code={"ZipFile": _lambda_zip()},
    )["FunctionArn"]
    sqs = session.client("sqs")
    queue_url = sqs.create_queue(QueueName="jobs")["QueueUrl"]
    queue = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    dlq_url = sqs.create_queue(QueueName="dlq")["QueueUrl"]
    dlq = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    session.client("scheduler").create_schedule(
        Name="nightly",
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": fn, "RoleArn": role, "DeadLetterConfig": {"Arn": dlq}},
    )
    session.client("pipes").create_pipe(Name="jobs-pipe", Source=queue, Target=fn, RoleArn=role)
    events = session.client("events")
    conn = events.create_connection(
        Name="partner",
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "SUPERSECRET-KEY"}
        },
    )["ConnectionArn"]
    events.create_api_destination(
        Name="partner-hook",
        ConnectionArn=conn,
        InvocationEndpoint="https://hooks.example.com/in?token=abc123",
        HttpMethod="POST",
    )
    events.create_archive(
        ArchiveName="all-events",
        EventSourceArn=f"arn:aws:events:{REGION}:{ACCOUNT}:event-bus/default",
    )

    services = [
        "scheduler",
        "pipes",
        "eventbridge_api_destinations",
        "eventbridge_archives",
        "eventbridge",
        "lambda",
        "sqs",
        "iam",
    ]
    collector = _collector(services)
    assets = _run(collector)
    _assert_success(
        collector, "scheduler", "pipes", "eventbridge_api_destinations", "eventbridge_archives"
    )

    by_arn = _by_arn(assets)
    fn_a, queue_a, dlq_a, role_a = by_arn[fn], by_arn[queue], by_arn[dlq], by_arn[role]
    schedule = _one(assets, AssetType.SCHEDULE)
    pipe = _one(assets, AssetType.EVENT_PIPE)
    connection = _one(assets, AssetType.API_DESTINATION, kind="connection")
    dest = _one(assets, AssetType.API_DESTINATION, kind="api_destination")
    archive = _one(assets, AssetType.EVENT_ARCHIVE, kind="event_archive")
    bus = _one(assets, AssetType.EVENT_BUS)

    edges = RelationshipLinker(assets).link()
    assert _edge(edges, schedule, fn_a, EdgeType.INVOKES)
    assert _edge(edges, schedule, role_a, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, schedule, dlq_a, EdgeType.REFERENCES, "WRITES_TO")
    assert _edge(edges, queue_a, pipe, EdgeType.INVOKES, "TRIGGERED_BY")
    assert _edge(edges, pipe, fn_a, EdgeType.INVOKES)
    assert _edge(edges, pipe, role_a, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, dest, connection, EdgeType.REFERENCES)
    assert _edge(edges, archive, bus, EdgeType.REFERENCES, "READS_FROM")
    assert dest.metadata["endpoint_host"] == "hooks.example.com"
    assert connection.metadata["secret_arn"].startswith("arn:aws:secretsmanager:")
    dumped = _dump(assets)
    assert "SUPERSECRET-KEY" not in dumped
    assert "token=abc123" not in dumped


# ----------------------------------------------------------------------
# CloudWatch Logs, OAM, alarms
# ----------------------------------------------------------------------


@mock_aws
def test_log_subscriptions_destinations_and_alarms(aws_credentials):
    session = boto3.Session(region_name=REGION)
    role = _role(session)
    lam = session.client("lambda")
    fn = lam.create_function(
        FunctionName="shipper",
        Runtime="python3.12",
        Role=role,
        Handler="h.h",
        Code={"ZipFile": _lambda_zip()},
    )["FunctionArn"]
    logs = session.client("logs")
    logs.create_log_group(logGroupName="/app/web")
    logs.put_subscription_filter(
        logGroupName="/app/web", filterName="to-shipper", filterPattern="", destinationArn=fn
    )
    logs.put_destination(
        destinationName="central",
        targetArn=f"arn:aws:kinesis:{REGION}:{ACCOUNT}:stream/logs",
        roleArn=role,
    )
    logs.put_destination_policy(
        destinationName="central",
        accessPolicy=json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "222222222222"},
                        "Action": "logs:PutSubscriptionFilter",
                        "Resource": "*",
                    }
                ]
            }
        ),
    )
    topic = session.client("sns").create_topic(Name="oncall")["TopicArn"]
    session.client("cloudwatch").put_metric_alarm(
        AlarmName="worker-errors",
        MetricName="Errors",
        Namespace="AWS/Lambda",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanThreshold",
        Dimensions=[{"Name": "FunctionName", "Value": "shipper"}],
        AlarmActions=[topic],
    )

    services = [
        "log_subscriptions",
        "log_destinations",
        "cloudwatch_alarms",
        "log_groups",
        "lambda",
        "sns",
        "iam",
    ]
    collector = _collector(services)
    assets = _run(collector)
    _assert_success(collector, "log_subscriptions", "log_destinations", "cloudwatch_alarms")

    by_arn = _by_arn(assets)
    group = _one(assets, AssetType.LOG_GROUP)
    sink = _one(assets, AssetType.LOG_SINK, kind="subscription_filter")
    destination = _one(assets, AssetType.LOG_SINK, kind="log_destination")
    alarm = _one(assets, AssetType.ALARM)
    linker = RelationshipLinker(assets)
    edges = linker.link()
    assert _edge(edges, group, sink, EdgeType.INVOKES, "STREAMS_TO")
    assert _edge(edges, sink, by_arn[fn], EdgeType.INVOKES, "STREAMS_TO")
    assert _edge(edges, destination, by_arn[role], EdgeType.ASSUMES_ROLE)
    partner = next(
        a for a in linker.external_assets if a.metadata.get("account_id") == "222222222222"
    )
    assert _edge(edges, partner, destination, EdgeType.GRANTS_ACCESS)
    assert _edge(edges, alarm, by_arn[topic], EdgeType.INVOKES)
    assert _edge(edges, alarm, by_arn[fn], EdgeType.MONITORS)


def test_oam_and_composite_alarms_with_fake_clients():
    sink_arn = f"arn:aws:oam:{REGION}:555555555555:sink/s1"
    oam = _FakeClient(
        {
            "list_sinks": {
                "Items": [
                    {
                        "Arn": f"arn:aws:oam:{REGION}:{ACCOUNT}:sink/mine",
                        "Id": "mine",
                        "Name": "monitoring",
                    }
                ]
            },
            "get_sink_policy": {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": ["666666666666"]},
                                "Action": ["oam:CreateLink"],
                                "Resource": "*",
                            }
                        ]
                    }
                )
            },
            "list_links": {
                "Items": [
                    {
                        "Arn": f"arn:aws:oam:{REGION}:{ACCOUNT}:link/l1",
                        "Id": "l1",
                        "Label": "prod",
                        "ResourceTypes": ["AWS::Logs::LogGroup"],
                        "SinkArn": sink_arn,
                    }
                ]
            },
        }
    )
    asg_policy = f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:scalingPolicy:u:autoScalingGroupName/web-asg:policyName/up"
    cloudwatch = _FakeClient(
        {
            "describe_alarms": {
                "MetricAlarms": [
                    {
                        "AlarmName": "cpu",
                        "AlarmArn": f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:cpu",
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "Dimensions": [{"Name": "AutoScalingGroupName", "Value": "web-asg"}],
                        "AlarmActions": [asg_policy, "arn:aws:automate:us-east-1:ec2:stop"],
                    }
                ],
                "CompositeAlarms": [
                    {
                        "AlarmName": "service-down",
                        "AlarmArn": f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:service-down",
                        "AlarmRule": 'ALARM("cpu") OR ALARM(other)',
                    }
                ],
            }
        }
    )
    collector = _collector(["oam", "cloudwatch_alarms"], {"oam": oam, "cloudwatch": cloudwatch})
    assets = _run(collector)
    _assert_success(collector, "oam", "cloudwatch_alarms")
    link = _one(assets, AssetType.LOG_SINK, kind="oam_link")
    sink = _one(assets, AssetType.LOG_SINK, kind="oam_sink")
    cpu = next(a for a in assets if a.name == "cpu")
    composite = next(a for a in assets if a.name == "service-down")
    assert link.metadata["monitoring_account_id"] == "555555555555"
    assert cpu.metadata["ec2_actions"] == ["stop"]
    asg = _asset(
        "web-asg",
        AssetType.AUTOSCALING_GROUP,
        f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:u:autoScalingGroupName/web-asg",
    )
    linker = RelationshipLinker(assets + [asg])
    edges = linker.link()
    monitoring = next(
        a for a in linker.external_assets if a.metadata.get("account_id") == "555555555555"
    )
    source = next(
        a for a in linker.external_assets if a.metadata.get("account_id") == "666666666666"
    )
    assert _edge(edges, link, monitoring, EdgeType.INVOKES, "STREAMS_TO")
    assert _edge(edges, source, sink, EdgeType.GRANTS_ACCESS)
    assert _edge(edges, cpu, asg, EdgeType.INVOKES, "SCALES_WITH")
    assert _edge(edges, cpu, asg, EdgeType.MONITORS)
    assert _edge(edges, composite, cpu, EdgeType.REFERENCES, "DEPENDS_ON")


# ----------------------------------------------------------------------
# Firehose
# ----------------------------------------------------------------------


@mock_aws
def test_firehose_sources_and_destinations(aws_credentials):
    session = boto3.Session(region_name=REGION)
    role = _role(session)
    session.client("s3").create_bucket(Bucket="lake")
    session.client("kinesis").create_stream(StreamName="clicks", ShardCount=1)
    stream_arn = f"arn:aws:kinesis:{REGION}:{ACCOUNT}:stream/clicks"
    firehose = session.client("firehose")
    firehose.create_delivery_stream(
        DeliveryStreamName="clicks-to-lake",
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": stream_arn, "RoleARN": role},
        ExtendedS3DestinationConfiguration={"RoleARN": role, "BucketARN": "arn:aws:s3:::lake"},
    )
    firehose.create_delivery_stream(
        DeliveryStreamName="to-splunk",
        SplunkDestinationConfiguration={
            "HECEndpoint": "https://splunk.example.com:8088/services/collector",
            "HECEndpointType": "Raw",
            "HECToken": "HEC-SECRET-TOKEN",
            "S3Configuration": {"RoleARN": role, "BucketARN": "arn:aws:s3:::lake"},
        },
    )

    collector = _collector(["firehose", "kinesis", "s3", "iam"])
    assets = _run(collector)
    _assert_success(collector, "firehose")
    by_arn = _by_arn(assets)
    lake_stream = next(a for a in assets if a.name == "clicks-to-lake")
    splunk = next(a for a in assets if a.name == "to-splunk")
    assert lake_stream.asset_type == AssetType.DELIVERY_STREAM
    edges = RelationshipLinker(assets).link()
    assert _edge(edges, by_arn[stream_arn], lake_stream, EdgeType.INVOKES, "TRIGGERED_BY")
    assert _edge(edges, lake_stream, by_arn["arn:aws:s3:::lake"], EdgeType.INVOKES, "STREAMS_TO")
    assert _edge(edges, lake_stream, by_arn[role], EdgeType.ASSUMES_ROLE)
    assert _edge(edges, splunk, by_arn["arn:aws:s3:::lake"], EdgeType.REFERENCES, "BACKUP_TO")
    assert splunk.metadata["destinations"][0]["endpoint_host"] == "splunk.example.com"
    assert "HEC-SECRET-TOKEN" not in _dump(assets)


# ----------------------------------------------------------------------
# Batch
# ----------------------------------------------------------------------


@mock_aws
def test_batch_environments_queues_and_job_definitions(aws_credentials):
    session = boto3.Session(region_name=REGION)
    role = _role(session)
    repo = session.client("ecr").create_repository(repositoryName="worker")["repository"]
    batch = session.client("batch")
    ce = batch.create_compute_environment(
        computeEnvironmentName="batch-ce", type="UNMANAGED", serviceRole=role
    )["computeEnvironmentArn"]
    batch.create_job_queue(
        jobQueueName="batch-jq",
        state="ENABLED",
        priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce}],
    )
    secret = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:db-AbCdEf"
    batch.register_job_definition(
        jobDefinitionName="batch-jd",
        type="container",
        containerProperties={
            "image": repo["repositoryUri"] + ":1",
            "vcpus": 1,
            "memory": 512,
            "jobRoleArn": role,
            "environment": [{"name": "PASSWORD", "value": "plain-batch-secret"}],
            "secrets": [{"name": "DB", "valueFrom": secret + ":password::"}],
        },
    )
    batch.register_job_definition(
        jobDefinitionName="batch-jd",
        type="container",
        containerProperties={
            "image": repo["repositoryUri"] + ":2",
            "vcpus": 1,
            "memory": 512,
            "jobRoleArn": role,
        },
    )

    collector = _collector(["batch", "ecr", "iam"])
    assets = _run(collector)
    _assert_success(collector, "batch")
    env = _one(assets, AssetType.BATCH_ENVIRONMENT)
    queue = _one(assets, AssetType.JOB_QUEUE)
    jd = _one(assets, AssetType.JOB_DEFINITION)
    assert jd.metadata["revision"] == 2 and jd.metadata["active_revisions"] == 2
    by_arn = _by_arn(assets)
    db_secret = _asset("db", AssetType.SECRET, secret)
    edges = RelationshipLinker(assets + [db_secret]).link()
    assert _edge(edges, queue, env, EdgeType.REFERENCES, "RUNS_ON")
    assert _edge(edges, env, by_arn[role], EdgeType.ASSUMES_ROLE)
    assert _edge(edges, jd, by_arn[repo["repositoryArn"]], EdgeType.USES_IMAGE)
    assert _edge(edges, jd, by_arn[role], EdgeType.ASSUMES_ROLE)
    assert "plain-batch-secret" not in _dump(assets)

    # The first revision carries the secret reference; it is not the latest
    # revision, so check the reference helper directly.
    assert collector._secret_or_param_ref(secret + ":password::") == secret
    assert (
        collector._secret_or_param_ref("/app/db")
        == f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/app/db"
    )


# ----------------------------------------------------------------------
# App Runner and Elastic Beanstalk
# ----------------------------------------------------------------------


def test_apprunner_with_fake_client():
    svc_arn = f"arn:aws:apprunner:{REGION}:{ACCOUNT}:service/web/abc"
    connector_arn = f"arn:aws:apprunner:{REGION}:{ACCOUNT}:vpcconnector/vc/1/x"
    image = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/web:prod"
    apprunner = _FakeClient(
        {
            "list_services": {
                "ServiceSummaryList": [{"ServiceArn": svc_arn, "ServiceName": "web"}]
            },
            "list_vpc_connectors": {
                "VpcConnectors": [
                    {
                        "VpcConnectorArn": connector_arn,
                        "VpcConnectorName": "vc",
                        "Subnets": ["subnet-0123456789abcdef0"],
                        "SecurityGroups": ["sg-0123456789abcdef0"],
                    }
                ]
            },
            "describe_service": {
                "Service": {
                    "ServiceArn": svc_arn,
                    "ServiceName": "web",
                    "ServiceId": "abc",
                    "ServiceUrl": "abc.us-east-1.awsapprunner.com",
                    "Status": "RUNNING",
                    "SourceConfiguration": {
                        "ImageRepository": {
                            "ImageIdentifier": image,
                            "ImageRepositoryType": "ECR",
                            "ImageConfiguration": {
                                "RuntimeEnvironmentVariables": {
                                    "API_KEY": "apprunner-plain-secret"
                                },
                                "RuntimeEnvironmentSecrets": {
                                    "DB": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:db-AbCdEf"
                                },
                            },
                        },
                        "AuthenticationConfiguration": {
                            "AccessRoleArn": f"arn:aws:iam::{ACCOUNT}:role/ecr-access"
                        },
                    },
                    "InstanceConfiguration": {
                        "InstanceRoleArn": f"arn:aws:iam::{ACCOUNT}:role/web"
                    },
                    "NetworkConfiguration": {
                        "EgressConfiguration": {
                            "EgressType": "VPC",
                            "VpcConnectorArn": connector_arn,
                        },
                        "IngressConfiguration": {"IsPubliclyAccessible": True},
                    },
                }
            },
        }
    )
    collector = _collector(["apprunner"], {"apprunner": apprunner})
    assets = _run(collector)
    _assert_success(collector, "apprunner")
    svc = _one(assets, AssetType.APP_SERVICE)
    connector = _one(assets, AssetType.VPC_LINK)
    assert svc.is_internet_exposed
    assert svc.metadata["environment_variable_names"] == ["API_KEY"]
    assert "apprunner-plain-secret" not in _dump(assets)
    repo = _asset(
        "web",
        AssetType.CONTAINER_REGISTRY,
        f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/web",
        {"repository_uri": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/web"},
    )
    role = _asset("web", AssetType.IAM_ROLE, f"arn:aws:iam::{ACCOUNT}:role/web")
    subnet = _asset(
        "subnet",
        AssetType.SUBNET,
        f"arn:aws:ec2:{REGION}:{ACCOUNT}:subnet/subnet-0123456789abcdef0",
        {"subnet_id": "subnet-0123456789abcdef0"},
    )
    secret = _asset(
        "db", AssetType.SECRET, f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:db-AbCdEf"
    )
    edges = RelationshipLinker(assets + [repo, role, subnet, secret]).link()
    assert _edge(edges, svc, repo, EdgeType.USES_IMAGE)
    assert _edge(edges, svc, role, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, svc, connector, EdgeType.REFERENCES)
    assert _edge(edges, svc, secret, EdgeType.REFERENCES, "READS_FROM")
    assert _edge(edges, subnet, connector, EdgeType.CONTAINS)
    assert _edge(edges, subnet, svc, EdgeType.CONTAINS)


def test_elasticbeanstalk_with_fake_client():
    eb = _FakeClient(
        {
            "describe_applications": {
                "Applications": [
                    {
                        "ApplicationName": "shop",
                        "ApplicationArn": f"arn:aws:elasticbeanstalk:{REGION}:{ACCOUNT}:application/shop",
                    }
                ]
            },
            "describe_environments": {
                "Environments": [
                    {
                        "EnvironmentName": "shop-prod",
                        "EnvironmentId": "e-abc",
                        "ApplicationName": "shop",
                        "EnvironmentArn": f"arn:aws:elasticbeanstalk:{REGION}:{ACCOUNT}:environment/shop/shop-prod",
                        "SolutionStackName": "64bit Amazon Linux 2023 running Node.js 20",
                        "CNAME": "shop-prod.us-east-1.elasticbeanstalk.com",
                        "Tier": {"Name": "WebServer", "Type": "Standard"},
                        "Status": "Ready",
                        "Health": "Green",
                    }
                ]
            },
            "describe_environment_resources": {
                "EnvironmentResources": {
                    "AutoScalingGroups": [{"Name": "awseb-asg"}],
                    "Instances": [{"Id": "i-0123456789abcdef0"}],
                    "LoadBalancers": [
                        {
                            "Name": f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/awseb/1"
                        }
                    ],
                }
            },
            "describe_configuration_settings": {
                "ConfigurationSettings": [
                    {
                        "OptionSettings": [
                            {
                                "Namespace": "aws:elasticbeanstalk:environment",
                                "OptionName": "ServiceRole",
                                "Value": "aws-elasticbeanstalk-service-role",
                            },
                            {
                                "Namespace": "aws:autoscaling:launchconfiguration",
                                "OptionName": "IamInstanceProfile",
                                "Value": "aws-elasticbeanstalk-ec2-role",
                            },
                            {
                                "Namespace": "aws:autoscaling:launchconfiguration",
                                "OptionName": "SecurityGroups",
                                "Value": "sg-0123456789abcdef0,awseb-sg",
                            },
                            {
                                "Namespace": "aws:ec2:vpc",
                                "OptionName": "ELBScheme",
                                "Value": "public",
                            },
                            {
                                "Namespace": "aws:elasticbeanstalk:application:environment",
                                "OptionName": "DB_PASSWORD",
                                "Value": "eb-plain-secret",
                            },
                        ]
                    }
                ]
            },
        }
    )
    collector = _collector(["elasticbeanstalk"], {"elasticbeanstalk": eb})
    assets = _run(collector)
    _assert_success(collector, "elasticbeanstalk")
    env = _one(assets, AssetType.APP_SERVICE, kind="environment")
    app = _one(assets, AssetType.APP_SERVICE, kind="application")
    assert env.is_internet_exposed
    assert env.metadata["platform"].startswith("64bit Amazon Linux")
    assert env.metadata["environment_variable_names"] == ["DB_PASSWORD"]
    assert env.metadata["security_groups"] == ["sg-0123456789abcdef0"]
    assert "eb-plain-secret" not in _dump(assets)
    asg = _asset(
        "awseb-asg",
        AssetType.AUTOSCALING_GROUP,
        f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:u:autoScalingGroupName/awseb-asg",
    )
    instance = _asset(
        "node", AssetType.EC2, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
    )
    lb = _asset(
        "awseb",
        AssetType.LOAD_BALANCER,
        f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/awseb/1",
    )
    role = _asset(
        "aws-elasticbeanstalk-service-role",
        AssetType.IAM_ROLE,
        f"arn:aws:iam::{ACCOUNT}:role/aws-elasticbeanstalk-service-role",
    )
    profile = _asset(
        "aws-elasticbeanstalk-ec2-role",
        AssetType.INSTANCE_PROFILE,
        f"arn:aws:iam::{ACCOUNT}:instance-profile/aws-elasticbeanstalk-ec2-role",
    )
    edges = RelationshipLinker(assets + [asg, instance, lb, role, profile]).link()
    assert _edge(edges, app, env, EdgeType.CONTAINS)
    for target in (asg, instance, lb):
        assert _edge(edges, env, target, EdgeType.MANAGES)
    assert _edge(edges, env, role, EdgeType.ASSUMES_ROLE)
    assert _edge(edges, env, profile, EdgeType.REFERENCES, "RUNS_ON")


@mock_aws
def test_elasticbeanstalk_tolerates_partial_moto_support(aws_credentials):
    session = boto3.Session(region_name=REGION)
    eb = session.client("elasticbeanstalk")
    eb.create_application(ApplicationName="shop")
    eb.create_environment(
        ApplicationName="shop",
        EnvironmentName="shop-prod",
        SolutionStackName="64bit Amazon Linux 2023 v6.1.0 running Node.js 20",
    )
    collector = _collector(["elasticbeanstalk"])
    assets = _run(collector)
    _assert_success(collector, "elasticbeanstalk")
    assert {a.metadata.get("kind") for a in assets} == {"application", "environment"}


def test_total_failure_is_reported_as_failed():
    collector = _collector(
        ["firehose", "apprunner"], {"firehose": _FakeClient({}), "apprunner": _FakeClient({})}
    )
    assert _run(collector) == []
    status = _status(collector)
    assert status["firehose"] == ServiceStatus.FAILED
    assert status["apprunner"] == ServiceStatus.FAILED


def test_composite_alarm_rule_children_parsing():
    from cloudg.inventory.aws_services.application._common import alarm_rule_children

    rule = 'ALARM("cpu-high") OR ALARM(mem) AND NOT OK( "disk" ) OR INSUFFICIENT_DATA(q)'
    assert alarm_rule_children(rule) == ["cpu-high", "mem", "disk", "q"]
    # Blank and quote-only references produce no child
    assert alarm_rule_children('OK(" ") AND ALARM()') == []
    assert alarm_rule_children("") == []


def test_composite_alarm_rule_parsing_is_linear_on_hostile_rules():
    import time

    from cloudg.inventory.aws_services.application._common import alarm_rule_children

    for hostile in ("INSUFFICIENT_DATA(" + " " * 200_000, "OK(" * 70_000, "(" * 200_000):
        started = time.perf_counter()
        alarm_rule_children(hostile)
        assert time.perf_counter() - started < 2.0
