"""Tests for the data / analytics / messaging / ML collectors
(:mod:`cloudg.inventory.aws_services.data_ml`)."""

from __future__ import annotations

import asyncio
import json

import boto3
import pytest
from moto import mock_aws

from cloudg.coverage import ServiceStatus
from cloudg.inventory.aws_deep import SERVICE_FAMILIES, AWSDeepInventoryCollector
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, EdgeType

ACCOUNT = "123456789012"
REGION = "us-east-1"
EXTERNAL = "999999999999"
TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
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


# ── Helpers ──


class FakeClient:
    """Minimal async stand-in for an aiobotocore client.

    Args:
        pages: operation -> list of pages (or callable(**kwargs) -> pages)
            served through ``get_paginator``.
        calls: operation -> response dict, exception or callable(**kwargs).
    """

    def __init__(self, pages=None, calls=None):
        self._pages = pages or {}
        self._calls = calls or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def get_paginator(self, op):
        data = self._pages[op]

        class _Paginator:
            def paginate(self, **kwargs):
                async def gen():
                    for page in data(**kwargs) if callable(data) else data:
                        yield page

                return gen()

        return _Paginator()

    def __getattr__(self, op):
        if op.startswith("_") or op not in self._calls:
            raise AttributeError(op)
        handler = self._calls[op]

        async def call(**kwargs):
            result = handler(**kwargs) if callable(handler) else handler
            if isinstance(result, Exception):
                raise result
            return result

        return call


def _collector(services, primary=True, fakes=None):
    collector = AWSDeepInventoryCollector(
        session=boto3.Session(region_name=REGION),
        region=REGION,
        account_id=ACCOUNT,
        kubernetes=False,
        tagging_sweep=False,
        is_primary_region=primary,
        services=services,
    )
    if fakes:
        original = collector._client

        def client(service, region=None):
            return fakes[service] if service in fakes else original(service, region)

        collector._client = client
    return collector


def _run(services, fakes=None):
    collector = _collector(services, fakes=fakes)
    assets = asyncio.run(collector.collect())
    edges = RelationshipLinker(assets).link()
    return assets, edges, collector


def _status(collector, name):
    return next(s.status for s in collector.coverage.services if s.service == name)


def _edge(edges, src, dst, edge_type=None, relationship=None):
    return [
        e
        for e in edges
        if e.source_id == src.id
        and e.target_id == dst.id
        and (edge_type is None or e.edge_type == edge_type)
        and (relationship is None or e.relationship == relationship)
    ]


def _one(assets, **match):
    found = [
        a
        for a in assets
        if all(
            (a.metadata.get(k) if k not in ("asset_type", "name", "arn") else getattr(a, k)) == v
            for k, v in match.items()
        )
    ]
    assert len(found) == 1, (match, [a.name for a in found])
    return found[0]


def _network(session):
    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a")[
        "Subnet"
    ]["SubnetId"]
    subnet2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b")[
        "Subnet"
    ]["SubnetId"]
    sg = ec2.create_security_group(GroupName="data", Description="data", VpcId=vpc)["GroupId"]
    return vpc, subnet, subnet2, sg


def _role(session, name="svc"):
    return session.client("iam").create_role(RoleName=name, AssumeRolePolicyDocument=TRUST)["Role"][
        "Arn"
    ]


# ── Registration ──


class TestRegistration:
    def test_tasks_families_and_globals(self):
        collector = _collector(["all"])
        tasks = collector._data_ml_tasks()
        assert tasks["msk"][1:] == ("integration", False)
        assert tasks["sagemaker"][1:] == ("ml", False)
        assert tasks["glue"][1:] == ("analytics", False)
        assert tasks["rds_global_clusters"][1:] == ("data", True)
        assert tasks["ecr_public"][1:] == ("containers", True)
        selected = collector._service_tasks()
        assert set(tasks) <= set(selected)
        assert SERVICE_FAMILIES["bedrock"] == "ml"

    def test_global_tasks_only_in_primary_region(self):
        selected = _collector(["all"], primary=False)._service_tasks()
        assert "rds_global_clusters" not in selected
        assert "ecr_public" not in selected
        assert "rds_proxies" in selected

    def test_family_filter(self):
        selected = _collector(["ml"])._service_tasks()
        assert set(selected) == {"sagemaker", "bedrock"}


# ── moto-backed collectors ──


@mock_aws
class TestMessaging:
    def test_msk_and_mq(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        _, subnet, subnet2, sg = _network(session)
        kafka = session.client("kafka")
        cluster = kafka.create_cluster_v2(
            ClusterName="events",
            Provisioned={
                "BrokerNodeGroupInfo": {
                    "ClientSubnets": [subnet, subnet2],
                    "InstanceType": "kafka.m5.large",
                    "SecurityGroups": [sg],
                    "ConnectivityInfo": {"PublicAccess": {"Type": "SERVICE_PROVIDED_EIPS"}},
                },
                "KafkaVersion": "3.5.1",
                "NumberOfBrokerNodes": 2,
            },
        )["ClusterArn"]
        kafka.put_cluster_policy(
            ClusterArn=cluster,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL}:root"},
                            "Action": "kafka:CreateVpcConnection",
                            "Resource": cluster,
                        }
                    ],
                }
            ),
        )
        mq = session.client("mq")
        mq.create_broker(
            BrokerName="orders",
            DeploymentMode="SINGLE_INSTANCE",
            EngineType="ACTIVEMQ",
            EngineVersion="5.17.6",
            HostInstanceType="mq.t3.micro",
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            SubnetIds=[subnet],
            SecurityGroups=[sg],
            Users=[{"Username": "admin", "Password": "Sup3rS3cretPassw0rd"}],
            Logs={"General": True},
        )

        assets, edges, collector = _run(["msk", "amazon_mq", "subnets", "security_groups"])
        assert _status(collector, "msk") == ServiceStatus.SUCCESS
        assert _status(collector, "amazon_mq") == ServiceStatus.SUCCESS
        msk = _one(assets, asset_type=AssetType.MESSAGE_BROKER, service="msk")
        broker = _one(assets, asset_type=AssetType.MESSAGE_BROKER, service="amazon-mq")
        sn = _one(assets, asset_type=AssetType.SUBNET, subnet_id=subnet)
        sg_asset = _one(assets, asset_type=AssetType.SECURITY_GROUP, group_id=sg)

        assert msk.is_internet_exposed and broker.is_internet_exposed
        assert _edge(edges, sn, msk, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        assert _edge(edges, msk, sg_asset, EdgeType.ATTACHED_TO)
        assert _edge(edges, sn, broker, EdgeType.CONTAINS)
        assert _edge(edges, broker, sg_asset, EdgeType.ATTACHED_TO)
        grant = [
            e for e in edges if e.target_id == msk.id and e.edge_type == EdgeType.GRANTS_ACCESS
        ]
        assert (
            grant
            and grant[0].properties.get("external_reference") == f"arn:aws:iam::{EXTERNAL}:root"
        )
        assert "Sup3rS3cretPassw0rd" not in json.dumps(broker.model_dump(mode="json"))


@mock_aws
class TestSageMaker:
    def test_models_endpoints_notebooks_domains(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        vpc, subnet, _, sg = _network(session)
        role = _role(session)
        repo = session.client("ecr").create_repository(repositoryName="inference")["repository"]
        session.client("s3").create_bucket(Bucket="models")
        sm = session.client("sagemaker")
        sm.create_model(
            ModelName="ranker",
            ExecutionRoleArn=role,
            PrimaryContainer={
                "Image": repo["repositoryUri"] + ":v3",
                "ModelDataUrl": "s3://models/ranker/model.tar.gz",
                "Environment": {"API_TOKEN": "tok-should-not-leak"},
            },
            VpcConfig={"SecurityGroupIds": [sg], "Subnets": [subnet]},
        )
        sm.create_endpoint_config(
            EndpointConfigName="ranker-cfg",
            ProductionVariants=[
                {
                    "VariantName": "main",
                    "ModelName": "ranker",
                    "InitialInstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                }
            ],
        )
        sm.create_endpoint(EndpointName="ranker", EndpointConfigName="ranker-cfg")
        sm.create_notebook_instance(
            NotebookInstanceName="research",
            InstanceType="ml.t3.medium",
            RoleArn=role,
            SubnetId=subnet,
            SecurityGroupIds=[sg],
            DirectInternetAccess="Enabled",
        )
        sm.create_domain(
            DomainName="studio",
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role},
            SubnetIds=[subnet],
            VpcId=vpc,
            AppNetworkAccessType="PublicInternetOnly",
        )

        assets, edges, collector = _run(
            ["sagemaker", "subnets", "security_groups", "iam", "secretsmanager", "ecr", "s3"]
        )
        assert _status(collector, "sagemaker") == ServiceStatus.SUCCESS
        model = _one(assets, asset_type=AssetType.ML_MODEL)
        endpoint = _one(assets, asset_type=AssetType.ML_ENDPOINT)
        notebook = _one(assets, asset_type=AssetType.ML_WORKSPACE, kind="notebook_instance")
        domain = _one(assets, asset_type=AssetType.ML_WORKSPACE, kind="domain")
        role_asset = _one(assets, arn=role)
        repo_asset = _one(assets, arn=repo["repositoryArn"])
        bucket = _one(assets, arn="arn:aws:s3:::models")
        sn = _one(assets, asset_type=AssetType.SUBNET, subnet_id=subnet)

        assert _edge(edges, model, repo_asset, EdgeType.USES_IMAGE)
        assert _edge(edges, model, role_asset, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, model, bucket, EdgeType.REFERENCES, "READS_FROM")
        assert _edge(edges, sn, model, EdgeType.CONTAINS)
        assert _edge(edges, endpoint, model, EdgeType.REFERENCES)
        assert _edge(edges, notebook, role_asset, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, sn, notebook, EdgeType.CONTAINS)
        assert notebook.is_internet_exposed
        assert _edge(edges, domain, role_asset, EdgeType.ASSUMES_ROLE)
        assert domain.is_internet_exposed
        assert "tok-should-not-leak" not in json.dumps(model.model_dump(mode="json"))


@mock_aws
class TestGlueAndLakeFormation:
    def test_catalog_jobs_crawlers_connections_triggers(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        _, subnet, _, sg = _network(session)
        role = _role(session, "glue")
        s3 = session.client("s3")
        for bucket in ("lake", "scripts", "raw"):
            s3.create_bucket(Bucket=bucket)
        glue = session.client("glue")
        glue.create_database(DatabaseInput={"Name": "sales", "LocationUri": "s3://lake/sales"})
        for t in ("orders", "customers"):
            glue.create_table(DatabaseName="sales", TableInput={"Name": t})
        glue.create_connection(
            ConnectionInput={
                "Name": "warehouse",
                "ConnectionType": "JDBC",
                "ConnectionProperties": {
                    "JDBC_CONNECTION_URL": "jdbc:postgresql://db.internal.example:5432/sales",
                    "USERNAME": "etl",
                    "PASSWORD": "hunter2-glue",
                },
                "PhysicalConnectionRequirements": {"SubnetId": subnet, "SecurityGroupIdList": [sg]},
            }
        )
        glue.create_job(
            Name="nightly",
            Role=role,
            Command={"Name": "glueetl", "ScriptLocation": "s3://scripts/nightly.py"},
            Connections={"Connections": ["warehouse"]},
            DefaultArguments={"--TempDir": "s3://raw/tmp/", "--db-password": "arg-secret-value"},
        )
        glue.create_crawler(
            Name="discover",
            Role=role,
            DatabaseName="sales",
            Targets={
                "S3Targets": [{"Path": "s3://raw/landing/"}],
                "DynamoDBTargets": [{"Path": "orders"}],
            },
        )
        glue.create_trigger(Name="after-crawl", Type="ON_DEMAND", Actions=[{"JobName": "nightly"}])
        lf = session.client("lakeformation")
        lf.put_data_lake_settings(
            DataLakeSettings={"DataLakeAdmins": [{"DataLakePrincipalIdentifier": role}]}
        )
        lf.grant_permissions(
            Principal={"DataLakePrincipalIdentifier": f"arn:aws:iam::{EXTERNAL}:role/analyst"},
            Resource={"Database": {"Name": "sales"}},
            Permissions=["DESCRIBE"],
        )

        assets, edges, collector = _run(
            ["glue", "lakeformation", "subnets", "security_groups", "iam", "secretsmanager", "s3"]
        )
        assert _status(collector, "glue") == ServiceStatus.SUCCESS
        assert _status(collector, "lakeformation") == ServiceStatus.SUCCESS
        catalog = _one(assets, asset_type=AssetType.DATA_CATALOG, kind="catalog")
        db = _one(assets, asset_type=AssetType.DATA_CATALOG, kind="database")
        conn = _one(assets, asset_type=AssetType.DATA_CATALOG, kind="connection")
        lake = _one(assets, asset_type=AssetType.DATA_CATALOG, kind="data_lake_settings")
        job = _one(assets, asset_type=AssetType.ETL_JOB, kind="job")
        crawler = _one(assets, asset_type=AssetType.ETL_JOB, kind="crawler")
        trigger = _one(assets, asset_type=AssetType.EVENT_RULE, kind="trigger")
        role_asset = _one(assets, arn=role)
        sn = _one(assets, asset_type=AssetType.SUBNET, subnet_id=subnet)
        sg_asset = _one(assets, asset_type=AssetType.SECURITY_GROUP, group_id=sg)

        def bucket(name):
            return _one(assets, arn=f"arn:aws:s3:::{name}")

        assert db.metadata["table_count"] == 2
        assert _edge(edges, catalog, db, EdgeType.CONTAINS)
        assert _edge(edges, job, role_asset, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, job, bucket("scripts"), EdgeType.REFERENCES, "READS_FROM")
        assert _edge(edges, job, bucket("raw"), EdgeType.REFERENCES, "WRITES_TO")
        assert _edge(edges, job, conn, EdgeType.REFERENCES)
        assert _edge(edges, crawler, bucket("raw"), EdgeType.REFERENCES, "READS_FROM")
        assert {
            "target": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders",
            "edge": "REFERENCES",
            "relationship": "READS_FROM",
            "properties": {"source_type": "dynamodb"},
        } in crawler.metadata["relations"]
        assert _edge(edges, crawler, db, EdgeType.REFERENCES, "WRITES_TO")
        assert _edge(edges, trigger, job, EdgeType.INVOKES)
        assert _edge(edges, sn, conn, EdgeType.CONTAINS)
        assert _edge(edges, conn, sg_asset, EdgeType.ATTACHED_TO)
        assert conn.metadata["hosts"] == ["db.internal.example"]
        assert _edge(edges, role_asset, lake, EdgeType.GRANTS_ACCESS)
        assert _edge(edges, lake, catalog, EdgeType.GOVERNS)
        external = [
            e for e in edges if e.target_id == db.id and e.edge_type == EdgeType.GRANTS_ACCESS
        ]
        assert external and external[0].properties["permissions"] == ["DESCRIBE"]

        dumped = json.dumps([a.model_dump(mode="json") for a in (conn, job)])
        assert "hunter2-glue" not in dumped and "arg-secret-value" not in dumped


@mock_aws
class TestDataStoresAndAnalytics:
    def test_rds_proxy_global_cluster_emr_athena(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        _, subnet, subnet2, sg = _network(session)
        role = _role(session, "proxy")
        secret = session.client("secretsmanager").create_secret(Name="db-creds", SecretString="x")[
            "ARN"
        ]
        rds = session.client("rds")
        rds.create_db_instance(
            DBInstanceIdentifier="orders-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
        )
        rds.create_db_proxy(
            DBProxyName="orders-proxy",
            EngineFamily="POSTGRESQL",
            RoleArn=role,
            Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret, "IAMAuth": "DISABLED"}],
            VpcSubnetIds=[subnet, subnet2],
            VpcSecurityGroupIds=[sg],
        )
        rds.register_db_proxy_targets(
            DBProxyName="orders-proxy", DBInstanceIdentifiers=["orders-db"]
        )
        rds.create_global_cluster(
            GlobalClusterIdentifier="global-orders", Engine="aurora-postgresql"
        )
        rds.create_db_cluster(
            DBClusterIdentifier="primary",
            Engine="aurora-postgresql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            GlobalClusterIdentifier="global-orders",
        )
        session.client("s3").create_bucket(Bucket="emr-logs")
        session.client("s3").create_bucket(Bucket="athena-results")
        emr = session.client("emr")
        emr.run_job_flow(
            Name="spark",
            ReleaseLabel="emr-6.15.0",
            LogUri="s3://emr-logs/spark/",
            Instances={
                "MasterInstanceType": "m5.xlarge",
                "SlaveInstanceType": "m5.xlarge",
                "InstanceCount": 3,
                "KeepJobFlowAliveWhenNoSteps": True,
                "Ec2SubnetId": subnet,
                "EmrManagedMasterSecurityGroup": sg,
            },
            JobFlowRole="EMR_EC2_DefaultRole",
            ServiceRole="proxy",
            VisibleToAllUsers=True,
        )
        session.client("athena").create_work_group(
            Name="analysts",
            Configuration={
                "ResultConfiguration": {"OutputLocation": "s3://athena-results/q/"},
                "EnforceWorkGroupConfiguration": True,
            },
        )

        assets, edges, collector = _run(
            [
                "rds_proxies",
                "rds_global_clusters",
                "emr",
                "athena",
                "rds",
                "subnets",
                "security_groups",
                "iam",
                "secretsmanager",
                "s3",
            ]
        )
        for task in ("rds_proxies", "rds_global_clusters", "emr", "athena"):
            assert _status(collector, task) == ServiceStatus.SUCCESS, task
        proxy = _one(assets, asset_type=AssetType.DATABASE_PROXY)
        db = _one(assets, asset_type=AssetType.RDS_INSTANCE)
        secret_asset = _one(assets, arn=secret)
        role_asset = _one(assets, arn=role)
        sn = _one(assets, asset_type=AssetType.SUBNET, subnet_id=subnet)
        sg_asset = _one(assets, asset_type=AssetType.SECURITY_GROUP, group_id=sg)
        assert _edge(edges, proxy, db, EdgeType.LOAD_BALANCER_TARGET)
        assert _edge(edges, proxy, secret_asset, EdgeType.REFERENCES, "READS_FROM")
        assert _edge(edges, proxy, role_asset, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, sn, proxy, EdgeType.CONTAINS)
        assert _edge(edges, proxy, sg_asset, EdgeType.ATTACHED_TO)

        glob = _one(assets, asset_type=AssetType.AURORA_CLUSTER, kind="global_cluster")
        member = _one(assets, asset_type=AssetType.AURORA_CLUSTER, name="primary")
        assert glob.region == "global"
        assert _edge(edges, glob, member, EdgeType.CONTAINS)

        cluster = _one(assets, asset_type=AssetType.BIG_DATA_CLUSTER)
        assert _edge(edges, cluster, role_asset, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, cluster, _one(assets, arn="arn:aws:s3:::emr-logs"), EdgeType.LOGS_TO)
        assert _edge(edges, sn, cluster, EdgeType.CONTAINS)
        assert _edge(edges, cluster, sg_asset, EdgeType.ATTACHED_TO)

        wg = _one(assets, asset_type=AssetType.QUERY_WORKGROUP, name="analysts")
        assert wg.metadata["enforce_workgroup_configuration"] is True
        assert _edge(
            edges,
            wg,
            _one(assets, arn="arn:aws:s3:::athena-results"),
            EdgeType.REFERENCES,
            "WRITES_TO",
        )

    def test_memorydb_dax_fsx(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        _, subnet, subnet2, sg = _network(session)
        role = _role(session, "dax")
        mdb = session.client("memorydb")
        mdb.create_subnet_group(SubnetGroupName="cache", SubnetIds=[subnet, subnet2])
        mdb.create_cluster(
            ClusterName="sessions",
            NodeType="db.t4g.small",
            ACLName="open-access",
            SubnetGroupName="cache",
            SecurityGroupIds=[sg],
        )
        session.client("dax").create_cluster(
            ClusterName="accel", NodeType="dax.t3.small", ReplicationFactor=1, IamRoleArn=role
        )
        fs = session.client("fsx").create_file_system(
            FileSystemType="LUSTRE",
            StorageCapacity=1200,
            SubnetIds=[subnet],
            LustreConfiguration={"DeploymentType": "SCRATCH_2"},
        )["FileSystem"]

        assets, edges, collector = _run(
            ["memorydb", "dax", "fsx", "subnets", "security_groups", "iam", "secretsmanager"]
        )
        for task in ("memorydb", "dax", "fsx"):
            assert _status(collector, task) == ServiceStatus.SUCCESS, task
        sn = _one(assets, asset_type=AssetType.SUBNET, subnet_id=subnet)
        sg_asset = _one(assets, asset_type=AssetType.SECURITY_GROUP, group_id=sg)
        memorydb = _one(assets, asset_type=AssetType.CACHE_CLUSTER, service="memorydb")
        dax = _one(assets, asset_type=AssetType.CACHE_CLUSTER, service="dax")
        fsx = _one(assets, asset_type=AssetType.FILE_SYSTEM, service="fsx")
        assert _edge(edges, sn, memorydb, EdgeType.CONTAINS)
        assert _edge(edges, memorydb, sg_asset, EdgeType.ATTACHED_TO)
        assert _edge(edges, dax, _one(assets, arn=role), EdgeType.ASSUMES_ROLE)
        assert _edge(edges, sn, fsx, EdgeType.CONTAINS)
        assert fsx.metadata["file_system_id"] == fs["FileSystemId"]


@mock_aws
class TestDataMovement:
    def test_datasync_tasks_and_locations(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        role = _role(session, "datasync")
        session.client("s3").create_bucket(Bucket="archive")
        ds = session.client("datasync")
        src = ds.create_location_smb(
            ServerHostname="files.corp.example",
            Subdirectory="/share",
            User="svc",
            Password="smb-password-value",
            AgentArns=["arn:aws:datasync:us-east-1:123456789012:agent/agent-0123456789abcdef0"],
        )
        dst = ds.create_location_s3(
            S3BucketArn="arn:aws:s3:::archive",
            Subdirectory="/in",
            S3Config={"BucketAccessRoleArn": role},
        )
        task = ds.create_task(
            SourceLocationArn=src["LocationArn"],
            DestinationLocationArn=dst["LocationArn"],
            Name="nightly-copy",
        )["TaskArn"]

        assets, edges, collector = _run(["datasync", "iam", "secretsmanager", "s3"])
        assert _status(collector, "datasync") == ServiceStatus.SUCCESS
        task_asset = _one(assets, arn=task)
        src_asset = _one(assets, arn=src["LocationArn"])
        dst_asset = _one(assets, arn=dst["LocationArn"])
        bucket = _one(assets, arn="arn:aws:s3:::archive")
        assert _edge(edges, task_asset, src_asset, EdgeType.REFERENCES, "READS_FROM")
        assert _edge(edges, task_asset, dst_asset, EdgeType.REFERENCES, "WRITES_TO")
        assert _edge(edges, task_asset, bucket, EdgeType.REFERENCES, "WRITES_TO")
        assert _edge(edges, dst_asset, bucket, EdgeType.REFERENCES)
        assert _edge(edges, dst_asset, _one(assets, arn=role), EdgeType.ASSUMES_ROLE)
        assert src_asset.metadata["host"] == "files.corp.example"
        assert "smb-password-value" not in json.dumps([a.model_dump(mode="json") for a in assets])


# ── Fake-client collectors (no / partial moto support) ──


@mock_aws
class TestFakeClients:
    def test_transfer_family(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        role = _role(session, "sftp")
        session.client("s3").create_bucket(Bucket="partner-drop")
        fn = "arn:aws:lambda:us-east-1:123456789012:function:idp"
        server_arn = f"arn:aws:transfer:{REGION}:{ACCOUNT}:server/s-0123456789abcdef0"
        transfer = FakeClient(
            pages={
                "list_servers": [
                    {"Servers": [{"Arn": server_arn, "ServerId": "s-0123456789abcdef0"}]}
                ],
                "list_users": [
                    {
                        "Users": [
                            {
                                "UserName": "acme",
                                "Arn": server_arn.replace("server", "user") + "/acme",
                            }
                        ]
                    }
                ],
            },
            calls={
                "describe_server": {
                    "Server": {
                        "Arn": server_arn,
                        "ServerId": "s-0123456789abcdef0",
                        "EndpointType": "PUBLIC",
                        "IdentityProviderType": "AWS_LAMBDA",
                        "IdentityProviderDetails": {"Function": fn},
                        "LoggingRole": role,
                        "Domain": "S3",
                        "Protocols": ["SFTP"],
                    }
                },
                "describe_user": {
                    "User": {
                        "UserName": "acme",
                        "Role": role,
                        "HomeDirectory": "/partner-drop/acme",
                        "SshPublicKeys": [
                            {"SshPublicKeyBody": "ssh-ed25519 AAAA", "SshPublicKeyId": "key-1"}
                        ],
                    }
                },
            },
        )
        assets, edges, collector = _run(
            ["transfer_family", "iam", "secretsmanager", "s3"], {"transfer": transfer}
        )
        assert _status(collector, "transfer_family") == ServiceStatus.SUCCESS
        server = _one(assets, asset_type=AssetType.DATA_TRANSFER, kind="server")
        user = _one(assets, asset_type=AssetType.IDENTITY_USER, service="transfer")
        role_asset = _one(assets, arn=role)
        assert server.is_internet_exposed
        assert _edge(edges, server, role_asset, EdgeType.ASSUMES_ROLE)
        assert {
            "target": fn,
            "edge": "INVOKES",
            "relationship": "INVOKES",
            "description": "custom identity provider",
        } in server.metadata["relations"]
        assert _edge(edges, server, user, EdgeType.CONTAINS)
        assert _edge(edges, user, role_asset, EdgeType.ASSUMES_ROLE)
        assert _edge(
            edges,
            user,
            _one(assets, arn="arn:aws:s3:::partner-drop"),
            EdgeType.REFERENCES,
            "READS_FROM",
        )

    def test_bedrock(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        role = _role(session, "agent")
        session.client("s3").create_bucket(Bucket="kb-docs")
        session.client("s3").create_bucket(Bucket="invocation-logs")
        lam = "arn:aws:lambda:us-east-1:123456789012:function:orders-api"
        kb_arn = f"arn:aws:bedrock:{REGION}:{ACCOUNT}:knowledge-base/KB12345678"
        guard_arn = f"arn:aws:bedrock:{REGION}:{ACCOUNT}:guardrail/gr0123456789"
        collection = f"arn:aws:aoss:{REGION}:{ACCOUNT}:collection/abcdefghij0123456789"
        agent = FakeClient(
            pages={
                "list_agents": [
                    {"agentSummaries": [{"agentId": "AGENT00001", "agentName": "support"}]}
                ],
                "list_agent_action_groups": [{"actionGroupSummaries": [{"actionGroupId": "AG1"}]}],
                "list_agent_knowledge_bases": [
                    {"agentKnowledgeBaseSummaries": [{"knowledgeBaseId": "KB12345678"}]}
                ],
                "list_knowledge_bases": [
                    {"knowledgeBaseSummaries": [{"knowledgeBaseId": "KB12345678"}]}
                ],
                "list_data_sources": [
                    {
                        "dataSourceSummaries": [
                            {"dataSourceId": "DS1", "knowledgeBaseId": "KB12345678"}
                        ]
                    }
                ],
            },
            calls={
                "get_agent": {
                    "agent": {
                        "agentId": "AGENT00001",
                        "agentName": "support",
                        "agentArn": f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/AGENT00001",
                        "agentResourceRoleArn": role,
                        "foundationModel": "anthropic.claude-3-haiku",
                        "guardrailConfiguration": {
                            "guardrailIdentifier": "gr0123456789",
                            "guardrailVersion": "1",
                        },
                    }
                },
                "get_agent_action_group": {
                    "agentActionGroup": {
                        "actionGroupName": "orders",
                        "actionGroupExecutor": {"lambda": lam},
                    }
                },
                "get_knowledge_base": {
                    "knowledgeBase": {
                        "knowledgeBaseId": "KB12345678",
                        "name": "docs",
                        "knowledgeBaseArn": kb_arn,
                        "roleArn": role,
                        "storageConfiguration": {
                            "type": "OPENSEARCH_SERVERLESS",
                            "opensearchServerlessConfiguration": {"collectionArn": collection},
                        },
                    }
                },
                "get_data_source": {
                    "dataSource": {
                        "name": "docs-bucket",
                        "dataSourceConfiguration": {
                            "type": "S3",
                            "s3Configuration": {"bucketArn": "arn:aws:s3:::kb-docs"},
                        },
                    }
                },
            },
        )
        bedrock = FakeClient(
            pages={
                "list_guardrails": [
                    {
                        "guardrails": [
                            {
                                "id": "gr0123456789",
                                "arn": guard_arn,
                                "name": "pii",
                                "status": "READY",
                                "version": "DRAFT",
                            }
                        ]
                    }
                ]
            },
            calls={
                "get_guardrail": {
                    "guardrailArn": guard_arn,
                    "sensitiveInformationPolicy": {"piiEntities": []},
                },
                "get_model_invocation_logging_configuration": {
                    "loggingConfig": {
                        "s3Config": {"bucketName": "invocation-logs"},
                        "textDataDeliveryEnabled": True,
                    }
                },
            },
        )
        aoss = FakeClient(
            calls={
                "list_collections": {
                    "collectionSummaries": [
                        {"id": "abcdefghij0123456789", "name": "vectors", "arn": collection}
                    ]
                },
                "batch_get_collection": {
                    "collectionDetails": [
                        {
                            "id": "abcdefghij0123456789",
                            "name": "vectors",
                            "arn": collection,
                            "kmsKeyArn": "auto",
                        }
                    ]
                },
                "list_security_policies": lambda type, **kw: {
                    "securityPolicySummaries": [{"name": f"{type}-p"}]
                },
                "get_security_policy": lambda type, name: {
                    "securityPolicyDetail": {
                        "policy": (
                            [
                                {
                                    "Rules": [
                                        {
                                            "ResourceType": "collection",
                                            "Resource": ["collection/vec*"],
                                        }
                                    ],
                                    "AllowFromPublic": True,
                                }
                            ]
                            if type == "network"
                            else {
                                "Rules": [
                                    {
                                        "ResourceType": "collection",
                                        "Resource": ["collection/vectors"],
                                    }
                                ],
                                "AWSOwnedKey": True,
                            }
                        )
                    }
                },
                "list_access_policies": {"accessPolicySummaries": [{"name": "kb-access"}]},
                "get_access_policy": {
                    "accessPolicyDetail": {
                        "policy": [
                            {
                                "Rules": [
                                    {
                                        "ResourceType": "index",
                                        "Resource": ["index/vectors/*"],
                                        "Permission": ["aoss:ReadDocument"],
                                    }
                                ],
                                "Principal": [role],
                            }
                        ]
                    }
                },
            }
        )
        assets, edges, collector = _run(
            ["bedrock", "opensearch_serverless", "iam", "secretsmanager", "s3"],
            {"bedrock-agent": agent, "bedrock": bedrock, "opensearchserverless": aoss},
        )
        assert _status(collector, "bedrock") == ServiceStatus.SUCCESS
        assert _status(collector, "opensearch_serverless") == ServiceStatus.SUCCESS
        agent_asset = _one(assets, asset_type=AssetType.AI_AGENT)
        kb = _one(assets, asset_type=AssetType.KNOWLEDGE_BASE)
        guard = _one(assets, asset_type=AssetType.AI_GUARDRAIL)
        sink = _one(assets, asset_type=AssetType.LOG_SINK)
        coll = _one(assets, asset_type=AssetType.SEARCH_DOMAIN)
        role_asset = _one(assets, arn=role)
        assert _edge(edges, agent_asset, role_asset, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, agent_asset, kb, EdgeType.REFERENCES, "READS_FROM")
        assert _edge(edges, guard, agent_asset, EdgeType.PROTECTS)
        assert agent_asset.metadata["action_group_lambdas"] == [lam]
        assert _edge(edges, kb, coll, EdgeType.REFERENCES, "READS_FROM")
        assert _edge(
            edges, kb, _one(assets, arn="arn:aws:s3:::kb-docs"), EdgeType.REFERENCES, "READS_FROM"
        )
        assert _edge(
            edges, sink, _one(assets, arn="arn:aws:s3:::invocation-logs"), EdgeType.LOGS_TO
        )
        assert coll.is_internet_exposed and coll.metadata["aws_owned_key"] is True
        assert _edge(edges, role_asset, coll, EdgeType.GRANTS_ACCESS)

    def test_redshift_serverless_and_ecr_public(self, aws_credentials):
        session = boto3.Session(region_name=REGION)
        _, subnet, _, sg = _network(session)
        role = _role(session, "redshift")
        rs = FakeClient(
            pages={
                "list_namespaces": [
                    {
                        "namespaces": [
                            {
                                "namespaceName": "analytics",
                                "namespaceId": "11111111-2222-3333-4444-555555555555",
                                "namespaceArn": f"arn:aws:redshift-serverless:{REGION}:{ACCOUNT}:namespace/11111111-2222-3333-4444-555555555555",
                                "iamRoles": [f"IamRole(applyStatus=in-sync, iamRoleArn={role})"],
                                "kmsKeyId": "AWS_OWNED_KMS_KEY",
                            }
                        ]
                    }
                ],
                "list_workgroups": [
                    {
                        "workgroups": [
                            {
                                "workgroupName": "bi",
                                "workgroupId": "wg-1",
                                "namespaceName": "analytics",
                                "workgroupArn": f"arn:aws:redshift-serverless:{REGION}:{ACCOUNT}:workgroup/wg-1",
                                "subnetIds": [subnet],
                                "securityGroupIds": [sg],
                                "publiclyAccessible": True,
                                "endpoint": {
                                    "address": "bi.123456789012.us-east-1.redshift-serverless.amazonaws.com"
                                },
                            }
                        ]
                    }
                ],
            }
        )
        ecr_public = FakeClient(
            pages={
                "describe_repositories": [
                    {
                        "repositories": [
                            {
                                "repositoryArn": f"arn:aws:ecr-public::{ACCOUNT}:repository/tools",
                                "repositoryName": "tools",
                                "registryId": ACCOUNT,
                                "repositoryUri": "public.ecr.aws/acme/tools",
                            }
                        ]
                    }
                ]
            }
        )
        assets, edges, collector = _run(
            [
                "redshift_serverless",
                "ecr_public",
                "subnets",
                "security_groups",
                "iam",
                "secretsmanager",
            ],
            {"redshift-serverless": rs, "ecr-public": ecr_public},
        )
        assert _status(collector, "redshift_serverless") == ServiceStatus.SUCCESS
        ns = _one(assets, asset_type=AssetType.DATA_WAREHOUSE, kind="namespace")
        wg = _one(assets, asset_type=AssetType.DATA_WAREHOUSE, kind="workgroup")
        assert ns.metadata["kms_key_id"] is None
        assert _edge(edges, ns, _one(assets, arn=role), EdgeType.ASSUMES_ROLE)
        assert _edge(edges, wg, ns, EdgeType.REFERENCES)
        assert _edge(
            edges,
            _one(assets, asset_type=AssetType.SUBNET, subnet_id=subnet),
            wg,
            EdgeType.CONTAINS,
        )
        assert _edge(
            edges,
            wg,
            _one(assets, asset_type=AssetType.SECURITY_GROUP, group_id=sg),
            EdgeType.ATTACHED_TO,
        )
        assert wg.is_internet_exposed

        repo = _one(assets, asset_type=AssetType.CONTAINER_REGISTRY, service="ecr-public")
        assert (
            repo.is_internet_exposed and repo.metadata["public"] is True and repo.region == "global"
        )
        resolved = RelationshipLinker(assets).resolve("public.ecr.aws/acme/tools:latest")
        assert resolved == repo.id

    def test_partial_failure_is_tolerated_total_failure_is_reported(self, aws_credentials):
        boom = RuntimeError("AccessDenied")
        ok_agent = FakeClient(
            pages={
                "list_agents": [{"agentSummaries": []}],
                "list_knowledge_bases": [{"knowledgeBaseSummaries": []}],
            }
        )
        broken = FakeClient(
            pages={"list_guardrails": lambda **kw: (_ for _ in ()).throw(boom)},
            calls={"get_model_invocation_logging_configuration": boom},
        )
        _, _, collector = _run(["bedrock"], {"bedrock-agent": ok_agent, "bedrock": broken})
        assert _status(collector, "bedrock") == ServiceStatus.SUCCESS

        dead = FakeClient(
            pages={
                "list_agents": lambda **kw: (_ for _ in ()).throw(boom),
                "list_knowledge_bases": lambda **kw: (_ for _ in ()).throw(boom),
            }
        )
        _, _, collector = _run(["bedrock"], {"bedrock-agent": dead, "bedrock": broken})
        assert _status(collector, "bedrock") == ServiceStatus.FAILED
