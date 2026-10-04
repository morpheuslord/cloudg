"""App Runner services / VPC connectors and Elastic Beanstalk applications /
environments. Environment variable values are never collected."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import gather_limited, rel
from cloudg.inventory.aws_services.application._common import (
    ApplicationBase,
    _clean_url,
    _role_rel,
    _vpc_config,
    logger,
)
from cloudg.inventory.aws_services.containers import image_repository
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# describe_environment_resources key -> (identifier field, label)
_EB_RESOURCE_FIELDS = (
    ("AutoScalingGroups", "Name", "auto scaling group"),
    ("Instances", "Id", "instance"),
    ("LaunchTemplates", "Id", "launch template"),
    ("LaunchConfigurations", "Name", "launch configuration"),
    ("LoadBalancers", "Name", "load balancer"),
    ("Queues", "URL", "worker queue"),
)
_EB_ENV_NAMESPACE = "aws:elasticbeanstalk:application:environment"


def _split(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _eb_exposed(env: dict, options: dict[tuple[str, str], str]) -> bool:
    """A web-server tier behind a public load balancer or a public instance."""
    scheme = options.get(("aws:ec2:vpc", "ELBScheme"), "public")
    env_type = options.get(("aws:elasticbeanstalk:environment", "EnvironmentType"))
    return (
        (env.get("Tier") or {}).get("Name") == "WebServer"
        and scheme != "internal"
        and (
            env_type != "SingleInstance"
            or options.get(("aws:ec2:vpc", "AssociatePublicIpAddress"), "true") != "false"
        )
    )


def _eb_environment_fields(env: dict, options: dict[tuple[str, str], str]) -> dict[str, Any]:
    return {
        "application": env.get("ApplicationName", ""),
        "environment_id": env.get("EnvironmentId"),
        "platform": env.get("PlatformArn") or env.get("SolutionStackName"),
        "solution_stack": env.get("SolutionStackName"),
        "tier": (env.get("Tier") or {}).get("Name"),
        "environment_type": options.get(("aws:elasticbeanstalk:environment", "EnvironmentType")),
        "status": env.get("Status"),
        "health": env.get("Health"),
        "version_label": env.get("VersionLabel"),
        "cname": env.get("CNAME"),
        "endpoint": env.get("EndpointURL"),
    }


def _eb_network_metadata(options: dict[tuple[str, str], str]) -> dict[str, Any]:
    subnets = _split(options.get(("aws:ec2:vpc", "Subnets")))
    elb_subnets = _split(options.get(("aws:ec2:vpc", "ELBSubnets")))
    groups = _split(options.get(("aws:autoscaling:launchconfiguration", "SecurityGroups")))
    return {
        "load_balancer_type": options.get(("aws:elasticbeanstalk:environment", "LoadBalancerType")),
        "elb_scheme": options.get(("aws:ec2:vpc", "ELBScheme"), "public"),
        "vpc_id": options.get(("aws:ec2:vpc", "VPCId")),
        "security_groups": [s for s in groups if s.startswith("sg-")],
        "vpc_config": {"SubnetIds": sorted(set(subnets + elb_subnets)), "SecurityGroupIds": []}
        if subnets or elb_subnets
        else None,
    }


class ComputeCollectorsMixin(ApplicationBase):
    """App Runner and Elastic Beanstalk collectors."""

    # ------------------------------------------------------------------
    # App Runner
    # ------------------------------------------------------------------

    def _apprunner_relations(self, svc: dict) -> list[dict | None]:
        img = (svc.get("SourceConfiguration") or {}).get("ImageRepository") or {}
        auth = (svc.get("SourceConfiguration") or {}).get("AuthenticationConfiguration") or {}
        egress = (svc.get("NetworkConfiguration") or {}).get("EgressConfiguration") or {}
        log_group = f"/aws/apprunner/{svc.get('ServiceName')}/{svc.get('ServiceId')}/application"
        relations: list[dict | None] = [
            _role_rel(
                (svc.get("InstanceConfiguration") or {}).get("InstanceRoleArn"), "instance role"
            ),
            _role_rel(auth.get("AccessRoleArn"), "ECR access role"),
            rel(
                auth.get("ConnectionArn"),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="source connection",
            ),
            rel(
                (svc.get("EncryptionConfiguration") or {}).get("KmsKey"),
                EdgeType.REFERENCES,
                "ENCRYPTED_BY_KMS",
            ),
            rel(
                egress.get("VpcConnectorArn"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="VPC connector",
            ),
            rel(self._log_group_arn(log_group), EdgeType.LOGS_TO, "LOGS_TO"),
        ]
        image = img.get("ImageIdentifier")
        if image and img.get("ImageRepositoryType") == "ECR":
            relations.append(
                rel(
                    image_repository(image),
                    EdgeType.USES_IMAGE,
                    "RUNS_ON",
                    description=f"runs {image}",
                )
            )
        return relations

    def _apprunner_env(self, src: dict) -> tuple[list[dict | None], list[str], list[str]]:
        """Environment references, variable names and secret names (never values)."""
        relations: list[dict | None] = []
        env_names: list[str] = []
        secret_names: list[str] = []
        code = src.get("CodeRepository") or {}
        cfgs = [
            (src.get("ImageRepository") or {}).get("ImageConfiguration") or {},
            ((code.get("CodeConfiguration") or {}).get("CodeConfigurationValues")) or {},
        ]
        for cfg in cfgs:
            env = cfg.get("RuntimeEnvironmentVariables") or {}
            env_names += sorted(env)
            relations += self._env_relations(env, "environment reference")
            for sname, ref in (cfg.get("RuntimeEnvironmentSecrets") or {}).items():
                secret_names.append(sname)
                relations.append(self._app_secret_rel(ref, "parameter", f"secret {sname}"))
        return relations, env_names, secret_names

    def _apprunner_service_asset(self, svc: dict, connectors: dict[str, dict]) -> CloudAsset:
        src = svc.get("SourceConfiguration") or {}
        img = src.get("ImageRepository") or {}
        net = svc.get("NetworkConfiguration") or {}
        egress = net.get("EgressConfiguration") or {}
        relations = self._apprunner_relations(svc)
        env_rels, env_names, secret_names = self._apprunner_env(src)
        relations += env_rels
        connector = connectors.get(egress.get("VpcConnectorArn") or "") or {}
        public = (net.get("IngressConfiguration") or {}).get("IsPubliclyAccessible", True)
        return self._asset(
            arn=svc["ServiceArn"],
            name=svc.get("ServiceName", ""),
            asset_type=AssetType.APP_SERVICE,
            metadata={
                "service": "apprunner",
                "platform": "apprunner",
                "status": svc.get("Status"),
                "service_url": svc.get("ServiceUrl"),
                "source_type": "image" if img else "code",
                "image": img.get("ImageIdentifier"),
                "image_repository_type": img.get("ImageRepositoryType"),
                "repository_url": _clean_url(
                    (src.get("CodeRepository") or {}).get("RepositoryUrl")
                ),
                "auto_deployments": src.get("AutoDeploymentsEnabled"),
                "cpu": (svc.get("InstanceConfiguration") or {}).get("Cpu"),
                "memory": (svc.get("InstanceConfiguration") or {}).get("Memory"),
                "egress_type": egress.get("EgressType"),
                "publicly_accessible": public,
                "environment_variable_names": env_names,
                "secret_names": sorted(secret_names),
                "vpc_config": _vpc_config(connector, "Subnets", "SecurityGroups"),
            },
            relations=relations,
            exposed=bool(public),
            aliases=[svc.get("ServiceUrl"), svc.get("ServiceId")],
        )

    def _apprunner_connector_asset(self, c: dict) -> CloudAsset:
        return self._asset(
            arn=c["VpcConnectorArn"],
            name=c.get("VpcConnectorName", ""),
            asset_type=AssetType.VPC_LINK,
            metadata={
                "service": "apprunner",
                "kind": "vpc_connector",
                "status": c.get("Status"),
                "revision": c.get("VpcConnectorRevision"),
                "vpc_config": _vpc_config(c, "Subnets", "SecurityGroups"),
            },
        )

    async def _collect_apprunner(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("apprunner") as ar:
            summaries = [s async for s in self._pages(ar.list_services, "ServiceSummaryList")]
            connectors: dict[str, dict] = {}
            try:
                async for c in self._pages(ar.list_vpc_connectors, "VpcConnectors"):
                    connectors[c["VpcConnectorArn"]] = c
            except Exception as exc:
                logger.debug("list_vpc_connectors failed: %s", exc)

            async def detail(s: dict) -> CloudAsset:
                svc = (await ar.describe_service(ServiceArn=s["ServiceArn"]))["Service"]
                return self._apprunner_service_asset(svc, connectors)

            results = await gather_limited([lambda s=s: detail(s) for s in summaries])
            assets.extend(a for a in results if a)
        assets.extend(self._apprunner_connector_asset(c) for c in connectors.values())
        return assets

    # ------------------------------------------------------------------
    # Elastic Beanstalk
    # ------------------------------------------------------------------

    async def _eb_resources(self, eb: Any, env: dict, relations: list) -> dict[str, Any]:
        """Managed resources by kind; MANAGES relations go into ``relations``."""
        name = env.get("EnvironmentName", "")
        resources: dict[str, Any] = {}
        try:
            ident = (
                {"EnvironmentId": env["EnvironmentId"]}
                if env.get("EnvironmentId")
                else {"EnvironmentName": name}
            )
            res = (await eb.describe_environment_resources(**ident)).get(
                "EnvironmentResources"
            ) or {}
            for key, field, label in _EB_RESOURCE_FIELDS:
                ids = [r.get(field) for r in res.get(key, []) or [] if r.get(field)]
                resources[key] = ids
                relations.extend(
                    rel(i, EdgeType.MANAGES, description=f"environment {label}") for i in ids
                )
        except Exception as exc:
            logger.debug("describe_environment_resources failed for %s: %s", name, exc)
        return resources

    async def _eb_options(
        self, eb: Any, app: str, name: str
    ) -> tuple[dict[tuple[str, str], str], list[str]]:
        """Option settings, and environment variable names (never values)."""
        options: dict[tuple[str, str], str] = {}
        env_var_names: list[str] = []
        try:
            cfg = await eb.describe_configuration_settings(
                ApplicationName=app, EnvironmentName=name
            )
            for setting in (cfg.get("ConfigurationSettings") or [{}])[0].get(
                "OptionSettings", []
            ) or []:
                ns, opt = setting.get("Namespace", ""), setting.get("OptionName", "")
                if ns == _EB_ENV_NAMESPACE:
                    env_var_names.append(opt)  # never the value
                    continue
                if setting.get("Value") is not None:
                    options[(ns, opt)] = str(setting["Value"])
        except Exception as exc:
            logger.debug("describe_configuration_settings failed for %s: %s", name, exc)
        return options, env_var_names

    def _eb_link_relations(self, env: dict, app: str) -> list[dict | None]:
        return [
            rel(
                self._arn("elasticbeanstalk", f"environment/{app}/{link.get('EnvironmentName')}"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description=f"environment link {link.get('LinkName')}",
            )
            for link in env.get("EnvironmentLinks", []) or []
        ]

    async def _eb_environment_asset(self, eb: Any, env: dict) -> CloudAsset:
        name, app = env.get("EnvironmentName", ""), env.get("ApplicationName", "")
        relations: list[dict | None] = [
            rel(
                self._arn("elasticbeanstalk", f"application/{app}"), EdgeType.CONTAINS, reverse=True
            ),
            _role_rel(env.get("OperationsRole"), "operations role"),
        ]
        resources = await self._eb_resources(eb, env, relations)
        options, env_var_names = await self._eb_options(eb, app, name)
        service_role = options.get(("aws:elasticbeanstalk:environment", "ServiceRole"))
        profile = options.get(("aws:autoscaling:launchconfiguration", "IamInstanceProfile"))
        relations.append(_role_rel(self._role_ref(service_role), "service role"))
        relations.append(
            rel(
                self._instance_profile_ref(profile),
                EdgeType.REFERENCES,
                "RUNS_ON",
                description="instance profile",
            )
        )
        relations += self._eb_link_relations(env, app)
        return self._asset(
            arn=env.get("EnvironmentArn")
            or self._arn("elasticbeanstalk", f"environment/{app}/{name}"),
            name=name,
            asset_type=AssetType.APP_SERVICE,
            metadata={
                "service": "elasticbeanstalk",
                "kind": "environment",
                **_eb_environment_fields(env, options),
                **_eb_network_metadata(options),
                "service_role": service_role,
                "instance_profile": profile,
                "environment_variable_names": sorted(env_var_names),
                "managed_resources": resources,
            },
            relations=relations,
            exposed=_eb_exposed(env, options),
            aliases=[env.get("EnvironmentId"), env.get("CNAME"), env.get("EndpointURL")],
        )

    def _eb_application_asset(self, app: dict) -> CloudAsset:
        aname = app.get("ApplicationName", "")
        lifecycle_role = (app.get("ResourceLifecycleConfig") or {}).get("ServiceRole")
        return self._asset(
            arn=app.get("ApplicationArn") or self._arn("elasticbeanstalk", f"application/{aname}"),
            name=aname,
            asset_type=AssetType.APP_SERVICE,
            metadata={
                "service": "elasticbeanstalk",
                "kind": "application",
                "platform": "elasticbeanstalk",
                "versions": len(app.get("Versions", []) or []),
                "configuration_templates": app.get("ConfigurationTemplates", []),
                "service_role": lifecycle_role,
            },
            relations=[_role_rel(lifecycle_role, "version lifecycle role")],
        )

    async def _collect_elasticbeanstalk(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("elasticbeanstalk") as eb:
            apps = (await eb.describe_applications()).get("Applications", []) or []
            envs = [
                e
                async for e in self._paginate(
                    eb, "describe_environments", "Environments", IncludeDeleted=False
                )
            ]
            results = await gather_limited(
                [lambda e=e: self._eb_environment_asset(eb, e) for e in envs]
            )
            assets.extend(a for a in results if a)
        assets.extend(self._eb_application_asset(app) for app in apps)
        return assets
