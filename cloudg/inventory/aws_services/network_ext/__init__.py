"""Extended network fabric: hybrid connectivity, edge, PrivateLink, DNS
resolution and service networking.

- Site-to-site VPN: connections (-> customer gateway, VGW / TGW / Cloud
  WAN, tunnel status, static routes), virtual private gateways (-> VPCs),
  customer gateways (public IP, BGP ASN).
- Egress-only internet gateways and customer-managed prefix lists.
- Transit Gateway depth: route tables (associations / propagations ->
  attached resources, route sample) and peering attachments (cross-account
  / cross-region TGW peering).
- PrivateLink provider side: endpoint services -> NLB / GWLB, allowed
  principals, consumer endpoints (and their accounts).
- API Gateway depth: authorizers (-> Lambda / Cognito), VPC links
  (-> NLBs, subnets, SGs), custom domains (-> APIs, certificates; their
  regional / CloudFront names are aliases so Route 53 records resolve).
- CloudFront (deep, overrides the shallow base collector): CNAMEs,
  certificates, typed origins (S3 / ALB / API / VPC origins), OAC / OAI,
  Lambda@Edge and CloudFront Functions, access-log bucket, WAF.
- Route 53 Resolver: endpoints, forwarding rules + VPC associations, DNS
  Firewall rule group associations, query logging configurations.
- Direct Connect: connections, LAGs, virtual interfaces, DX gateways and
  their VGW / TGW associations.
- Global Accelerator: accelerators -> listeners -> endpoint groups ->
  endpoints.
- ELBv2 listeners and listener rules (forward / authenticate / redirect).
- VPC Lattice: service networks, services, target groups, auth policies.
- Network Manager / Cloud WAN: global networks, core networks and their
  attachments, transit gateway registrations.

Secrets are never collected: VPN tunnel options and customer gateway
configuration (pre-shared keys), Direct Connect BGP auth keys and MACsec
keys, OIDC client secrets and CloudFront origin custom header values are
all dropped.
"""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services.network_ext._common import (
    _COGNITO_ISSUER_RE,
    _EXECUTE_API_RE,
    _GONE_STATES,
    _LAMBDA_URI_RE,
    _MAX_LIST_METADATA,
    _MAX_PREFIX_ENTRIES,
    _MAX_RULES_PER_LISTENER,
    _MAX_TGW_ROUTES,
    _S3_ORIGIN_RE,
    _S3_URI_RE,
    _bucket_from_domain,
    _ec2_arn,
    _name_tag,
    _policy_is_public,
    _unique,
    logger,
)
from cloudg.inventory.aws_services.network_ext.apigateway import ApiGatewayCollectorsMixin
from cloudg.inventory.aws_services.network_ext.cloudfront import CloudFrontCollectorsMixin
from cloudg.inventory.aws_services.network_ext.direct_connect import (
    DirectConnectCollectorsMixin,
)
from cloudg.inventory.aws_services.network_ext.elb_rules import ElbRulesCollectorsMixin
from cloudg.inventory.aws_services.network_ext.global_accelerator import (
    GlobalAcceleratorCollectorsMixin,
)
from cloudg.inventory.aws_services.network_ext.lattice import LatticeCollectorsMixin
from cloudg.inventory.aws_services.network_ext.network_manager import (
    NetworkManagerCollectorsMixin,
)
from cloudg.inventory.aws_services.network_ext.privatelink import PrivateLinkCollectorsMixin
from cloudg.inventory.aws_services.network_ext.resolver import ResolverCollectorsMixin
from cloudg.inventory.aws_services.network_ext.tgw import TransitGatewayCollectorsMixin
from cloudg.inventory.aws_services.network_ext.vpn import VpnCollectorsMixin
from cloudg.schema.models import CloudAsset

__all__ = [
    "NetworkExtCollectorsMixin",
    "_COGNITO_ISSUER_RE",
    "_EXECUTE_API_RE",
    "_GONE_STATES",
    "_LAMBDA_URI_RE",
    "_MAX_LIST_METADATA",
    "_MAX_PREFIX_ENTRIES",
    "_MAX_RULES_PER_LISTENER",
    "_MAX_TGW_ROUTES",
    "_S3_ORIGIN_RE",
    "_S3_URI_RE",
    "_bucket_from_domain",
    "_ec2_arn",
    "_name_tag",
    "_policy_is_public",
    "_unique",
    "logger",
]


class NetworkExtCollectorsMixin(
    VpnCollectorsMixin,
    PrivateLinkCollectorsMixin,
    TransitGatewayCollectorsMixin,
    ApiGatewayCollectorsMixin,
    CloudFrontCollectorsMixin,
    ResolverCollectorsMixin,
    DirectConnectCollectorsMixin,
    GlobalAcceleratorCollectorsMixin,
    ElbRulesCollectorsMixin,
    LatticeCollectorsMixin,
    NetworkManagerCollectorsMixin,
):
    def _network_ext_tasks(self) -> dict[str, tuple[Any, str, bool]]:
        """name -> (collector callable, service family, is_global)."""
        return {
            "vpn": (self._collect_vpn, "hybrid", False),
            "egress_only_igw": (self._collect_egress_only_igw, "network", False),
            "prefix_lists": (self._collect_prefix_lists, "network", False),
            "tgw_routing": (self._collect_tgw_routing, "network", False),
            "endpoint_services": (self._collect_endpoint_services, "network", False),
            "apigateway_authorizers": (self._collect_apigateway_authorizers, "serverless", False),
            "apigateway_vpc_links": (self._collect_apigateway_vpc_links, "serverless", False),
            "apigateway_domains": (self._collect_apigateway_domains, "serverless", False),
            "route53_resolver": (self._collect_route53_resolver, "dns", False),
            "direct_connect": (self._collect_direct_connect, "hybrid", False),
            "direct_connect_gateways": (self._collect_direct_connect_gateways, "hybrid", True),
            "global_accelerator": (self._collect_global_accelerator, "network", True),
            "elb_rules": (self._collect_elb_rules, "network", False),
            "vpc_lattice": (self._collect_vpc_lattice, "network", False),
            "network_manager": (self._collect_network_manager, "hybrid", True),
        }

    async def _collect_cloudfront(self) -> list[CloudAsset]:
        """Deep CloudFront collector. Defined here so it overrides the
        shallow base collector: this class precedes AsyncAWSCollector in
        the deep collector's MRO."""
        return await self._collect_cloudfront_deep()
