"""The cloudg MCP catalog: every tool, resource, resource template and
prompt the layer exposes, grouped by category.

Each module has a ``register(registry)`` function. :func:`default_registry`
registers them all; build your own :class:`~cloudg.mcp.core.Registry` from
a subset to expose less::

    from cloudg.mcp.core import Registry
    from cloudg.mcp.catalog import inventory, graph

    reg = Registry()
    inventory.register(reg)
    graph.register(reg)
    layer = CloudGMCPLayer(registry=reg)

(or filter with ``CloudGMCPLayer(include_categories=[...])``).
"""

from __future__ import annotations

import logging
from types import ModuleType

from cloudg.mcp.core import Registry

logger = logging.getLogger("cloudg.mcp")

CATEGORIES: dict[str, str] = {
    "workspace": "Load, select, snapshot, diff and unload datasets",
    "inventory": "Search, inspect and aggregate assets, accounts, regions, tags, coverage, org",
    "graph": "Relationships: neighbours, paths, exposure, attack / lateral paths, "
    "dependencies, blast radius, centrality, sub-graphs",
    "findings": "Browse, summarise, prioritise, suppress and ingest security findings",
    "compliance": "Framework posture, controls and compliance gaps",
    "ontology": "RDF ontology, read-only SPARQL, semantic neighbourhoods, RAG chunks",
    "export": "Terraform recreation and report files",
    "live": "Collect from cloud APIs and run scanners (credentials / binaries; open world)",
    "meta": "Server capabilities and cloudg's vocabulary",
    "privacy": "Privacy policy, pseudonym vault and data-handling controls",
    "prompts": "Packaged analysis workflows",
}


def _modules() -> list[ModuleType]:
    from cloudg.mcp.catalog import (
        compliance,
        export,
        findings,
        graph,
        inventory,
        live,
        meta,
        ontology,
        prompts,
        resources,
        workspace,
    )

    return [workspace, inventory, graph, findings, compliance, ontology, export, live, meta,
            resources, prompts]


def default_registry() -> Registry:
    """A registry with the full cloudg catalog (plus the privacy module
    when it is available)."""
    reg = Registry()
    for mod in _modules():
        mod.register(reg)
    try:
        from cloudg.mcp.catalog import privacy
    except ImportError:
        logger.debug("cloudg.mcp.catalog.privacy not available; skipping privacy tools")
    else:
        privacy.register(reg)
    return reg


__all__ = ["CATEGORIES", "default_registry"]
