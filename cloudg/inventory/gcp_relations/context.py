"""Extraction framework: per-asset context, extractor output and registry."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.gcp_relations.names import kms_refs, sa_email, sa_ref
from cloudg.schema.models import CloudAsset, EdgeType

logger = logging.getLogger(__package__)

# ---------------------------------------------------------------------------
# Extraction framework
# ---------------------------------------------------------------------------


@dataclass
class GCPContext:
    """What an extractor knows about the asset being mapped."""

    name: str
    asset_type: str
    data: dict[str, Any]
    project_id: str | None = None
    project_number: str | None = None
    location: str | None = None
    ancestors: list[str] = field(default_factory=list)

    @property
    def region(self) -> str | None:
        loc = self.location or ""
        if re.fullmatch(r"[a-z]+-[a-z]+\d+-[a-z]", loc):
            return loc.rsplit("-", 1)[0]
        return loc or None

    def default_sa(self) -> str | None:
        if self.project_number:
            return f"{self.project_number}-compute@developer.gserviceaccount.com"
        return None


@dataclass
class Extracted:
    """Output of one extractor run."""

    relations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    exposure: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self, target: Any, edge: EdgeType, relationship: str | None = None, **kwargs: Any
    ) -> None:
        """Declare a relation (``kwargs``: ``reverse``, ``description`` and edge
        properties, as for :func:`rel`); empty targets and repeats are dropped."""
        r = rel(target, edge, relationship, **kwargs)
        if r and r not in self.relations:
            self.relations.append(r)

    def sa(
        self, ref: Any, ctx: GCPContext, description: str | None = None, **props: Any
    ) -> str | None:
        """Declare that the asset runs as a service account."""
        if ref == "default":
            ref = ctx.default_sa()
        email = sa_email(ref)
        if not email:
            return None
        self.add(sa_ref(email), EdgeType.ASSUMES_ROLE, "RUNS_ON", description=description, **props)
        return email

    def in_subnet(self, ref: Any) -> None:
        """Declare that the subnet (or network) ``ref`` contains the asset."""
        self.add(ref, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)

    def alias(self, *values: Any) -> None:
        """Extra identifiers of the asset (non-empty strings, first occurrence kept)."""
        for v in values:
            if isinstance(v, str) and v and v not in self.aliases:
                self.aliases.append(v)

    def expose(
        self,
        reason: str,
        protocol: str | None = None,
        ports: Iterable[str] = (),
        kind: str = "INTERNET_EXPOSED",
    ) -> None:
        """Mark the asset reachable from the internet (0.0.0.0/0)."""
        entry = {"via": reason, "kind": kind}
        if protocol:
            entry["protocol"] = protocol
        port_list = [str(p) for p in ports if p not in (None, "")]
        if port_list:
            entry["ports"] = port_list
        if entry not in self.exposure:
            self.exposure.append(entry)


Extractor = Callable[[GCPContext, Extracted], None]
EXTRACTORS: dict[str, Extractor] = {}


def _extractor(*asset_types: str) -> Callable[[Extractor], Extractor]:
    def register(fn: Extractor) -> Extractor:
        for t in asset_types:
            EXTRACTORS[t] = fn
        return fn

    return register


def extract(ctx: GCPContext) -> Extracted:
    """Run the extractor for ``ctx.asset_type`` plus the generic CMEK scan."""
    out = Extracted()
    fn = EXTRACTORS.get(ctx.asset_type)
    if fn is not None:
        try:
            fn(ctx, out)
        except Exception as exc:  # one malformed resource must not stop the sweep
            logger.debug("GCP extractor failed for %s: %s", ctx.name, exc, exc_info=True)
            out.metadata["extraction_error"] = f"{type(exc).__name__}: {exc}"
    if ctx.asset_type.startswith("cloudkms.googleapis.com/"):
        return out
    keys = kms_refs(ctx.data)
    if keys:
        out.metadata["kms_keys"] = keys
        for key in keys:
            out.add(
                key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description=f"encrypted with {key}"
            )
    return out


def mark_exposed(asset: CloudAsset, reason: str, **detail: Any) -> None:
    """Flag an asset internet-exposed and record why (drives 0.0.0.0/0 edges)."""
    asset.is_internet_exposed = True
    reasons = asset.metadata.setdefault("exposure_reasons", [])
    if reason not in reasons:
        reasons.append(reason)
    entry = {
        "via": reason,
        "kind": detail.pop("kind", None) or "INTERNET_EXPOSED",
        **{k: v for k, v in detail.items() if v},
    }
    ingress = asset.metadata.setdefault("internet_ingress", [])
    if entry not in ingress:
        ingress.append(entry)
