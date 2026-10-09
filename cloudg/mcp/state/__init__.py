"""In-memory workspace of named datasets shared by every MCP request.

A :class:`Dataset` is one loaded view of cloud infrastructure: assets,
edges, findings, compliance mappings, collection coverage, the
organization topology and unresolved references, plus where it came from
(a file path, a live collection, or inline data). Derived structures
(lookup indexes, the NetworkX graph, the :class:`DependencyGraph`, the
reachability analyser, centrality metrics and the RDF ontology) are
built lazily on first use, cached, and invalidated whenever the dataset
is mutated (findings ingested, suppressed, normalised...).

The :class:`Workspace` holds several datasets by name with one marked
active, so an agent can load a baseline and a fresh collection side by
side and diff them. It also owns filesystem safety: every path a tool
reads or writes must resolve inside one of the configured allowed roots
(default: the current directory and the configured report directory,
never ``/`` or the home directory implicitly), and writes land under a
single output root.

Usage::

    ws = Workspace(CloudGConfig(), allowed_roots=["./reports"])
    ds = ws.load("./reports/inventory-map.json")       # auto-detected
    ws.get().resolve_asset("arn:aws:lambda:...:function:api")
    ws.on_change(lambda kind, uri: print(kind, uri))  # list_changed hooks

Everything here is thread-safe: tool handlers run in worker threads.

The package is split by concern: :mod:`~cloudg.mcp.state.dataset`,
:mod:`~cloudg.mcp.state.loading`, :mod:`~cloudg.mcp.state.diff` and
:mod:`~cloudg.mcp.state.workspace`; everything is re-exported here.
"""

from __future__ import annotations

from cloudg.mcp.state.base import (
    DATASET_KINDS,
    INTERNET_NODES,
    SCANNER_KINDS,
    SEVERITY_RANK,
    NoDatasetError,
    ReferenceNotFoundError,
    ref_tails,
)
from cloudg.mcp.state.dataset import Dataset
from cloudg.mcp.state.diff import diff_datasets
from cloudg.mcp.state.loading import (
    check_prowler_input,
    detect_kind,
    is_ocsf,
    load_dataset_file,
)
from cloudg.mcp.state.workspace import ALLOWED_ROOTS_ENV, Workspace, default_roots

__all__ = [
    "ALLOWED_ROOTS_ENV",
    "DATASET_KINDS",
    "INTERNET_NODES",
    "SCANNER_KINDS",
    "SEVERITY_RANK",
    "Dataset",
    "NoDatasetError",
    "ReferenceNotFoundError",
    "Workspace",
    "check_prowler_input",
    "default_roots",
    "detect_kind",
    "diff_datasets",
    "is_ocsf",
    "load_dataset_file",
    "ref_tails",
]
