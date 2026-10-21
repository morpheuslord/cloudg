#!/usr/bin/env python3
"""Render a sample report.html from the synthetic multi-cloud test estate.

No cloud account needed: the assets, edges, findings and compliance results
come from tests/mcp/fixtures/sample_estate.py, so every ID in the output is
fake and safe to publish.

Usage (from the repo root):
    python scripts/build_sample_report.py              # -> site/static/sample-report.html
    python scripts/build_sample_report.py --out docs/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cloudg.graph.builder import GraphBuilder  # noqa: E402
from cloudg.renderers.html_report import HTMLReportGenerator  # noqa: E402
from cloudg.schema.models import ScanResult  # noqa: E402
from tests.mcp.fixtures import sample_estate  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(ROOT / "site" / "static"))
    ap.add_argument("--filename", default="sample-report.html")
    args = ap.parse_args()

    inv = sample_estate.build_inventory()
    result = ScanResult(
        assets=inv.assets,
        edges=inv.edges,
        findings=sample_estate.findings(),
        compliance=sample_estate.compliance(),
    )
    graph = GraphBuilder()
    graph.build(inv.assets, inv.edges)

    path = HTMLReportGenerator(output_dir=args.out).generate(
        result, graph_json=graph.to_d3_json(), filename=args.filename
    )
    print(
        f"{path}  ({len(result.assets)} assets, {len(result.findings)} findings, "
        f"{len(result.compliance)} compliance results)"
    )


if __name__ == "__main__":
    main()
