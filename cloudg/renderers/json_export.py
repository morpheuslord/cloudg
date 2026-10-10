"""JSON findings export renderer."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from cloudg.schema.models import ScanResult

logger = logging.getLogger(__name__)


def _iso(value: datetime | None) -> str | None:
    """ISO 8601 text of a timestamp, or None (JSON null) when it is unset."""
    return value.isoformat() if value is not None else None


class JSONExporter:
    """Exports scan results to a findings.json file.

    Contains: full asset inventory, all findings, edges, graph data,
    compliance mappings (enough for `cloudg report -i` to rebuild the run).
    Timestamps in ``metadata`` are ISO 8601 strings, the format the
    findings and assets use; an unset value is JSON null.
    """

    def __init__(self, output_dir: str = ".") -> None:
        self._output_dir = Path(output_dir)

    def export(
        self,
        scan_result: ScanResult,
        graph_json: dict[str, Any] | None = None,
        filename: str = "findings.json",
    ) -> Path:
        """Export scan results to JSON.

        Args:
            scan_result: The normalised scan result.
            graph_json: Optional D3.js graph data.
            filename: Output filename.

        Returns:
            Path to the generated JSON file.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self._output_dir / filename

        export_data = {
            "metadata": {
                "scan_id": scan_result.scan_id,
                "provider": scan_result.provider.value if scan_result.provider else None,
                "account_id": scan_result.account_id,
                "region": scan_result.region,
                "started_at": _iso(scan_result.started_at),
                "completed_at": _iso(scan_result.completed_at),
            },
            "summary": scan_result.summary,
            "assets": [
                asset.model_dump(exclude={"raw_data"}, mode="json") for asset in scan_result.assets
            ],
            "findings": [finding.model_dump(mode="json") for finding in scan_result.findings],
            "compliance": [result.model_dump(mode="json") for result in scan_result.compliance],
            "edges": [edge.model_dump(mode="json") for edge in scan_result.edges],
            "graph": graph_json or {"nodes": [], "links": []},
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        logger.info("Exported findings to %s", output_path)
        return output_path
