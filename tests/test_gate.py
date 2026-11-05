"""Tests for the CI severity gate (cloudg.gate, cloudg gate) and the SARIF renderer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from cloudg.cli import cli
from cloudg.gate import EXIT_GATE_FAILED, evaluate_gate, parse_threshold
from cloudg.renderers.json_export import JSONExporter
from cloudg.renderers.sarif import build_sarif, write_sarif
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    Finding,
    ScanResult,
    Severity,
)

ARN = "arn:aws:s3:::data-bucket"


def _asset() -> CloudAsset:
    return CloudAsset(
        id="bucket-1",
        arn=ARN,
        name="data-bucket",
        asset_type=AssetType.S3_BUCKET,
        provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="111111111111",
    )


def _finding(
    severity: Severity = Severity.HIGH,
    title: str = "S3 bucket is public",
    tool: str = "prowler",
    rule: str | None = "s3_bucket_public_access",
    suppressed: bool = False,
    resource_id: str = "bucket-1",
) -> Finding:
    return Finding(
        resource_id=resource_id,
        resource_arn=ARN if resource_id == "bucket-1" else None,
        severity=severity,
        title=title,
        description=f"{title} (description)",
        remediation="Block public access.",
        source_tool=tool,
        source_finding_id=rule,
        compliance_frameworks=["CIS-AWS-3.0"],
        is_suppressed=suppressed,
    )


def _result(findings: list[Finding], assets: list[CloudAsset] | None = None) -> ScanResult:
    return ScanResult(
        provider=CloudProvider.AWS,
        assets=[_asset()] if assets is None else assets,
        findings=findings,
    )


def _findings_json(directory: Path, findings: list[Finding], **kwargs: Any) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    return JSONExporter(str(directory)).export(_result(findings, **kwargs))


def invoke(*args: str) -> Any:
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


# ── evaluate_gate ────────────────────────────────────────────────────


class TestEvaluateGate:
    def test_counts_findings_at_or_above_the_threshold(self) -> None:
        result = _result(
            [_finding(Severity.CRITICAL), _finding(Severity.HIGH), _finding(Severity.MEDIUM)]
        )
        gate = evaluate_gate(result, fail_on="high")
        assert len(gate.blocking) == 2
        assert not gate.passed
        assert gate.counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0}

    def test_suppressed_findings_never_block(self) -> None:
        gate = evaluate_gate(_result([_finding(Severity.CRITICAL, suppressed=True)]), "low")
        assert gate.passed
        assert gate.suppressed == 1
        assert gate.counts["CRITICAL"] == 0

    def test_max_tolerates_that_many_blocking_findings(self) -> None:
        result = _result([_finding(Severity.HIGH), _finding(Severity.HIGH)])
        assert evaluate_gate(result, "high", max_blocking=2).passed
        assert not evaluate_gate(result, "high", max_blocking=1).passed

    def test_never_does_not_fail_on_findings(self) -> None:
        gate = evaluate_gate(_result([_finding(Severity.CRITICAL)]), "never")
        assert gate.passed
        assert gate.blocking == []

    def test_min_assets_fails_a_run_that_collected_too_little(self) -> None:
        gate = evaluate_gate(_result([], assets=[]), "high", min_assets=1)
        assert not gate.passed
        assert "asset" in gate.reason

    def test_blocking_is_sorted_worst_first(self) -> None:
        result = _result(
            [_finding(Severity.HIGH, title="b"), _finding(Severity.CRITICAL, title="a")]
        )
        gate = evaluate_gate(result, "high")
        assert [f.severity for f in gate.blocking] == [Severity.CRITICAL, Severity.HIGH]

    @pytest.mark.parametrize("bad", ["severe", "", "HIGHEST"])
    def test_unknown_threshold_is_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            parse_threshold(bad)

    def test_threshold_is_case_insensitive(self) -> None:
        assert parse_threshold("Critical") is Severity.CRITICAL
        assert parse_threshold("NEVER") is None


# ── SARIF ────────────────────────────────────────────────────────────


class TestSarif:
    def test_document_shape(self) -> None:
        doc = build_sarif(_result([_finding()]))
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "cloudg"
        assert len(run["results"]) == 1

    def test_rules_are_deduplicated_and_carry_security_severity(self) -> None:
        result = _result(
            [
                _finding(Severity.MEDIUM),
                _finding(Severity.CRITICAL),  # same rule, worse severity wins
                _finding(Severity.LOW, tool="checkov", rule="CKV_AWS_18", title="No logging"),
            ]
        )
        rules = build_sarif(result)["runs"][0]["tool"]["driver"]["rules"]
        by_id = {r["id"]: r for r in rules}
        assert set(by_id) == {"prowler/s3_bucket_public_access", "checkov/CKV_AWS_18"}
        public = by_id["prowler/s3_bucket_public_access"]
        assert public["properties"]["security-severity"] == "9.5"
        assert public["defaultConfiguration"]["level"] == "error"
        assert "CIS-AWS-3.0" in public["properties"]["tags"]

    def test_prowler_finding_ids_share_one_rule_per_check(self) -> None:
        a = _finding(rule="prowler-aws-s3_bucket_public_access-111111111111-us-east-1-ab12")
        b = _finding(rule="prowler-aws-s3_bucket_public_access-111111111111-eu-west-1-cd34")
        doc = build_sarif(_result([a, b]))["runs"][0]
        assert [r["id"] for r in doc["tool"]["driver"]["rules"]] == [
            "prowler/s3_bucket_public_access"
        ]
        assert {r["ruleId"] for r in doc["results"]} == {"prowler/s3_bucket_public_access"}

    def test_rule_id_falls_back_to_the_title(self) -> None:
        doc = build_sarif(_result([_finding(rule=None, title="Root account has no MFA!")]))
        assert doc["runs"][0]["results"][0]["ruleId"] == "prowler/root-account-has-no-mfa"

    @pytest.mark.parametrize(
        ("severity", "level"),
        [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ],
    )
    def test_levels(self, severity: Severity, level: str) -> None:
        doc = build_sarif(_result([_finding(severity)]))
        assert doc["runs"][0]["results"][0]["level"] == level

    def test_location_names_the_cloud_resource(self) -> None:
        res = build_sarif(_result([_finding()]))["runs"][0]["results"][0]
        loc = res["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("cloud/aws/111111111111/us-east-1/")
        assert loc["logicalLocations"][0]["fullyQualifiedName"] == ARN

    def test_unknown_resource_still_gets_a_location(self) -> None:
        res = build_sarif(_result([_finding(resource_id="vm/../x y")]))["runs"][0]["results"][0]
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("cloud/unknown/")
        assert ".." not in uri.split("/")
        assert " " not in uri

    def test_fingerprint_is_stable_across_runs(self) -> None:
        a = build_sarif(_result([_finding()]))["runs"][0]["results"][0]
        b = build_sarif(_result([_finding()]))["runs"][0]["results"][0]
        assert a["partialFingerprints"] == b["partialFingerprints"]

    def test_suppressed_findings_are_marked(self) -> None:
        res = build_sarif(_result([_finding(suppressed=True)]))["runs"][0]["results"][0]
        assert res["suppressions"] == [{"kind": "external"}]

    def test_write_sarif(self, tmp_path: Path) -> None:
        path = write_sarif(_result([_finding()]), tmp_path / "out" / "cloudg.sarif")
        assert json.loads(path.read_text())["version"] == "2.1.0"


# ── cloudg gate ──────────────────────────────────────────────────────


class TestGateCommand:
    def test_passes_below_the_threshold(self, tmp_path: Path) -> None:
        src = _findings_json(tmp_path, [_finding(Severity.MEDIUM)])
        res = invoke("gate", "-i", str(src), "--fail-on", "high")
        assert res.exit_code == 0, res.output
        assert "passed" in res.output

    def test_fails_with_its_own_exit_code(self, tmp_path: Path) -> None:
        src = _findings_json(tmp_path, [_finding(Severity.CRITICAL)])
        res = invoke("gate", "-i", str(src))
        assert res.exit_code == EXIT_GATE_FAILED
        assert "S3 bucket is public" in res.output

    def test_reads_findings_json_from_a_directory(self, tmp_path: Path) -> None:
        _findings_json(tmp_path, [_finding(Severity.LOW)])
        assert invoke("gate", "-i", str(tmp_path)).exit_code == 0

    def test_missing_input_exits_1(self, tmp_path: Path) -> None:
        res = invoke("gate", "-i", str(tmp_path / "nope.json"))
        assert res.exit_code == 1

    def test_writes_sarif_and_summary(self, tmp_path: Path) -> None:
        src = _findings_json(tmp_path / "r", [_finding(Severity.HIGH, title="a | b")])
        sarif = tmp_path / "cloudg.sarif"
        summary = tmp_path / "summary.md"
        summary.write_text("# earlier step\n")
        res = invoke("gate", "-i", str(src), "--sarif", str(sarif), "--summary", str(summary))
        assert res.exit_code == EXIT_GATE_FAILED
        assert json.loads(sarif.read_text())["runs"][0]["results"]
        text = summary.read_text()
        assert text.startswith("# earlier step\n")  # appended, not replaced
        assert "a \\| b" in text  # table cells are escaped
        assert "| HIGH | 1 |" in text

    def test_json_output(self, tmp_path: Path) -> None:
        src = _findings_json(tmp_path, [_finding(Severity.HIGH), _finding(Severity.LOW)])
        res = invoke("gate", "-i", str(src), "--json", "--fail-on", "critical")
        data = json.loads(res.stdout)  # the banner and the table go to stderr
        assert res.exit_code == 0
        assert data["passed"] is True
        assert data["blocking"] == 0
        assert data["total_findings"] == 2
        assert data["fail_on"] == "CRITICAL"

    def test_min_assets(self, tmp_path: Path) -> None:
        src = _findings_json(tmp_path, [], assets=[])
        res = invoke("gate", "-i", str(src), "--min-assets", "1")
        assert res.exit_code == EXIT_GATE_FAILED
