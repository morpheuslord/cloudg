"""Tests for ingesting pre-existing scanner outputs (cloudg.ingest)."""

from __future__ import annotations

import json

import pytest

from cloudg.ingest import ingest_reports, parse_report
from cloudg.scanners.checkov import CheckovScanner
from cloudg.scanners.prowler import ProwlerScanner
from cloudg.scanners.scoutsuite import ScoutSuiteScanner
from cloudg.scanners.trivy import TrivyScanner
from cloudg.schema.models import Severity

# ─────────────────────────────────────────────────────────────────────
# Sample native outputs
# ─────────────────────────────────────────────────────────────────────

PROWLER_ASFF = [
    {
        "Id": "prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-abc",
        "Title": "S3 bucket default encryption",
        "Description": "Bucket has no default encryption",
        "Severity": {"Label": "HIGH"},
        "Resources": [{"Id": "arn:aws:s3:::my-bucket"}],
        "Compliance": {"Status": "FAILED", "RelatedRequirements": ["CIS 2.1.1"]},
        "Remediation": {"Recommendation": {"Text": "Enable default encryption"}},
    },
    {
        "Id": "prowler-aws-s3_bucket_versioning-123456789012-eu-west-1-def",
        "Title": "S3 bucket versioning",
        "Description": "Passing check",
        "Severity": {"Label": "LOW"},
        "Resources": [{"Id": "arn:aws:s3:::my-bucket"}],
        "Compliance": {"Status": "PASSED"},
    },
]

CHECKOV_JSON = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_19",
                "check_name": "Ensure S3 bucket has server-side encryption enabled",
                "severity": "HIGH",
                "resource": "aws_s3_bucket.data",
                "file_path": "/main.tf",
                "file_line_range": [1, 10],
                "guideline": "https://docs.example/ckv-aws-19",
            }
        ]
    },
}

TRIVY_IMAGE_JSON = {
    "ArtifactName": "myrepo/app:latest",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "myrepo/app:latest (alpine 3.19)",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.1.0",
                    "FixedVersion": "3.1.1",
                    "Severity": "CRITICAL",
                    "Description": "A very bad bug",
                }
            ],
        }
    ],
}

TRIVY_FS_JSON = {
    "ArtifactName": "./iac",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "main.tf",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AVD-AWS-0088",
                    "Title": "S3 bucket encryption not enabled",
                    "Description": "Bucket does not have encryption enabled",
                    "Severity": "HIGH",
                    "Resolution": "Enable encryption",
                }
            ],
        }
    ],
}

SCOUTSUITE_JS = (
    "scoutsuite_results =\n"
    + json.dumps(
        {
            "services": {
                "s3": {
                    "findings": {
                        "s3-bucket-no-encryption": {
                            "description": "Bucket without encryption",
                            "rationale": "Data at rest should be encrypted",
                            "remediation": "Enable encryption",
                            "level": "danger",
                            "flagged_items": 1,
                            "items": ["arn:aws:s3:::my-bucket"],
                            "references": [],
                        }
                    }
                }
            }
        }
    )
    + ";"
)


# ─────────────────────────────────────────────────────────────────────
# Per-scanner parse_report
# ─────────────────────────────────────────────────────────────────────


def test_prowler_parse_report_file(tmp_path):
    report = tmp_path / "prowler.asff.json"
    report.write_text(json.dumps(PROWLER_ASFF))

    findings = ProwlerScanner.parse_report(str(report))

    # PASSED check is skipped
    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "prowler"
    assert f.severity == Severity.HIGH
    assert f.resource_arn == "arn:aws:s3:::my-bucket"
    assert "s3_bucket_default_encryption" in f.source_finding_id


def test_prowler_parse_report_directory(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "out.json").write_text(json.dumps(PROWLER_ASFF))

    findings = ProwlerScanner.parse_report(str(tmp_path))
    assert len(findings) == 1


def test_prowler_parse_report_jsonl(tmp_path):
    report = tmp_path / "prowler.jsonl"
    report.write_text("\n".join(json.dumps(item) for item in PROWLER_ASFF))

    findings = ProwlerScanner.parse_report(str(report))
    assert len(findings) == 1


def test_checkov_parse_report_file(tmp_path):
    report = tmp_path / "results_json.json"
    report.write_text(json.dumps(CHECKOV_JSON))

    findings = CheckovScanner.parse_report(str(report))
    assert len(findings) == 1
    assert findings[0].source_tool == "checkov"
    assert findings[0].source_finding_id == "CKV_AWS_19"


def test_checkov_parse_report_directory(tmp_path):
    (tmp_path / "results_json.json").write_text(json.dumps(CHECKOV_JSON))

    findings = CheckovScanner.parse_report(str(tmp_path))
    assert len(findings) == 1


def test_trivy_parse_report_image(tmp_path):
    report = tmp_path / "image.json"
    report.write_text(json.dumps(TRIVY_IMAGE_JSON))

    findings = TrivyScanner.parse_report(str(report))
    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "trivy"
    assert f.source_finding_id == "CVE-2024-0001"
    assert f.resource_id == "myrepo/app:latest"


def test_trivy_parse_report_filesystem(tmp_path):
    report = tmp_path / "fs.json"
    report.write_text(json.dumps(TRIVY_FS_JSON))

    findings = TrivyScanner.parse_report(str(report))
    assert len(findings) == 1
    assert findings[0].source_finding_id == "AVD-AWS-0088"


def test_trivy_parse_report_directory_mixed(tmp_path):
    (tmp_path / "image.json").write_text(json.dumps(TRIVY_IMAGE_JSON))
    (tmp_path / "fs.json").write_text(json.dumps(TRIVY_FS_JSON))

    findings = TrivyScanner.parse_report(str(tmp_path))
    assert len(findings) == 2


def test_scoutsuite_parse_report_file(tmp_path):
    report = tmp_path / "scoutsuite_results_aws.js"
    report.write_text(SCOUTSUITE_JS)

    findings = ScoutSuiteScanner.parse_report(str(report))
    assert len(findings) == 1
    assert findings[0].source_tool == "scoutsuite"
    assert findings[0].severity == Severity.CRITICAL


def test_scoutsuite_parse_report_directory(tmp_path):
    nested = tmp_path / "scoutsuite-report" / "scoutsuite-results"
    nested.mkdir(parents=True)
    (nested / "scoutsuite_results_aws-000000000000.js").write_text(SCOUTSUITE_JS)

    findings = ScoutSuiteScanner.parse_report(str(tmp_path))
    assert len(findings) == 1


# ─────────────────────────────────────────────────────────────────────
# Dispatch and multi-tool ingest
# ─────────────────────────────────────────────────────────────────────


def test_parse_report_unknown_tool(tmp_path):
    report = tmp_path / "x.json"
    report.write_text("{}")
    with pytest.raises(ValueError, match="Unsupported tool"):
        parse_report("nmap", str(report))


def test_parse_report_missing_path():
    with pytest.raises(FileNotFoundError):
        parse_report("prowler", "/nonexistent/report.json")


def test_ingest_reports_combination(tmp_path):
    (tmp_path / "prowler.json").write_text(json.dumps(PROWLER_ASFF))
    (tmp_path / "trivy.json").write_text(json.dumps(TRIVY_IMAGE_JSON))

    findings = ingest_reports(
        {
            "prowler": [tmp_path / "prowler.json"],
            "trivy": [tmp_path / "trivy.json"],
        }
    )
    assert len(findings) == 2
    assert {f.source_tool for f in findings} == {"prowler", "trivy"}


def test_ingest_reports_skips_bad_paths(tmp_path):
    (tmp_path / "prowler.json").write_text(json.dumps(PROWLER_ASFF))

    findings = ingest_reports(
        {
            "prowler": [tmp_path / "prowler.json"],
            "checkov": [tmp_path / "does-not-exist.json"],
        }
    )
    # The missing checkov path is logged and skipped, not fatal
    assert len(findings) == 1


# ─────────────────────────────────────────────────────────────────────
# Cross-scanner combination through the normaliser (equivalence rules)
# ─────────────────────────────────────────────────────────────────────


def test_ingested_findings_merge_via_equivalence_map(tmp_path):
    """Prowler + Checkov findings for the same check on the same resource
    merge into one via rules/check_equivalence.yaml."""
    from cloudg.normaliser import FindingsNormaliser

    prowler_asff = dict(PROWLER_ASFF[0])
    checkov_json = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    # Same canonical check (aws-s3-default-encryption) as
                    # prowler s3_bucket_default_encryption, and a check name
                    # that normalises to the same title.
                    "check_id": "CKV_AWS_19",
                    "check_name": "S3 bucket default encryption",
                    "severity": "HIGH",
                    "resource": "arn:aws:s3:::my-bucket",
                    "file_path": "/main.tf",
                }
            ]
        },
    }

    (tmp_path / "prowler.json").write_text(json.dumps([prowler_asff]))
    (tmp_path / "checkov.json").write_text(json.dumps(checkov_json))

    findings = ingest_reports(
        {"prowler": [tmp_path / "prowler.json"], "checkov": [tmp_path / "checkov.json"]}
    )
    assert len(findings) == 2

    result = FindingsNormaliser().normalise(findings)
    merged = [f for f in result.findings if "prowler" in f.source_tool]
    assert len(merged) == 1
    assert "checkov" in merged[0].source_tool


# ─────────────────────────────────────────────────────────────────────
# Engine integration
# ─────────────────────────────────────────────────────────────────────


def test_engine_run_from_reports(tmp_path):
    from cloudg.api import CloudGEngine
    from cloudg.config import CloudGConfig

    (tmp_path / "prowler.json").write_text(json.dumps(PROWLER_ASFF))
    (tmp_path / "checkov.json").write_text(json.dumps(CHECKOV_JSON))

    engine = CloudGEngine(CloudGConfig())
    out = tmp_path / "reports"
    result = engine.run_from_reports_sync(
        {
            "prowler": [tmp_path / "prowler.json"],
            "checkov": [tmp_path / "checkov.json"],
        },
        output_dir=out,
    )

    assert result.total_findings == 2
    assert result.scan_result is not None
    assert not result.errors
    assert "json" in result.report_paths and result.report_paths["json"].exists()
    assert "html" in result.report_paths and result.report_paths["html"].exists()
