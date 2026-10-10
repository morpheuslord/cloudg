"""Compliance mapping in the normaliser: Prowler control ids, cross-scanner
merges, and PASS / FAIL control status."""

from __future__ import annotations

import pytest

from cloudg.normaliser import FindingList, FindingsNormaliser, prowler_check_id
from cloudg.schema.models import ComplianceStatus, Finding, Severity

RULESET = """
framework: TEST-FW
controls:
  - id: TF.1
    title: Buckets are encrypted
    checks: [s3_bucket_default_encryption]
  - id: TF.2
    title: Buckets are versioned
    checks: [s3_bucket_versioning]
  - id: TF.3
    title: Root has hardware MFA
    checks: [iam_root_hardware_mfa_enabled]
"""

EQUIVALENCE = """
equivalences:
  - id: aws-s3-default-encryption
    checks:
      prowler: [s3_bucket_default_encryption]
      checkov: [CKV_AWS_19]
"""

BUCKET = "arn:aws:s3:::my-bucket"


@pytest.fixture
def rules_dir(tmp_path):
    (tmp_path / "test_fw.yaml").write_text(RULESET)
    (tmp_path / "check_equivalence.yaml").write_text(EQUIVALENCE)
    return tmp_path


def _finding(src: str, tool: str = "prowler", **kw) -> Finding:
    base = {
        "resource_id": BUCKET,
        "resource_arn": BUCKET,
        "severity": Severity.MEDIUM,
        "title": "S3 bucket default encryption enabled",
        "description": "d",
        "source_tool": tool,
        "source_finding_id": src,
    }
    base.update(kw)
    return Finding(**base)


@pytest.mark.parametrize(
    "src,check",
    [
        (
            "prowler-aws-iam_root_hardware_mfa_enabled-123456789012-eu-west-1-abc",
            "iam_root_hardware_mfa_enabled",
        ),
        (
            "prowler-iam_root_hardware_mfa_enabled-123456789012-eu-west-1-abc",
            "iam_root_hardware_mfa_enabled",
        ),
        (
            "prowler-azure-defender_ensure_defender_is_on-sub-global-x",
            "defender_ensure_defender_is_on",
        ),
        ("prowler-s3_bucket_versioning", "s3_bucket_versioning"),
        ("s3_bucket_versioning", ""),
        ("CKV_AWS_19", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_prowler_check_id(src, check):
    assert prowler_check_id(src) == check


@pytest.mark.parametrize(
    "src",
    [
        "prowler-aws-iam_root_hardware_mfa_enabled-123456789012-eu-west-1-abc",
        "prowler-iam_root_hardware_mfa_enabled-123456789012-eu-west-1-abc",
    ],
)
def test_prowler_control_id_is_the_check_not_the_account(src):
    f = _finding(src, compliance_frameworks=["CIS"])
    assert FindingsNormaliser._extract_control_id(f, "CIS") == "CIS/iam_root_hardware_mfa_enabled"


def test_prowler_fallback_control_ids_group_accounts(tmp_path):
    """The same check in two accounts is one control, not one per account."""
    findings = [
        _finding(
            f"prowler-aws-iam_root_hardware_mfa_enabled-{acct}-eu-west-1-abc",
            resource_id=f"arn:aws:iam::{acct}:root",
            resource_arn=f"arn:aws:iam::{acct}:root",
            title="Root MFA",
            compliance_frameworks=["CIS"],
        )
        for acct in ("111111111111", "222222222222")
    ]
    # Empty rules dir: only scanner-native control ids
    result = FindingsNormaliser(rules_dir=tmp_path).normalise(findings)
    assert [c.control_id for c in result.compliance] == ["CIS/iam_root_hardware_mfa_enabled"]
    assert len(result.compliance[0].finding_ids) == 2


def test_cross_scanner_merge_keeps_both_scanners_mappings(rules_dir):
    """A Checkov finding that wins the merge still maps Prowler's check."""
    prowler = _finding("prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-a")
    checkov = _finding(
        "CKV_AWS_19",
        tool="checkov",
        severity=Severity.HIGH,
        title="[Checkov/terraform] S3 Bucket Default Encryption Enabled",
    )
    result = FindingsNormaliser(rules_dir=rules_dir).normalise([prowler], [checkov])

    assert len(result.findings) == 1
    survivor = result.findings[0]
    assert survivor.source_tool.startswith("checkov")  # higher severity survives
    assert "TEST-FW" in survivor.compliance_frameworks
    control = next(c for c in result.compliance if c.control_id == "TF.1")
    assert control.status == ComplianceStatus.FAIL
    assert control.finding_ids == [survivor.id]


def test_no_passed_checks_reports_only_failing_controls(rules_dir):
    f = _finding("prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-a")
    result = FindingsNormaliser(rules_dir=rules_dir).normalise([f])
    assert {(c.control_id, c.status) for c in result.compliance} == {
        ("TF.1", ComplianceStatus.FAIL)
    }


def test_passed_checks_give_pass_results(rules_dir):
    f = _finding("prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-a")
    result = FindingsNormaliser(rules_dir=rules_dir).normalise(
        [f],
        # A check that passed on another resource does not clear a failure
        passed_checks=["s3_bucket_versioning", "s3_bucket_default_encryption"],
    )
    by_control = {c.control_id: c for c in result.compliance}
    assert by_control["TF.1"].status == ComplianceStatus.FAIL
    assert by_control["TF.2"].status == ComplianceStatus.PASS
    assert by_control["TF.2"].control_title == "Buckets are versioned"
    assert by_control["TF.2"].finding_ids == []
    # Never assessed: no result at all
    assert "TF.3" not in by_control


def test_finding_list_carries_passed_checks(rules_dir):
    f = _finding("prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-a")
    findings = FindingList([f], passed_checks={"s3_bucket_versioning"})
    assert findings == [f]
    normaliser = FindingsNormaliser(rules_dir=rules_dir)
    result = normaliser.normalise(findings, [])
    statuses = {c.control_id: c.status for c in result.compliance}
    assert statuses == {"TF.1": ComplianceStatus.FAIL, "TF.2": ComplianceStatus.PASS}

    # Only passing checks: PASS results and no findings
    result = normaliser.normalise(FindingList(passed_checks={"iam_root_hardware_mfa_enabled"}))
    assert [(c.control_id, c.status) for c in result.compliance] == [
        ("TF.3", ComplianceStatus.PASS)
    ]


def _prowler_job(findings):
    from cloudg.api_scanners import ScanJob

    return ScanJob(
        name="prowler-aws", label="Prowler (aws)", scanner="prowler", fn=lambda: findings
    )


def test_engine_scan_plan_keeps_passed_checks(rules_dir):
    """Live scans hand Prowler's passing checks on to the normaliser."""
    from cloudg.api import CloudGEngine
    from cloudg.api_scanners import ScanPlan
    from cloudg.config import CloudGConfig

    f = _finding("prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-a")
    plan = ScanPlan(jobs=[_prowler_job(FindingList([f], passed_checks={"s3_bucket_versioning"}))])
    found = CloudGEngine(CloudGConfig())._run_scan_plan(plan)
    assert found == [f]
    assert found.passed_checks == {"s3_bucket_versioning"}

    result = FindingsNormaliser(rules_dir=rules_dir).normalise([], found, [])
    statuses = {c.control_id: c.status for c in result.compliance}
    assert statuses == {"TF.1": ComplianceStatus.FAIL, "TF.2": ComplianceStatus.PASS}


def test_cli_scan_outcome_keeps_passed_checks():
    from cloudg.cli_helpers import ScanOutcome

    f = _finding("prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-a")
    job = _prowler_job(None)
    outcome = ScanOutcome(results=[(job, FindingList([f], passed_checks={"s3_bucket_versioning"}))])
    selected = outcome.findings_of("iam", exclude=True)
    assert selected == [f]
    assert selected.passed_checks == {"s3_bucket_versioning"}
    assert outcome.findings_of("iam").passed_checks == set()
