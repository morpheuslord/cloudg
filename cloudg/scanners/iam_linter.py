"""IAM policy linter using Parliament and policy-sentry."""

from __future__ import annotations

import json
import logging

from cloudg.schema.models import CloudAsset, AssetType, Finding, Severity

logger = logging.getLogger(__name__)


class IAMLinter:
    """Analyses IAM policies using Parliament for linting and policy-sentry for least-privilege scoring.

    Parliament: Detects wildcard abuse, logical errors, unused conditions.
    Policy-sentry: Scores how over-permissioned policies are.
    """

    def __init__(self) -> None:
        self._parliament_available = False
        self._policy_sentry_available = False
        self._check_availability()

    def _check_availability(self) -> None:
        """Check which IAM analysis tools are available."""
        try:
            import parliament  # noqa: F401
            self._parliament_available = True
        except ImportError:
            logger.warning(
                "parliament not installed. Install with: pip install parliament"
            )

        try:
            import policy_sentry  # noqa: F401
            self._policy_sentry_available = True
        except ImportError:
            logger.debug(
                "policy-sentry not installed. Install with: pip install policy-sentry"
            )

    def analyze_policies(self, assets: list[CloudAsset]) -> list[Finding]:
        """Analyse all IAM policy assets.

        Args:
            assets: List of cloud assets (filters for IAM_POLICY and IAM_ROLE types).

        Returns:
            List of Finding objects for IAM policy issues.
        """
        findings: list[Finding] = []

        iam_assets = [
            a for a in assets
            if a.asset_type in (AssetType.IAM_POLICY, AssetType.IAM_ROLE)
        ]

        for asset in iam_assets:
            policy_doc = asset.metadata.get("assume_role_policy") or asset.metadata.get("policy_document")
            if not policy_doc:
                continue

            # Ensure it's a JSON string
            if isinstance(policy_doc, dict):
                policy_str = json.dumps(policy_doc)
            else:
                policy_str = str(policy_doc)

            # Run Parliament linting
            if self._parliament_available:
                findings.extend(self._lint_with_parliament(policy_str, asset))

            # Check for wildcard permissions
            findings.extend(self._check_wildcards(policy_str, asset))

        logger.info("IAM linter produced %d findings", len(findings))
        return findings

    def _lint_with_parliament(
        self, policy_str: str, asset: CloudAsset
    ) -> list[Finding]:
        """Run Parliament linter on a policy document."""
        findings: list[Finding] = []

        try:
            import parliament

            analyzed = parliament.analyze_policy_string(policy_str)

            for finding in analyzed.findings:
                severity = self._map_parliament_severity(finding.severity)
                findings.append(
                    Finding(
                        resource_id=asset.id,
                        resource_arn=asset.arn,
                        severity=severity,
                        title=f"[Parliament] IAM policy issue: {finding.issue}",
                        description=finding.detail if hasattr(finding, 'detail') else str(finding),
                        evidence=f"Policy: {asset.name}, Issue: {finding.issue}",
                        remediation=(
                            "Review and fix the IAM policy. Follow least-privilege "
                            "principles. Use policy-sentry to generate scoped policies."
                        ),
                        source_tool="parliament",
                        compliance_frameworks=["CIS", "NIST-800-53"],
                    )
                )
        except Exception as exc:
            logger.debug("Parliament analysis failed for %s: %s", asset.name, exc)

        return findings

    def _check_wildcards(
        self, policy_str: str, asset: CloudAsset
    ) -> list[Finding]:
        """Check for wildcard permissions (Action: * or Resource: *)."""
        findings: list[Finding] = []

        try:
            policy = json.loads(policy_str)
        except json.JSONDecodeError:
            return findings

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect", "")
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            # Check for wildcard actions
            if effect == "Allow" and "*" in actions:
                findings.append(
                    Finding(
                        resource_id=asset.id,
                        resource_arn=asset.arn,
                        severity=Severity.HIGH,
                        title=f"Wildcard Action (*) in IAM policy: {asset.name}",
                        description=(
                            f"The IAM policy '{asset.name}' grants 'Action: *' "
                            f"(all actions). This violates least-privilege principles."
                        ),
                        evidence=f"Statement: {json.dumps(statement)[:500]}",
                        remediation=(
                            "Replace 'Action: *' with specific actions required "
                            "by the workload. Use AWS Access Advisor to identify "
                            "unused permissions."
                        ),
                        source_tool="cloudg-iam",
                        compliance_frameworks=["CIS", "NIST-800-53", "SOC2"],
                    )
                )

            # Check for wildcard resources with sensitive actions
            if effect == "Allow" and "*" in resources:
                sensitive_prefixes = ("iam:", "sts:", "kms:", "s3:", "ec2:", "lambda:")
                has_sensitive = any(
                    any(a.startswith(p) for p in sensitive_prefixes)
                    for a in actions if isinstance(a, str) and a != "*"
                )

                if has_sensitive or "*" in actions:
                    findings.append(
                        Finding(
                            resource_id=asset.id,
                            resource_arn=asset.arn,
                            severity=Severity.HIGH,
                            title=f"Wildcard Resource (*) in IAM policy: {asset.name}",
                            description=(
                                f"The IAM policy '{asset.name}' grants access to "
                                f"'Resource: *' (all resources) for sensitive actions."
                            ),
                            evidence=f"Statement: {json.dumps(statement)[:500]}",
                            remediation=(
                                "Scope 'Resource' to specific ARN patterns. "
                                "Use conditions to further restrict access."
                            ),
                            source_tool="cloudg-iam",
                            compliance_frameworks=["CIS", "NIST-800-53"],
                        )
                    )

        return findings

    @staticmethod
    def _map_parliament_severity(severity: str) -> Severity:
        """Map Parliament severity to our Severity enum."""
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
            "WARNING": Severity.MEDIUM,
        }
        return mapping.get(str(severity).upper(), Severity.MEDIUM)
