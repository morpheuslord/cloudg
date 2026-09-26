"""Tests for the findings normaliser and graph engine."""

from __future__ import annotations


from cloudg.normaliser import FindingsNormaliser
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)
from cloudg.graph.builder import GraphBuilder
from cloudg.graph.reachability import ReachabilityAnalyzer


# ── Normaliser Tests ──


class TestFindingsNormaliser:
    """Test the findings normaliser."""

    def _make_finding(
        self,
        resource_arn: str = "arn:aws:ec2::123:i-1",
        title: str = "Test Finding",
        severity: Severity = Severity.HIGH,
        source_tool: str = "prowler",
        cvss: float | None = None,
    ) -> Finding:
        return Finding(
            resource_id="r1",
            resource_arn=resource_arn,
            severity=severity,
            title=title,
            description="Test description",
            source_tool=source_tool,
            cvss_score=cvss,
        )

    def test_normalise_empty(self):
        """Test normalisation of empty findings."""
        normaliser = FindingsNormaliser()
        result = normaliser.normalise([], [])
        assert len(result.findings) == 0

    def test_normalise_single_finding(self):
        """Test normalisation of a single finding."""
        normaliser = FindingsNormaliser()
        finding = self._make_finding()
        result = normaliser.normalise([finding])
        assert len(result.findings) == 1

    def test_deduplication_same_resource_and_title(self):
        """Test that duplicate findings (same ARN + title) are merged."""
        normaliser = FindingsNormaliser()
        f1 = self._make_finding(source_tool="prowler")
        f2 = self._make_finding(source_tool="scoutsuite")

        result = normaliser.normalise([f1], [f2])
        assert len(result.findings) == 1
        # Source tools should be merged
        assert "prowler" in result.findings[0].source_tool
        assert "scoutsuite" in result.findings[0].source_tool

    def test_deduplication_different_titles(self):
        """Test that different titles are not deduplicated."""
        normaliser = FindingsNormaliser()
        f1 = self._make_finding(title="Finding A")
        f2 = self._make_finding(title="Finding B")

        result = normaliser.normalise([f1, f2])
        assert len(result.findings) == 2

    def test_severity_ordering(self):
        """Test that findings are sorted by severity."""
        normaliser = FindingsNormaliser()
        findings = [
            self._make_finding(title="Low", severity=Severity.LOW),
            self._make_finding(title="Critical", severity=Severity.CRITICAL),
            self._make_finding(title="Medium", severity=Severity.MEDIUM),
        ]
        result = normaliser.normalise(findings)
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[1].severity == Severity.MEDIUM
        assert result.findings[2].severity == Severity.LOW

    def test_cvss_severity_promotion(self):
        """Test that high CVSS score promotes severity to CRITICAL."""
        normaliser = FindingsNormaliser()
        finding = self._make_finding(severity=Severity.MEDIUM, cvss=9.5)
        result = normaliser.normalise([finding])
        assert result.findings[0].severity == Severity.CRITICAL

    def test_compliance_auto_mapping(self):
        """Test auto-mapping of findings to compliance frameworks."""
        normaliser = FindingsNormaliser()
        finding = Finding(
            resource_id="r1",
            severity=Severity.HIGH,
            title="S3 bucket public access",
            description="S3 bucket with public access enabled. Encryption disabled.",
            source_tool="prowler",
        )
        result = normaliser.normalise([finding])
        frameworks = result.findings[0].compliance_frameworks
        # Should auto-map to CIS (s3.*public) and possibly NIST (encryption)
        assert len(frameworks) > 0

    def test_compliance_results_generated(self):
        """Test that ComplianceResult entries are generated."""
        normaliser = FindingsNormaliser()
        finding = Finding(
            resource_id="r1",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            source_tool="prowler",
            compliance_frameworks=["CIS", "NIST-800-53"],
        )
        result = normaliser.normalise([finding])
        assert len(result.compliance) > 0
        framework_names = [c.framework for c in result.compliance]
        assert "CIS" in framework_names


# ── Graph Builder Tests ──


class TestGraphBuilder:
    """Test the graph builder."""

    def _make_assets(self) -> list[CloudAsset]:
        return [
            CloudAsset(
                id="vpc-1",
                name="test-vpc",
                asset_type=AssetType.VPC,
                provider=CloudProvider.AWS,
            ),
            CloudAsset(
                id="subnet-1",
                name="test-subnet",
                asset_type=AssetType.SUBNET,
                provider=CloudProvider.AWS,
                metadata={"vpc_id": "vpc-1"},
            ),
            CloudAsset(
                id="ec2-1",
                name="test-instance",
                asset_type=AssetType.EC2,
                provider=CloudProvider.AWS,
                metadata={"vpc_id": "vpc-1"},
            ),
            CloudAsset(
                id="rds-1",
                name="test-db",
                asset_type=AssetType.RDS_INSTANCE,
                provider=CloudProvider.AWS,
            ),
        ]

    def _make_edges(self) -> list[NetworkEdge]:
        return [
            NetworkEdge(
                source_id="vpc-1",
                target_id="subnet-1",
                edge_type=EdgeType.CONTAINS,
            ),
            NetworkEdge(
                source_id="0.0.0.0/0",
                target_id="ec2-1",
                edge_type=EdgeType.SECURITY_GROUP_RULE,
                cidr="0.0.0.0/0",
                ports=[22],
                protocol="TCP",
            ),
            NetworkEdge(
                source_id="ec2-1",
                target_id="rds-1",
                edge_type=EdgeType.SECURITY_GROUP_RULE,
                ports=[3306],
                protocol="TCP",
            ),
        ]

    def test_build_graph(self):
        """Test basic graph construction."""
        builder = GraphBuilder()
        graph = builder.build(self._make_assets(), self._make_edges())
        assert graph.number_of_nodes() >= 4
        assert graph.number_of_edges() >= 3

    def test_d3_json_export(self):
        """Test D3.js JSON export format."""
        builder = GraphBuilder()
        builder.build(self._make_assets(), self._make_edges())
        d3_json = builder.to_d3_json()
        assert "nodes" in d3_json
        assert "links" in d3_json
        assert len(d3_json["nodes"]) >= 4
        assert len(d3_json["links"]) >= 3

    def test_d3_node_format(self):
        """Test D3.js node data format."""
        builder = GraphBuilder()
        builder.build(self._make_assets(), self._make_edges())
        d3_json = builder.to_d3_json()
        node = next(n for n in d3_json["nodes"] if n["id"] == "ec2-1")
        assert node["name"] == "test-instance"
        assert node["type"] == "EC2"

    def test_centrality_metrics(self):
        """Test centrality computation."""
        builder = GraphBuilder()
        builder.build(self._make_assets(), self._make_edges())
        metrics = builder.compute_centrality()
        assert "ec2-1" in metrics
        assert "degree" in metrics["ec2-1"]

    def test_external_nodes_created(self):
        """Test that external nodes (e.g., 0.0.0.0/0) are created for edges."""
        builder = GraphBuilder()
        graph = builder.build(self._make_assets(), self._make_edges())
        assert "0.0.0.0/0" in graph.nodes()
        assert graph.nodes["0.0.0.0/0"].get("is_external") is True


# ── Reachability Analyzer Tests ──


class TestReachabilityAnalyzer:
    """Test the reachability analyzer."""

    def _build_graph(self) -> GraphBuilder:
        builder = GraphBuilder()
        assets = [
            CloudAsset(
                id="ec2-1",
                name="web-server",
                asset_type=AssetType.EC2,
                provider=CloudProvider.AWS,
            ),
            CloudAsset(
                id="rds-1",
                name="database",
                asset_type=AssetType.RDS_INSTANCE,
                provider=CloudProvider.AWS,
            ),
            CloudAsset(
                id="lb-1",
                name="load-balancer",
                asset_type=AssetType.LOAD_BALANCER,
                provider=CloudProvider.AWS,
            ),
        ]
        edges = [
            NetworkEdge(
                source_id="0.0.0.0/0",
                target_id="lb-1",
                edge_type=EdgeType.SECURITY_GROUP_RULE,
                cidr="0.0.0.0/0",
                ports=[443],
            ),
            NetworkEdge(
                source_id="lb-1",
                target_id="ec2-1",
                edge_type=EdgeType.LOAD_BALANCER_TARGET,
            ),
            NetworkEdge(
                source_id="ec2-1",
                target_id="rds-1",
                edge_type=EdgeType.SECURITY_GROUP_RULE,
                ports=[3306],
            ),
        ]
        builder.build(assets, edges)
        return builder

    def test_find_internet_exposed(self):
        """Test identification of internet-exposed nodes."""
        builder = self._build_graph()
        analyzer = ReachabilityAnalyzer(builder.graph)
        exposed = analyzer.find_internet_exposed()
        assert "lb-1" in exposed
        assert "ec2-1" in exposed
        assert "rds-1" in exposed

    def test_blast_radius(self):
        """Test blast radius computation."""
        builder = self._build_graph()
        analyzer = ReachabilityAnalyzer(builder.graph)
        radius = analyzer.compute_blast_radius("lb-1")
        assert len(radius["reachable_nodes"]) >= 2
        assert "ec2-1" in radius["reachable_nodes"]
        assert "rds-1" in radius["reachable_nodes"]
        assert radius["risk_score"] > 0

    def test_generate_findings(self):
        """Test reachability finding generation."""
        builder = self._build_graph()
        analyzer = ReachabilityAnalyzer(builder.graph)
        findings = analyzer.generate_findings()

        # Should find RDS exposed (CRITICAL) and EC2 (HIGH)
        assert len(findings) > 0
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities

    def test_no_findings_for_unexposed(self):
        """Test that isolated nodes don't produce findings."""
        builder = GraphBuilder()
        assets = [
            CloudAsset(
                id="ec2-isolated",
                name="isolated",
                asset_type=AssetType.EC2,
                provider=CloudProvider.AWS,
            ),
        ]
        builder.build(assets, [])
        analyzer = ReachabilityAnalyzer(builder.graph)
        findings = analyzer.generate_findings()
        assert len(findings) == 0
