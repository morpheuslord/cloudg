from cloudg.normaliser import FindingsNormaliser
from cloudg.schema.models import Finding, Severity

BUCKET = "arn:aws:s3:::orders-archive"

def finding(tool, check, title, severity, **extra):
    return Finding(resource_id=BUCKET, resource_arn=BUCKET, source_tool=tool,
                   source_finding_id=check, title=title, description=title,
                   severity=severity, **extra)

prowler = [
    finding("prowler", "prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-orders-archive",
            "S3 bucket default encryption", Severity.MEDIUM),
    # the same check reported twice (two output formats, say): a within-scanner duplicate
    finding("prowler", "prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-orders-archive",
            "S3 bucket default encryption", Severity.MEDIUM),
]
trivy = [
    # equivalent check (AVD-AWS-0088), same resource, same normalised title
    finding("trivy", "AVD-AWS-0088", "[Trivy] S3 bucket default encryption", Severity.HIGH),
    # a CVE with a CVSS score of 9.8 reported as MEDIUM
    finding("trivy", "CVE-2024-0001", "openssl: buffer overflow", Severity.MEDIUM, cvss_score=9.8),
]
untagged = [finding("custom", None, "CloudTrail logging disabled in eu-west-1", Severity.LOW)]

result = FindingsNormaliser().normalise(prowler, trivy, untagged)
for f in result.findings:
    print(f"{f.severity.value:8} {f.risk_score:4} {f.source_tool:16} {f.title} {f.compliance_frameworks[:4]}")
print(len(result.compliance), "compliance results")
