"""Write one small native report per scanner, shaped like the real tools' output."""
import json
from pathlib import Path

Path("prowler-output").mkdir(exist_ok=True)
Path("prowler-output/prowler-output-123456789012.asff.json").write_text(json.dumps([
    {
        "Id": "prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-abc",
        "Title": "S3 bucket default encryption",
        "Description": "Bucket has no default encryption",
        "Severity": {"Label": "HIGH"},
        "Resources": [{"Id": "arn:aws:s3:::my-bucket"}],
        "Compliance": {"Status": "FAILED", "RelatedRequirements": ["CIS 2.1.1"]},
        "Remediation": {"Recommendation": {"Text": "Enable default encryption"}},
    }
]))

results = Path("scoutsuite-report/scoutsuite-results")
results.mkdir(parents=True, exist_ok=True)
(results / "scoutsuite_results_aws-123456789012.js").write_text(
    "scoutsuite_results =\n" + json.dumps({
        "services": {"s3": {"findings": {"s3-bucket-no-encryption": {
            "description": "Bucket without encryption",
            "rationale": "Data at rest should be encrypted",
            "remediation": "Enable encryption",
            "level": "danger",
            "flagged_items": 1,
            "items": ["s3.buckets.my-bucket"],
            "references": [],
        }}}}
    })
)

Path("results_json.json").write_text(json.dumps({
    "check_type": "terraform",
    "results": {"failed_checks": [{
        "check_id": "CKV_AWS_19",
        "check_name": "Ensure S3 bucket has server-side encryption enabled",
        "severity": "HIGH",
        "resource": "aws_s3_bucket.data",
        "file_path": "/main.tf",
        "file_line_range": [1, 10],
        "guideline": "https://docs.example/ckv-aws-19",
    }]},
}))

Path("trivy-image.json").write_text(json.dumps({
    "ArtifactName": "myrepo/app:latest",
    "ArtifactType": "container_image",
    "Results": [{
        "Target": "myrepo/app:latest (alpine 3.19)",
        "Type": "alpine",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-0001",
            "PkgName": "openssl",
            "InstalledVersion": "3.1.0",
            "FixedVersion": "3.1.1",
            "Severity": "CRITICAL",
            "Description": "Example vulnerability",
            "CVSS": {"nvd": {"V3Score": 9.8}},
        }],
    }],
}))

Path("trivy-fs.json").write_text(json.dumps({
    "ArtifactName": "./iac",
    "ArtifactType": "filesystem",
    "Results": [{
        "Target": "main.tf",
        "Type": "terraform",
        "Misconfigurations": [{
            "ID": "AVD-AWS-0088",
            "Title": "S3 bucket encryption not enabled",
            "Description": "Bucket does not have encryption enabled",
            "Severity": "HIGH",
            "Resolution": "Enable encryption",
        }],
    }],
}))
print("sample reports written")
