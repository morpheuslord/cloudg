"""Check credentials before a run, and sort what the run reports by type."""

import sys

from cloudg import CloudGConfig, CloudGEngine
from cloudg.credentials import build_aws_session
from cloudg.exceptions import (
    CloudGError,
    CredentialError,
    ProviderSDKMissingError,
    ScannerFailed,
)

config = CloudGConfig(providers=["aws"])
config.aws.profile = "audit"
config.aws.regions = ["eu-west-1"]

# The engine records collection failures instead of raising them, so a
# missing SDK or a refused role is easiest to catch before the run starts.
try:
    build_aws_session(config.aws, "eu-west-1")
except ProviderSDKMissingError as exc:
    sys.exit(f"{exc.missing} is not installed: pip install 'cloudg[{exc.extra}]'")
except CredentialError as exc:  # a role assumption failed, or no role to reach an account
    sys.exit(f"{exc.provider} credentials were refused: {exc.detail}")
except Exception as exc:  # SDK errors pass through untouched (botocore's ProfileNotFound, ...)
    sys.exit(f"{type(exc).__name__}: {exc}")


def on_error(phase: str, exc: Exception) -> None:
    if isinstance(exc, ScannerFailed):
        print(f"{phase}: kept {len(exc.findings)} partial findings ({exc})")
    elif isinstance(exc, CloudGError):
        print(f"{phase}: {type(exc).__name__}: {exc}")
    else:  # SDK and OS errors pass through untouched
        print(f"{phase}: unexpected {type(exc).__name__}: {exc}")


engine = CloudGEngine(config)
engine.on_error = on_error
result = engine.run_pipeline_sync(output_dir="./reports")
print(result.errors or "complete run")
