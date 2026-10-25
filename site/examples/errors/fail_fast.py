import asyncio
import sys

from cloudg import CloudGConfig, CloudGEngine

class PhaseFailed(RuntimeError):
    pass

async def main() -> int:
    engine = CloudGEngine(CloudGConfig(providers=["aws"]))
    failures: list[tuple[str, Exception]] = []
    engine.on_error = lambda phase, exc: failures.append((phase, exc))

    def checkpoint(step: str) -> None:
        if failures:
            phase, exc = failures[0]
            raise PhaseFailed(f"{phase} failed during {step}: {exc}")

    collection = await engine.collect()
    checkpoint("collection")
    broken = [c.to_summary() for c in collection.coverage if c.failed_services]
    if broken or not collection.assets:
        raise PhaseFailed(f"collection incomplete: {broken or 'no assets'}")

    findings = await engine.scan(collection.assets, collection.edges, output_dir="./reports")
    checkpoint("scanning")

    analysis = await engine.analyze(collection.assets, collection.edges, findings, "./reports")
    checkpoint("analysis")

    scan_result = engine.normalise_findings(
        findings + analysis.reachability_findings, assets=collection.assets
    )
    print(scan_result.summary)
    return 0

try:
    sys.exit(asyncio.run(main()))
except PhaseFailed as exc:
    print(f"cloudg: {exc}", file=sys.stderr)
    sys.exit(2)
