"""collection_failed(): when does a run count as a complete collection failure."""

from __future__ import annotations

from cloudg.api import collection_failed
from cloudg.coverage import CollectionCoverage, ServiceStatus


def _cov(*records: tuple[str, ServiceStatus]) -> CollectionCoverage:
    cov = CollectionCoverage(provider="aws", account_id="123456789012", region="us-east-1")
    for service, status in records:
        cov.record(service, status)
    return cov


def test_target_record_failed():
    assert collection_failed([], [_cov(("aws_full", ServiceStatus.FAILED))])


def test_every_service_failed_although_target_says_partial():
    # No usable credentials: each collector fails on its own, aws_full is PARTIAL
    cov = _cov(
        ("ec2", ServiceStatus.FAILED),
        ("s3", ServiceStatus.FAILED),
        ("aws_full", ServiceStatus.PARTIAL),
    )
    assert collection_failed([], [cov])


def test_empty_but_readable_account_is_not_a_failure():
    cov = _cov(("ec2", ServiceStatus.SUCCESS), ("aws_full", ServiceStatus.SUCCESS))
    assert not collection_failed([], [cov])
    assert not collection_failed([], [_cov(("aws_full", ServiceStatus.SUCCESS))])


def test_one_service_succeeding_is_partial_collection():
    cov = _cov(
        ("ec2", ServiceStatus.FAILED),
        ("s3", ServiceStatus.PARTIAL),
        ("aws_full", ServiceStatus.PARTIAL),
    )
    assert not collection_failed([], [cov])


def test_assets_mean_no_failure():
    assert not collection_failed([object()], [_cov(("aws_full", ServiceStatus.FAILED))])


def test_failed_targets_name_a_target_whose_services_all_failed():
    from cloudg.api import failed_collection_targets

    cov = CollectionCoverage(provider="aws", account_id="123456789012", region="us-east-1")
    cov.record("ec2", ServiceStatus.FAILED, error="Unable to locate credentials")
    cov.record("s3", ServiceStatus.FAILED)
    cov.record("aws_full", ServiceStatus.PARTIAL)
    assert failed_collection_targets([cov]) == [
        "aws 123456789012/us-east-1: every service failed (Unable to locate credentials)"
    ]

    partly = CollectionCoverage(provider="aws", region="eu-west-1")
    partly.record("ec2", ServiceStatus.FAILED)
    partly.record("s3", ServiceStatus.SUCCESS)
    partly.record("aws_full", ServiceStatus.PARTIAL)
    assert failed_collection_targets([partly]) == []
