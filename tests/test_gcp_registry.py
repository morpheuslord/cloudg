"""The GCP extractor registry runs every extractor registered for a type."""

from __future__ import annotations

from cloudg.inventory.gcp_relations import EXTRACTORS, GCPContext, extract
from cloudg.inventory.gcp_relations.context import _extractor
from cloudg.schema.models import EdgeType

_TYPE = "widgets.googleapis.com/Widget"


def test_second_extractor_appends_instead_of_replacing():
    calls: list[str] = []

    @_extractor(_TYPE)
    def first(ctx, out):
        calls.append("first")
        out.add("//widgets.googleapis.com/a", EdgeType.REFERENCES, "DEPENDS_ON")

    @_extractor(_TYPE)
    def second(ctx, out):
        calls.append("second")
        out.metadata["second"] = True

    @_extractor(_TYPE)
    def broken(ctx, out):
        raise ValueError("bad shape")

    @_extractor(_TYPE)
    def after_broken(ctx, out):
        out.alias("widget-alias")

    try:
        _extractor(_TYPE)(first)  # registering twice is a no-op
        assert EXTRACTORS[_TYPE] == [first, second, broken, after_broken]
        out = extract(GCPContext(name="//widgets.googleapis.com/w", asset_type=_TYPE, data={}))
        assert calls == ["first", "second"]
        assert out.relations[0]["target"] == "//widgets.googleapis.com/a"
        assert out.metadata["second"] is True
        assert out.aliases == ["widget-alias"]
        assert "ValueError: bad shape" in out.metadata["extraction_error"]
    finally:
        EXTRACTORS.pop(_TYPE, None)


def test_registry_values_are_lists():
    assert EXTRACTORS
    assert all(isinstance(v, list) and v for v in EXTRACTORS.values())
