"""Regression tests for privacy-layer bugs found by exercising the full
catalog end to end (sample estate from ``tests/mcp/fixtures``)."""

from __future__ import annotations

import json
import re

import pytest

from cloudg.mcp.context import Principal
from cloudg.mcp.core import (
    NotFoundError,
    AccessDeniedError,
    Capability,
    InvalidArgumentsError,
    PromptSpec,
    RateLimitedError,
    ToolSpec,
    render_json,
)
from cloudg.mcp.layer import CloudGMCPLayer
from cloudg.mcp import policy as policy_mod
from cloudg.mcp.policy import Policy, PolicyConfig, _aliases_after_redaction
from cloudg.mcp.transforms import (
    DEFAULT_REGISTRY,
    AliasMap,
    Depseudonymizer,
    Redactor,
    TokenVault,
    TransformContext,
)
from cloudg.mcp.transforms.detectors import account_entity

ANALYST = Principal(id="ann", roles={"analyst"})
LEAD = Principal(id="lee", roles={"lead"})
COLLECTOR = Principal(id="svc", roles={"collector"})
STRICT_MAP = {
    "identifier": "pseudonymize",
    "uuid": "keep",
    "network": "pseudonymize",
    "special_ip": "keep",
    "special_cidr": "keep",
    "pii": "pseudonymize",
    "free_text": "pseudonymize",
    "secret": "redact",
}


def make(workspace, policy):
    return CloudGMCPLayer(policy=policy, workspace=workspace)


def tool(name="t", caps=(Capability.READ_STATE,)):
    return ToolSpec(name=name, handler=lambda ctx: None, capabilities=set(caps))


# ---------------------------------------------------------------------------
# 1. aliases compose with pseudonymisation (soc-analyst)
# ---------------------------------------------------------------------------


async def test_soc_analyst_aliases_and_pseudonyms(workspace):
    layer = make(workspace, "soc-analyst")
    res = await layer.call_tool("get_asset", {"ref": "web-1"}, principal=ANALYST)
    assert not res.is_error, res.content[0].text
    a = res.structured
    assert a["account_id"] == "prod-payments"
    m = re.fullmatch(r"arn:aws:ec2:us-east-1:prod-payments:instance/(res-[0-9a-f]{10})", a["arn"])
    assert m, a["arn"]
    text = res.content[0].text
    assert "i-0web1" not in text and "awsaccount" not in text and "111111111111" not in text
    # alias passed back resolves to the real account
    by_alias = await layer.call_tool(
        "find_assets", {"account_id": "prod-payments"}, principal=ANALYST
    )
    by_real = await layer.call_tool("find_assets", {"account_id": "111111111111"}, principal=LEAD)
    assert by_alias.structured["total"] == by_real.structured["total"] > 0
    # the aliased, pseudonymised ARN resolves to the same asset
    again = await layer.call_tool("get_asset", {"ref": a["arn"]}, principal=ANALYST)
    assert not again.is_error and again.structured["id"] == a["id"]
    # the lead sees real identifiers with the alias applied
    lead = (await layer.call_tool("get_asset", {"ref": "web-1"}, principal=LEAD)).structured
    assert lead["arn"] == "arn:aws:ec2:us-east-1:prod-payments:instance/i-0web1"


def test_aliases_moved_after_redaction():
    specs = [
        {"type": "alias", "id": "a", "options": {}},
        {"type": "sanitize", "id": "s", "options": {}},
        {"type": "redact", "id": "r", "options": {}},
        {"type": "project", "id": "p", "options": {}},
    ]
    assert [s["id"] for s in _aliases_after_redaction(specs)] == ["s", "r", "a", "p"]
    no_redact = [specs[0], specs[1]]
    assert _aliases_after_redaction(no_redact) == no_redact


def test_alias_map_labels_pseudonyms_and_depseudonymizer_order():
    vault = TokenVault("k")
    ctx = TransformContext(vault=vault)
    red = Redactor(STRICT_MAP)
    amap = AliasMap({"111111111111": "prod"})
    arn = "arn:aws:ec2:us-east-1:111111111111:instance/i-0abc1234def567890"
    out = amap.apply(red.apply({"account_id": "111111111111", "arn": arn}, ctx), ctx)
    assert out["account_id"] == "prod"
    assert out["arn"].startswith("arn:aws:ec2:us-east-1:prod:instance/i-")
    dep = Depseudonymizer(vault, aliases=[amap])
    back = dep.apply({"a": out["arn"], "b": "prod"}, TransformContext(vault=vault))
    assert back == {"a": arn, "b": "111111111111"}
    # an exact token whose text contains an alias-like word is reversed first
    tok = vault.tokenize("my-prod-db", "resource_name")
    assert dep.apply(tok, TransformContext(vault=vault)) == "my-prod-db"


# ---------------------------------------------------------------------------
# 2. strict hides names under every reference key
# ---------------------------------------------------------------------------

SAMPLE_NAMES = ("web-1", "app-role", "sg-app", "prod-private-a", "web-tg", "i-0web1")


async def test_strict_get_asset_leaks_no_names(workspace):
    layer = make(workspace, "strict")
    res = await layer.call_tool("get_asset", {"ref": "web-1"})
    assert not res.is_error, res.content[0].text
    text = res.content[0].text
    for name in SAMPLE_NAMES:
        assert f'"{name}"' not in text and f"/{name}" not in text, name
    a = res.structured
    assert a["uri"] == f"cloudg://assets/{a['id']}"
    assert a["dataset"].startswith("ds-")
    for edge in a["relations"]["sample"]:
        assert edge["source"].startswith("res-") and edge["target"].startswith("res-")
    # reference tokens resolve back
    for ref in (a["id"], a["uri"].rsplit("/", 1)[1], a["arn"]):
        again = await layer.call_tool("get_asset", {"ref": ref})
        assert not again.is_error and again.structured["id"] == a["id"]


async def test_strict_path_summaries_and_findings(workspace):
    layer = make(workspace, "strict")
    res = await layer.call_tool("find_paths", {"source": "web-1", "target": "app-role"})
    assert not res.is_error, res.content[0].text
    for name in SAMPLE_NAMES:
        assert name not in res.content[0].text, name
    findings = await layer.call_tool("list_findings", {})
    for name in SAMPLE_NAMES:
        assert f'"{name}"' not in findings.content[0].text, name


def test_reference_keys_defer_to_detectors():
    vault = TokenVault("k")
    red = Redactor(STRICT_MAP)
    arn = "arn:aws:iam::123456789012:role/app-role"
    out = red.apply(
        {
            "source": "0.0.0.0/0",
            "target": arn,
            "asset_name": "web-1",
            "source_name": "web-1",
            "ref": "10.0.1.5",
            "datasets": ["prod", "dev"],
            "nodes": ["a-1", {"id": "x", "arn": arn}],
        },
        TransformContext(vault=vault),
    )
    assert out["source"] == "0.0.0.0/0"  # special CIDR keeps its own treatment
    assert out["target"] == vault.tokenize(arn, "aws_arn")  # an ARN pseudonym, not res-
    assert out["asset_name"] == out["source_name"] == vault.tokenize("web-1", "resource_name")
    assert out["ref"] == vault.tokenize("10.0.1.5", "private_ip")
    assert all(d.startswith("ds-") for d in out["datasets"])
    assert out["nodes"][0].startswith("res-") and out["nodes"][1]["id"].startswith("res-")


def test_name_mentions_in_free_text():
    vault = TokenVault("k")
    red = Redactor(STRICT_MAP)
    out = red.apply(
        {
            "nodes": [{"name": "web-1", "arn": "x"}],
            "summary": "web-1 -> db-main",
            "other": {"name": "db-main", "provider": "aws"},
            "single": "web-1",
            "type": "web-1",
            "tags": {"Team": "web-1"},
        },
        TransformContext(vault=vault),
    )
    tok_web, tok_db = (
        vault.lookup("web-1", "resource_name"),
        vault.lookup("db-main", "resource_name"),
    )
    assert out["summary"] == f"{tok_web} -> {tok_db}"
    assert out["single"] == tok_web  # exact whole-value mentions are replaced too
    assert out["type"] == "web-1"  # vocabulary keys are left alone
    assert out["tags"]["Team"].startswith("tag-")  # tag values keep their own token
    assert (
        Redactor(STRICT_MAP, name_mentions=False).apply(
            {"n": {"name": "web-1", "arn": "x"}, "s": "web-1 -> x"}, TransformContext(vault=vault)
        )["s"]
        == "web-1 -> x"
    )


# ---------------------------------------------------------------------------
# 3. completions
# ---------------------------------------------------------------------------


async def test_strict_completions_pseudonymised_and_reversible(workspace):
    layer = make(workspace, "strict")
    refs = await layer.complete(
        {"type": "ref/resource", "uri": "cloudg://assets/{+ref}"}, {"name": "ref", "value": "web"}
    )
    assert refs["values"] and all(v.startswith(("res-", "arn:")) for v in refs["values"])
    assert "web-1" not in refs["values"]
    contents = await layer.read_resource(f"cloudg://assets/{refs['values'][0]}")
    assert json.loads(contents[0].text)["id"].startswith("res-")
    ds = await layer.complete(
        {"type": "ref/resource", "uri": "cloudg://datasets/{dataset}/summary"},
        {"name": "dataset", "value": ""},
    )
    assert ds["values"] and ds["values"][0].startswith("ds-")
    summary = await layer.read_resource(f"cloudg://datasets/{ds['values'][0]}/summary")
    assert json.loads(summary[0].text)["dataset"] == ds["values"][0]


# ---------------------------------------------------------------------------
# 4. policy descriptions are not mangled by the caller's redactor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["standard", "strict"])
async def test_privacy_status_and_policy_resource_readable(workspace, profile):
    layer = make(workspace, profile)
    st = await layer.call_tool("privacy_status", {})
    assert "REDACTED" not in st.content[0].text
    red = next(s for s in st.structured["output_pipeline"] if s["type"] == "redact")
    assert {"applies_to": "secret", "strategy": "redact"} in red["strategies"]
    pol = (await layer.read_resource("cloudg://policy"))[0].text
    assert "REDACTED" not in pol and "res-" not in pol
    doc = json.loads(pol)
    strategies = doc["transforms"][1]["options"]["strategies"]
    assert any(s["applies_to"] == "secret" for s in strategies)
    if profile == "standard":
        cred = next(s for s in strategies if s["applies_to"] == "credential")
        assert cred == {
            "applies_to": "credential",
            "strategy": "mask",
            "options": {"keep_first": 4, "keep_last": 4},
        }
    det = await layer.call_tool("list_detectors", {})
    assert "REDACTED" not in det.content[0].text


async def test_reveal_output_not_redacted(workspace):
    layer = make(workspace, "soc-analyst")
    a = (await layer.call_tool("get_asset", {"ref": "web-1"}, principal=ANALYST)).structured
    rev = await layer.call_tool("reveal_token", {"token": a["id"]}, principal=LEAD)
    assert not rev.is_error, rev.content[0].text
    assert rev.structured == {
        "pseudonym": a["id"],
        "found": True,
        "value": "web-1",
        "entity_type": "resource_name",
    }


# ---------------------------------------------------------------------------
# 5-9
# ---------------------------------------------------------------------------


def test_budget_measured_like_the_layer_renders():
    from cloudg.mcp.transforms import Projection

    data = {"items": [{"name": "é" * 40, "n": i} for i in range(300)]}
    ctx = TransformContext()
    out = Projection(max_chars=5_000).apply(data, ctx)
    assert ctx.report["projection"]["budget"]["final_chars"] == len(render_json(out)) <= 5_000


def test_audit_size_zero_disables_ring_buffer():
    p = Policy.load({"name": "a", "audit": True, "audit_size": 0, "deny_tools": ["bad"]})
    p.check_call(tool("ok"), None, {})
    with pytest.raises(AccessDeniedError):
        p.check_call(tool("bad"), None, {})
    assert p.audit_log.maxlen == 0 and len(p.audit_log) == 0


def test_save_vault_and_exit_hook(tmp_path):
    path = tmp_path / "v.json"
    p = Policy.load({"extends": "strict", "name": "s", "vault": {"key": "k", "path": str(path)}})
    ctx = TransformContext(vault=p.vault)
    p.output_pipeline(tool(), None).apply({"arn": "arn:aws:s3:::bucket-a"}, ctx)
    assert not path.exists()  # no autosave
    assert p.save_vault() == path and path.exists()
    assert not p.vault.dirty
    p.output_pipeline(tool(), None).apply({"arn": "arn:aws:s3:::bucket-b"}, ctx)
    assert p.vault.dirty
    policy_mod._save_vaults_at_exit()
    assert not p.vault.dirty
    reloaded = TokenVault("k", path=path)
    assert len(reloaded) == len(p.vault)
    assert Policy.load("strict").save_vault() is None


async def test_secret_argument_rejection_audited(workspace):
    layer = make(workspace, {"extends": "standard", "name": "aud", "audit": True})
    res = await layer.call_tool("find_assets", {"query": "password=hunter22x"})
    assert res.is_error and "secrets" in res.content[0].text
    last = layer.policy.audit_log[-1]
    assert last["decision"] == "rejected" and last["name"] == "find_assets"
    assert "hunter22x" not in json.dumps(list(layer.policy.audit_log))
    assert layer.policy.counters["rejected"] == 1


def test_record_rejection_without_prior_entry_and_record_hidden():
    p = Policy.load({"name": "x"})  # audit off: allowed calls are not recorded
    p.check_call(tool("q"), None, {"a": 1})
    p.record_rejection(tool("q"), None, {"a": 1}, InvalidArgumentsError("nope"))
    p.record_hidden("tool", "secret_tool" * 50, Principal(id="eve"), {"x": "y"})
    decisions = [(e["decision"], e["name"][:11]) for e in p.audit_log]
    assert decisions == [("rejected", "q"), ("not_found", "secret_tool")]
    assert len(p.audit_log[-1]["name"]) <= 200 and p.counters["hidden"] == 1


def test_policy_config_extends_is_resolved():
    p = Policy.load(PolicyConfig(name="mine", extends="strict"))
    assert p.name == "mine" and p.extends_chain == ["standard", "strict"]
    assert not p.is_allowed(tool("m", caps=[Capability.CLOUD_ACCESS]), None)
    assert [t.name for t in p.output_pipeline(tool(), None).transforms][:2] == [
        "sanitize",
        "redact",
    ]


# ---------------------------------------------------------------------------
# 10-11
# ---------------------------------------------------------------------------


def test_soc_collector_gets_live_tools(workspace):
    layer = make(workspace, "soc-analyst")
    names = lambda p: {t["name"] for t in layer.tools_wire(p)}  # noqa: E731
    assert {"map_inventory", "collect_assets", "run_scanners"} <= names(COLLECTOR)
    assert not {"map_inventory", "export_report", "export_terraform"} & names(ANALYST)


def test_rate_limit_rejection_refunds_earlier_buckets():
    p = Policy.load(
        {
            "name": "rl",
            "rate_limits": [
                {"tools": ["*"], "rate": 10, "per": "hour", "scope": "principal"},
                {"tools": ["hot"], "rate": 1, "per": "hour", "scope": "principal_tool"},
            ],
        }
    )
    p.check_call(tool("hot"), None, {})
    for _ in range(5):
        with pytest.raises(RateLimitedError):
            p.check_call(tool("hot"), None, {})
    for _ in range(9):  # the global bucket was only charged once
        p.check_call(tool("cold"), None, {})
    with pytest.raises(RateLimitedError):
        p.check_call(tool("cold"), None, {})


def test_completions_have_their_own_rate_limit_kind():
    p = Policy.load(
        {
            "name": "rl",
            "rate_limits": [{"rate": 1, "per": "hour", "kinds": ["tool"], "tools": ["*"]}],
        }
    )
    prompt = PromptSpec(name="p", handler=lambda ctx: "")
    for _ in range(3):
        p.check_call(prompt, None, {"__completion__": "x"})  # "tool" does not cover completions


def test_url_userinfo_is_not_an_email():
    found = [(m.entity, m.text) for m in DEFAULT_REGISTRY.scan("https://alice@git.example.com/r")]
    assert ("url_username", "alice") in found
    assert not [e for e, _ in found if e == "email"]
    red = Redactor({"pii": "pseudonymize"})
    vault = TokenVault("k")
    out = red.apply("https://alice@git.example.com/r", TransformContext(vault=vault))
    assert "alice" not in out and out.startswith("https://user-")


def test_derive_keeps_extends_chain():
    p = Policy.load("strict")
    d = p.derive(deny_tools=["x"])
    assert d.extends_chain == ["standard", "strict"]


# ---------------------------------------------------------------------------
# (a) enum labels as keys, (b) account ids typed by shape
# ---------------------------------------------------------------------------


async def test_standard_dataset_summary_counts_not_redacted(workspace):
    layer = make(workspace, "standard")
    res = await layer.call_tool("dataset_summary", {})
    assert not res.is_error, res.content[0].text
    assert "REDACTED" not in res.content[0].text
    blob = json.dumps(res.structured)
    assert '"SECRET": 1' in blob or '"SECRET":1' in blob


def test_enum_keys_exempt_but_real_secret_keys_still_redacted():
    red = Redactor({"secret": "redact"})
    out = red.apply(
        {
            "assets_by_type": {"SECRET": 3, "KMS_KEY": 2, "ACCESS_KEY": 1},
            "secret": "hunter2",
            "Secret": "x1",
        },
        TransformContext(),
    )
    assert out["assets_by_type"] == {"SECRET": 3, "KMS_KEY": 2, "ACCESS_KEY": 1}
    assert out["secret"].startswith("[REDACTED") and out["Secret"].startswith("[REDACTED")


@pytest.mark.parametrize(
    "value, entity, pattern",
    [
        ("123456789012", "aws_account_id", r"\d{12}"),
        (
            "1b2c3d4e-1111-2222-3333-444455556666",
            "azure_subscription_id",
            r"[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        ),
        ("acme-prod-1", "gcp_project_id", r"proj-[0-9a-f]{8}"),
        ("Corp Tenant", "cloud_account", r"acct-[0-9a-f]{10}"),
    ],
)
def test_account_id_entity_from_shape(value, entity, pattern):
    assert account_entity(value) == entity
    vault = TokenVault("k")
    out = Redactor(STRICT_MAP).apply({"account_id": value}, TransformContext(vault=vault))
    assert re.fullmatch(pattern, out["account_id"]), out
    assert "awsaccount" not in out["account_id"]
    back = Depseudonymizer(vault).apply(
        {"account_id": out["account_id"]}, TransformContext(vault=vault)
    )
    assert back == {"account_id": value}


async def test_reveal_reverses_aliases_and_tokens_together(workspace):
    # soc-analyst: analysts see aliased accounts wrapped around pseudonyms;
    # a lead revealing what an analyst saw gets the real ARN back, not the alias
    layer = make(workspace, "soc-analyst")
    ann = Principal(id="ann", roles={"analyst", "default"})
    lead = Principal(id="lee", roles={"lead", "default"})
    seen = (await layer.call_tool("get_asset", {"ref": "web-1"}, principal=ann)).structured
    assert "prod-payments" in seen["arn"] and "i-0web1" not in seen["arn"]
    arn = await layer.call_tool("reveal_token", {"token": seen["arn"]}, principal=lead)
    assert not arn.is_error
    assert arn.structured["value"] == "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1"
    acct = await layer.call_tool("reveal_token", {"token": "prod-payments"}, principal=lead)
    assert acct.structured["value"] == "111111111111"
    with pytest.raises(NotFoundError):
        await layer.call_tool("reveal_token", {"token": seen["arn"]}, principal=ann)


# ---------------------------------------------------------------------------
# Round 3: organizations, dependency ids, ontology IRIs, RAG chunks, accounts
# ---------------------------------------------------------------------------


async def test_strict_round3_tools_leak_no_identifiers(workspace):
    layer = make(workspace, "strict")
    real = (
        "web-1",
        "app-role",
        "Workloads",
        "shared-services",
        "o-sample",
        "ou-work",
        "r-root",
        "111111111111",
        "222222222222",
        "sample-org",
        "web-team",
    )
    calls = [
        ("organization_topology", {}),
        ("depends_on", {"ref": "web-1"}),
        ("blast_radius", {"ref": "web-1"}),
        ("ontology_neighbourhood", {"ref": "web-1"}),
        ("rag_chunks", {}),
        ("cross_account_edges", {}),
        ("security_coverage", {}),
    ]
    for name, args in calls:
        layer.policy.reset_rate_limits()
        res = await layer.call_tool(name, args)
        assert not res.is_error, (name, res.content[0].text)
        text = res.content[0].text
        for value in real:
            assert value not in text, (name, value)


def test_org_detectors_and_formats():
    found = {
        m.entity for m in DEFAULT_REGISTRY.scan("org o-a1b2c3d4e5 ou ou-ab12-cdef5678 root r-ab12")
    }
    assert {"aws_org_id", "aws_ou_id", "aws_root_id"} <= found
    vault = TokenVault("k")
    assert re.fullmatch(r"o-[0-9a-f]{10}", vault.tokenize("o-a1b2c3d4e5", "aws_org_id"))
    assert re.fullmatch(
        r"ou-[0-9a-f]{4}-[0-9a-f]{8}", vault.tokenize("ou-ab12-cdef5678", "aws_ou_id")
    )


def test_iri_and_chunk_id_tokens_match_plain_ids():
    vault = TokenVault("k")
    red = Redactor(STRICT_MAP)
    out = red.apply(
        {
            "asset": {"id": "web-1", "name": "web-1", "type": "EC2"},
            "subject_id": "cmr:web-1",
            "object_id": "cmr:tag_owner_web-team",
            "env_iri": "cmr:tag_env_prod",
            "finding": "cmr:finding_f1",
            "chunk_id": "entity::web-1",
            "uuid_id": {"id": "9f86d081-884c-4d63-9a2b-1c5e3f0a7b21", "arn": "x"},
        },
        TransformContext(vault=vault),
    )
    tok = out["asset"]["id"]
    assert tok.startswith("res-") and out["asset"]["name"] == tok
    assert out["subject_id"] == f"cmr:{tok}" and out["chunk_id"] == f"entity::{tok}"
    assert out["object_id"] == f"cmr:tag_owner_{vault.lookup('web-team', 'person')}"
    assert out["env_iri"] == "cmr:tag_env_prod" and out["finding"] == "cmr:finding_f1"
    assert out["uuid_id"]["id"] == "9f86d081-884c-4d63-9a2b-1c5e3f0a7b21"  # random ids kept


def test_account_keys_and_maps_ignore_placeholder_heuristic():
    vault = TokenVault("k")
    out = Redactor(STRICT_MAP).apply(
        {
            "accounts_affected": ["111111111111"],
            "management_account_id": "111111111111",
            "by_account_pair": {"111111111111 -> 222222222222": 2},
            "services_by_account_region": {"111111111111": {"us-east-1": {"guardduty": True}}},
            "items": ["111111111111/us-east-1: security hub disabled"],
        },
        TransformContext(vault=vault),
    )
    acct = vault.lookup("111111111111", "aws_account_id")
    other = vault.lookup("222222222222", "aws_account_id")
    assert out["accounts_affected"] == [acct] and out["management_account_id"] == acct
    assert out["by_account_pair"] == {f"{acct} -> {other}": 2}
    assert list(out["services_by_account_region"]) == [acct]
    assert out["items"] == [f"{acct}/us-east-1: security hub disabled"]


def test_rag_content_lines():
    vault = TokenVault("k")
    content = (
        "Resource: sample-org\nType: ORGANIZATION\nAccount: 111111111111\n"
        'Tags: {"Owner": "alice", "env": "prod"}\n\nRelations (1):\n'
        "  → CONTAINS: Workloads\n  • web-1 (EC2)"
    )
    out = Redactor(STRICT_MAP).apply(
        {"chunk_id": "entity::org", "chunk_type": "entity", "content": content},
        TransformContext(vault=vault),
    )
    text = out["content"]
    for value in ("sample-org", "111111111111", "alice", "Workloads", "web-1"):
        assert value not in text, value
    assert "Type: ORGANIZATION" in text and '"env": "prod"' in text


def test_generic_pipeline_uses_alias_ordering():
    p = Policy.load("soc-analyst")
    names = [t.name for t in p._generic_pipeline(ANALYST).transforms]
    assert names.index("substitute") > names.index("redact")


def test_custom_key_rule_can_defer():
    red = Redactor(
        {"identifier": "pseudonymize", "network": "pseudonymize", "special_cidr": "keep"},
        extra_key_rules=[
            {
                "name": "peer",
                "entity": "resource_name",
                "pattern": "^peer$",
                "category": "identifier",
                "defer": True,
            }
        ],
    )
    vault = TokenVault("k")
    out = red.apply({"peer": "0.0.0.0/0", "x": {"peer": "web-1"}}, TransformContext(vault=vault))
    assert out["peer"] == "0.0.0.0/0" and out["x"]["peer"].startswith("res-")
