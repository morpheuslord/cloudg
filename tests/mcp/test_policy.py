"""Tests for cloudg.mcp.policy: profile loading, extends merging, access
decisions by role / capability / sensitivity, rate limits, pipelines and
transform hints."""

from __future__ import annotations

import json
import logging

import pytest

from cloudg.mcp.context import Principal
from cloudg.mcp.core import (
    AccessDeniedError,
    Capability,
    InvalidArgumentsError,
    PromptSpec,
    RateLimitedError,
    ResourceSpec,
    ResourceTemplateSpec,
    Sensitivity,
    ToolSpec,
)
from cloudg.mcp.policy import (
    POLICY_ENV,
    Policy,
    PolicyConfig,
    available_profiles,
    merge_policy_dicts,
    policy_fingerprint,
)
from cloudg.mcp.transforms import (
    IDENTITY,
    Depseudonymizer,
    Projection,
    Redactor,
    SecretArgumentGuard,
    TokenVault,
    TransformContext,
    UntrustedTextGuard,
)

ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc1234def567890"


def tool(name="get_asset", *, category="inventory", caps=(Capability.READ_STATE,),
         sensitivity=Sensitivity.CONFIDENTIAL, tags=(), hints=None) -> ToolSpec:
    return ToolSpec(name=name, handler=lambda ctx: None, category=category,
                    capabilities=set(caps), sensitivity=sensitivity, tags=set(tags),
                    transform_hints=dict(hints or {}))


def resource(uri="cloudg://workspace", sensitivity=Sensitivity.INTERNAL,
             category="inventory") -> ResourceSpec:
    return ResourceSpec(name="ws", handler=lambda ctx: None, uri=uri, sensitivity=sensitivity,
                        category=category)


LOCAL = Principal.local()
ADMIN = Principal(id="root", roles={"admin"})


def run(pipeline, value, policy, principal=LOCAL, spec=None, direction="output"):
    ctx = TransformContext(principal=principal, spec=spec, vault=policy.vault,
                           direction=direction)
    return pipeline.apply(value, ctx), ctx.report


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_profiles_are_packaged():
    assert {"open", "standard", "strict", "read_only", "airgapped", "audit",
            "soc-analyst"} <= set(available_profiles())
    for name in available_profiles():
        p = Policy.load(name)
        assert p.name == name
        assert p.describe()["name"] == name


def test_load_variants(tmp_path, monkeypatch):
    monkeypatch.delenv(POLICY_ENV, raising=False)
    assert Policy.load(None).name == "standard"
    assert Policy.default().name == "standard"
    assert Policy.load("read-only").name == "read_only"  # hyphen alias
    p = Policy.load({"name": "mine", "deny_tools": ["x"]})
    assert p.name == "mine" and Policy.load(p) is p
    assert Policy.load(PolicyConfig(name="cfg")).name == "cfg"
    assert Policy.load('{"name": "inline", "extends": "strict"}').name == "inline"
    y = tmp_path / "p.yaml"
    y.write_text("name: from-yaml\nextends: strict\ndeny_tools: [danger]\n")
    assert Policy.load(str(y)).name == "from-yaml"
    assert Policy.load(y).source == str(y)
    j = tmp_path / "p.json"
    j.write_text(json.dumps({"policy": {"name": "wrapped"}}))
    assert Policy.from_file(j).name == "wrapped"
    with pytest.raises(ValueError, match="Unknown policy"):
        Policy.load("no-such-profile")
    with pytest.raises(FileNotFoundError):
        Policy.load(str(tmp_path / "missing.yaml"))
    with pytest.raises(ValueError, match="Invalid policy"):
        Policy.load({"name": "bad", "not_a_field": 1})
    with pytest.raises(ValueError):
        Policy.load({"transforms": [{"type": "nope"}]})
    with pytest.raises(TypeError):
        Policy.load(42)


def test_env_var_selects_policy(monkeypatch, tmp_path):
    monkeypatch.setenv(POLICY_ENV, "strict")
    assert Policy.load(None).name == "strict"
    f = tmp_path / "env.yaml"
    f.write_text("name: env-file\n")
    monkeypatch.setenv(POLICY_ENV, str(f))
    assert Policy.load(None).name == "env-file"


def test_extends_merge_semantics(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(
        "name: base\nextends: standard\ndeny_tools: [a]\nrules: [{name: r1}]\n"
        "transform_options: {project: {max_list: 5}}\n"
    )
    child = tmp_path / "child.yaml"
    child.write_text(
        "extends: base.yaml\ndeny_tools: [b]\nrules: [{name: r2}]\n"
        "transform_options: {project: {max_string: 10}}\n"
    )
    p = Policy.load(str(child))
    assert p.name == "custom(base)"
    assert p.extends_chain == ["standard", "base"]
    assert p.config.deny_tools == ["a", "b"]
    assert [r.name for r in p.config.rules] == ["r1", "r2"]
    assert p.config.transform_options == {"project": {"max_list": 5, "max_string": 10}}
    assert p.config.transforms == Policy.load("standard").config.transforms
    loop = tmp_path / "loop.yaml"
    loop.write_text("extends: loop.yaml\n")
    with pytest.raises(ValueError, match="cycle"):
        Policy.load(str(loop))
    with pytest.raises(ValueError, match="Unknown policy to extend"):
        Policy.load({"extends": "nowhere"})


def test_merge_policy_dicts_unit():
    out = merge_policy_dicts(
        {"deny_capabilities": ["exec"], "vault": {"scope": "global"}, "transforms": ["a"],
         "rate_limits": [{"rate": 1}]},
        {"deny_capabilities": ["exec", "write_fs"], "vault": {"ttl_seconds": 5},
         "transforms": ["b"], "rate_limits": [{"rate": 2}]},
    )
    assert out == {"deny_capabilities": ["exec", "write_fs"],
                   "vault": {"scope": "global", "ttl_seconds": 5}, "transforms": ["b"],
                   "rate_limits": [{"rate": 1}, {"rate": 2}]}


def test_policy_level_allow_capabilities_undenies():
    p = Policy.load({"extends": "strict", "allow_capabilities": ["write_fs"]})
    assert p.is_allowed(tool("export", caps=[Capability.WRITE_FS]), LOCAL)
    assert not p.is_allowed(tool("scan", caps=[Capability.EXEC]), LOCAL)


def test_describe_never_leaks_vault_key():
    p = Policy.load({"name": "k", "vault": {"key": "super-secret-vault-key"}})
    blob = json.dumps(p.describe(), default=str)
    assert "super-secret-vault-key" not in blob
    assert p.describe()["vault"]["key_source"] == "config"
    assert p.describe()["vault"]["key_configured"] is True
    std = Policy.load("standard").describe()
    strategies = std["transforms"][1]["options"]["strategies"]
    assert {"applies_to": "secret", "strategy": "redact"} in strategies
    assert len(policy_fingerprint(p)) == 16


def test_derive_keeps_vault():
    p = Policy.load({"name": "x", "vault": {"key": "k1"}})
    d = p.derive(deny_tools=["foo"])
    assert d.vault is p.vault and d.config.deny_tools == ["foo"]
    assert not d.is_allowed(tool("foo"), LOCAL)


# ---------------------------------------------------------------------------
# Access decisions
# ---------------------------------------------------------------------------


def test_open_allows_everything():
    p = Policy.load("open")
    for caps in ([Capability.CLOUD_ACCESS], [Capability.REVEAL], [Capability.EXEC]):
        assert p.is_allowed(tool(caps=caps), LOCAL)
    assert p.output_pipeline(tool(), LOCAL) is IDENTITY
    assert p.input_pipeline(tool(), LOCAL) is IDENTITY


def test_standard_reveal_only_for_admin_roles():
    p = Policy.load("standard")
    reveal = tool("reveal_token", caps=[Capability.REVEAL], sensitivity=Sensitivity.RESTRICTED)
    assert not p.is_allowed(reveal, LOCAL)
    assert p.is_allowed(reveal, ADMIN)
    assert p.is_allowed(reveal, Principal(id="p", roles={"privacy-admin"}))
    assert p.is_allowed(tool("map_inventory", caps=[Capability.CLOUD_ACCESS]), LOCAL)
    with pytest.raises(AccessDeniedError) as ei:
        p.check_call(reveal, LOCAL, {"token": "x"})
    assert "reveal" in ei.value.message and ei.value.data["policy"] == "standard"


def test_strict_denials():
    p = Policy.load("strict")
    assert not p.is_allowed(tool(caps=[Capability.CLOUD_ACCESS]), LOCAL)
    assert not p.is_allowed(tool(caps=[Capability.EXEC]), LOCAL)
    assert not p.is_allowed(tool(caps=[Capability.WRITE_FS]), LOCAL)
    # never-reveal rule beats the admin grant inherited from standard
    reveal = tool("reveal_token", caps=[Capability.REVEAL], sensitivity=Sensitivity.CONFIDENTIAL)
    assert not p.is_allowed(reveal, ADMIN)
    assert not p.is_allowed(tool(sensitivity=Sensitivity.RESTRICTED), ADMIN)
    assert p.is_allowed(tool(), LOCAL)
    assert p.is_allowed(resource(), LOCAL)
    assert not p.is_allowed(resource(sensitivity=Sensitivity.RESTRICTED), LOCAL)


@pytest.mark.parametrize(
    "profile, denied",
    [
        ("read_only", {Capability.CLOUD_ACCESS, Capability.EXEC, Capability.WRITE_FS}),
        ("airgapped", {Capability.CLOUD_ACCESS, Capability.EXEC}),
        ("audit", {Capability.CLOUD_ACCESS, Capability.EXEC, Capability.WRITE_FS}),
    ],
)
def test_capability_profiles(profile, denied):
    p = Policy.load(profile)
    for cap in Capability:
        if cap is Capability.REVEAL:
            continue
        assert p.is_allowed(tool(caps=[cap]), LOCAL) is (cap not in denied), cap


def test_allow_and_deny_lists_with_globs_and_negation():
    p = Policy.load({
        "name": "lists",
        "allow_tools": ["find_*", "get_*", "!get_secret*"],
        "deny_resources": ["cloudg://raw/*"],
        "deny_prompts": ["dangerous"],
        "deny_categories": ["live"],
        "allow_categories": ["inventory", "graph", "live"],
    })
    assert p.is_allowed(tool("find_assets"), LOCAL)
    assert not p.is_allowed(tool("get_secret_value"), LOCAL)
    assert not p.is_allowed(tool("list_x"), LOCAL)
    assert not p.is_allowed(tool("find_live", category="live"), LOCAL)
    assert not p.is_allowed(tool("find_y", category="export"), LOCAL)
    assert not p.is_allowed(resource("cloudg://raw/1"), LOCAL)
    assert p.is_allowed(resource("cloudg://workspace"), LOCAL)
    assert not p.is_allowed(resource("cloudg://workspace", category="general"), LOCAL)
    tmpl = ResourceTemplateSpec(name="raw", handler=lambda ctx, x: None,
                                uri_template="cloudg://raw/{x}", category="inventory")
    assert not p.is_allowed(tmpl, LOCAL)
    prompt = PromptSpec(name="dangerous", handler=lambda ctx: "", category="graph")
    assert not p.is_allowed(prompt, LOCAL)
    assert p.is_allowed(PromptSpec(name="ok", handler=lambda ctx: "", category="graph"), LOCAL)


def test_role_rules_grant_and_deny():
    p = Policy.load({
        "name": "roles",
        "deny_capabilities": ["cloud_access"],
        "max_sensitivity": "internal",
        "roles": {
            "collector": {"allow_capabilities": ["cloud_access"]},
            "analyst": {"max_sensitivity": "confidential", "deny_tools": ["export_*"]},
            "intern": {"deny_categories": ["findings"]},
        },
        "rules": [
            {"name": "no-tag-x", "match": {"tags": ["x"]}, "deny_tools": ["*"]},
            {"name": "bob-only", "match": {"principals": ["bob"]}, "allow_tools": ["special"],
             "max_sensitivity": "restricted"},
        ],
    })
    live = tool("map_inventory", caps=[Capability.CLOUD_ACCESS], sensitivity=Sensitivity.INTERNAL)
    assert not p.is_allowed(live, LOCAL)
    assert p.is_allowed(live, Principal(id="c", roles={"collector"}))
    conf = tool("find_assets")
    assert not p.is_allowed(conf, LOCAL)  # confidential > internal
    analyst = Principal(id="a", roles={"analyst"})
    assert p.is_allowed(conf, analyst)
    assert not p.is_allowed(tool("export_csv", sensitivity=Sensitivity.INTERNAL), analyst)
    both = Principal(id="ai", roles={"analyst", "intern"})
    assert not p.is_allowed(tool("find_findings", category="findings"), both)  # deny wins
    assert not p.is_allowed(tool("tagged", tags=["x"], sensitivity=Sensitivity.PUBLIC), LOCAL)
    bob = Principal(id="bob", roles=set())
    assert p.is_allowed(tool("special", sensitivity=Sensitivity.RESTRICTED), bob)
    assert p._uses_principal_ids


def test_rule_match_kinds_sensitivity_capabilities():
    p = Policy.load({
        "name": "m",
        "rules": [
            {"name": "no-restricted-resources",
             "match": {"kinds": ["resource"], "sensitivity": ["restricted"]},
             "deny_resources": ["*"]},
            {"name": "no-exec-for-guests", "match": {"roles": ["guest"],
                                                      "capabilities": ["exec"]},
             "deny_tools": ["*"]},
        ],
    })
    assert not p.is_allowed(resource(sensitivity=Sensitivity.RESTRICTED), LOCAL)
    tmpl = ResourceTemplateSpec(name="t", handler=lambda ctx, x: None, uri_template="u://{x}",
                                sensitivity=Sensitivity.RESTRICTED)
    assert not p.is_allowed(tmpl, LOCAL)
    assert p.is_allowed(resource(), LOCAL)
    guest = Principal(id="g", roles={"guest"})
    assert not p.is_allowed(tool("scan", caps=[Capability.EXEC]), guest)
    assert p.is_allowed(tool("scan2"), guest)


def test_hide_denied_false_lists_but_blocks():
    p = Policy.load({"name": "visible", "extends": "strict", "hide_denied": False})
    live = tool("map_inventory", caps=[Capability.CLOUD_ACCESS])
    assert p.is_allowed(live, LOCAL)
    with pytest.raises(AccessDeniedError, match="cloud_access"):
        p.check_call(live, LOCAL, {})


def test_audit_log_and_reveal_logging(caplog):
    p = Policy.load({"name": "a", "audit": True, "deny_tools": ["bad"]})
    with caplog.at_level(logging.INFO, logger="cloudg.mcp.audit"):
        p.check_call(tool("good"), LOCAL, {"asset_id": "secret-ish-value"})
        with pytest.raises(AccessDeniedError):
            p.check_call(tool("bad"), LOCAL, {})
        p.check_call(tool("reveal_token", caps=[Capability.REVEAL]), ADMIN, {"token": "t"})
    decisions = [e["decision"] for e in p.audit_log]
    assert decisions == ["allowed", "denied", "allowed"]
    first = p.audit_log[0]
    assert set(first["arguments"]) == {"asset_id"}
    assert "secret-ish-value" not in json.dumps(list(p.audit_log))
    assert any("REVEAL" in r.getMessage() for r in caplog.records)
    assert p.counters["denied"] == 1 and p.counters["reveal"] == 1


def test_denials_audited_even_without_audit_flag():
    p = Policy.load({"name": "a", "deny_tools": ["bad"]})
    p.check_call(tool("good"), LOCAL, {})
    with pytest.raises(AccessDeniedError):
        p.check_call(tool("bad"), LOCAL, {})
    assert [e["decision"] for e in p.audit_log] == ["denied"]


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_rate_limit_token_bucket(monkeypatch):
    p = Policy.load({"name": "rl", "rate_limits": [
        {"tools": ["hot*"], "rate": 2, "per": "minute", "scope": "principal_tool"}]})
    t = tool("hot_tool")
    p.check_call(t, LOCAL, {})
    p.check_call(t, LOCAL, {})
    with pytest.raises(RateLimitedError) as ei:
        p.check_call(t, LOCAL, {})
    assert ei.value.data["retry_after"] > 0 and ei.value.data["limit"] == "2/minute"
    p.check_call(t, Principal(id="other"), {})  # separate bucket per principal
    p.check_call(tool("cold"), LOCAL, {})  # not matched
    # refill: pretend 31 seconds passed
    import cloudg.mcp.policy as mod

    real = mod.time.monotonic
    monkeypatch.setattr(mod.time, "monotonic", lambda: real() + 31)
    p.check_call(t, LOCAL, {})
    assert p.counters["rate_limited"] == 1
    p.reset_rate_limits()


@pytest.mark.parametrize("scope, second_ok", [("tool", False), ("principal", False),
                                              ("global", False), ("principal_tool", True)])
def test_rate_limit_scopes(scope, second_ok):
    p = Policy.load({"name": "rl", "rate_limits": [{"rate": 1, "per": "hour", "scope": scope}]})
    p.check_call(tool("a"), Principal(id="x"), {})
    other = (tool("b"), Principal(id="x")) if scope in ("principal", "principal_tool") \
        else (tool("a"), Principal(id="y"))
    if scope == "global":
        other = (tool("b"), Principal(id="y"))
    if second_ok:
        p.check_call(*other, {})
    else:
        with pytest.raises(RateLimitedError):
            p.check_call(*other, {})


def test_role_rate_limits_and_burst():
    p = Policy.load({"name": "rl", "roles": {"lead": {"rate_limits": [
        {"tools": ["reveal_token"], "rate": 1, "per": "day", "burst": 2}]}}})
    lead = Principal(id="l", roles={"lead"})
    t = tool("reveal_token")
    p.check_call(t, lead, {})
    p.check_call(t, lead, {})
    with pytest.raises(RateLimitedError):
        p.check_call(t, lead, {})
    for _ in range(5):
        p.check_call(t, LOCAL, {})  # rule does not apply to others


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


def test_standard_pipeline_shape_and_effects():
    p = Policy.load("standard")
    out_pl = p.output_pipeline(tool(), LOCAL)
    assert [t.name for t in out_pl.transforms] == ["sanitize", "redact", "project", "annotate"]
    data = {"asset": {"arn": ARN, "account_id": "123456789012", "raw_data": {"x": 1},
                      "metadata": {"password": "hunter2", "ip": "10.0.0.1"}}}
    out, report = run(out_pl, data, p, spec=tool())
    assert out["asset"]["arn"] == ARN and out["asset"]["account_id"] == "123456789012"
    assert out["asset"]["metadata"] == {"password": "[REDACTED:sensitive_field]",
                                        "ip": "10.0.0.1"}
    assert "raw_data" not in out["asset"]
    assert report["annotations"]["provenance"]["policy"] == "standard"
    in_pl = p.input_pipeline(tool(), LOCAL)
    kinds = [type(t) for t in in_pl.transforms]
    assert kinds == [SecretArgumentGuard, Depseudonymizer]  # fences are reversible
    with pytest.raises(InvalidArgumentsError):
        run(in_pl, {"q": "password=hunter22x"}, p, direction="input")


def test_pipelines_are_cached_per_spec_and_roles():
    p = Policy.load("standard")
    t = tool()
    assert p.output_pipeline(t, LOCAL) is p.output_pipeline(t, Principal.local())
    a = p.output_pipeline(t, LOCAL).transforms[1]
    b = p.output_pipeline(tool("other"), LOCAL).transforms[1]
    assert a is b  # identical transform specs share one (cached) instance


def test_strict_roundtrip_through_pipelines():
    p = Policy.load("strict")
    t = tool()
    data = {"asset": {"arn": ARN, "name": "web-1", "asset_type": "ec2",
                      "account_id": "123456789012", "ip": "10.0.1.5",
                      "tags": {"Owner": "alice@corp.com", "env": "prod"}}}
    out, report = run(p.output_pipeline(t, LOCAL), data, p, spec=t)
    a = out["asset"]
    assert a["arn"] != ARN and a["account_id"] != "123456789012" and a["ip"] != "10.0.1.5"
    assert a["tags"]["env"] == "prod" and "alice" not in json.dumps(out)
    assert report["pseudonymized"]["aws_arn"] == 1
    assert report["annotations"]["classification"]["note"].startswith("Identifiers")
    args = {"asset_id": a["arn"], "nested": {"ips": [a["ip"]]}, "owner": a["tags"]["Owner"]}
    back, _ = run(p.input_pipeline(t, LOCAL), args, p, direction="input")
    assert back == {"asset_id": ARN, "nested": {"ips": ["10.0.1.5"]}, "owner": "alice@corp.com"}
    # deterministic across calls
    again, _ = run(p.output_pipeline(t, LOCAL), data, p, spec=t)
    assert again == out


def test_shared_vault_and_principal_scope():
    v = TokenVault("shared")
    p1 = Policy.load("strict", vault=v)
    p2 = Policy.load("strict", vault=v)
    assert p1.vault is p2.vault is v
    scoped = Policy.load({"extends": "strict", "vault": {"scope": "principal", "key": "s"}})
    t = tool()
    a, _ = run(scoped.output_pipeline(t, LOCAL), ARN, scoped, principal=Principal(id="a"))
    b, _ = run(scoped.output_pipeline(t, LOCAL), ARN, scoped, principal=Principal(id="b"))
    assert a != b
    back_b, _ = run(scoped.input_pipeline(t, LOCAL), {"x": a}, scoped,
                    principal=Principal(id="b"), direction="input")
    assert back_b == {"x": a}  # b cannot reverse a's pseudonym


def test_transform_hints():
    p = Policy.load("strict")
    skip_all = tool("preview", hints={"skip": ["*"], "depseudonymize": False,
                                       "input_guard": False})
    assert p.output_pipeline(skip_all, LOCAL) is IDENTITY
    assert p.input_pipeline(skip_all, LOCAL) is IDENTITY
    no_proj = tool("big", hints={"skip": ["projection"]})
    assert "project" not in [t.name for t in p.output_pipeline(no_proj, LOCAL).transforms]
    no_pseudo = tool("reveal", hints={"pseudonymize": False})
    red = next(t for t in p.output_pipeline(no_pseudo, LOCAL).transforms
               if isinstance(t, Redactor))
    assert not red.reversible
    out, _ = run(p.output_pipeline(no_pseudo, LOCAL), ARN, p)
    assert out == ARN
    proj = tool("p", hints={"projection": {"max_list": 1}})
    pr = next(t for t in p.output_pipeline(proj, LOCAL).transforms if isinstance(t, Projection))
    assert pr.max_list == 1
    extra = tool("e", hints={"transforms": [{"type": "rename_keys",
                                             "options": {"renames": {"a": "b"}}}]})
    assert p.output_pipeline(extra, LOCAL).transforms[-1].name == "rename_keys"


def test_hints_ignored_when_policy_disallows():
    p = Policy.load({"extends": "strict", "honor_hints": False})
    t = tool("x", hints={"skip": ["*"], "pseudonymize": False,
                         "transforms": [{"type": "rename_keys", "options": {"renames": {}}}]})
    names = [x.name for x in p.output_pipeline(t, LOCAL).transforms]
    assert names[:2] == ["sanitize", "redact"] and names[-1] == "rename_keys"
    red = p.output_pipeline(t, LOCAL).transforms[1]
    assert red.reversible


def test_rule_transforms_modes_and_options():
    p = Policy.load({
        "name": "t",
        "transforms": ["sanitize", {"type": "redact", "options": {"strategies": {
            "secret": "redact"}}}],
        "rules": [
            {"name": "pseudo-for-analysts", "match": {"roles": ["analyst"]},
             "transform_options": {"redact": {"strategies": {"aws_arn": "pseudonymize"}}}},
            {"name": "findings-extra", "match": {"categories": ["findings"]},
             "transforms": ["annotate"]},
            {"name": "replace-for-raw", "match": {"names": ["raw_*"]},
             "transforms": [{"type": "project", "options": {"max_list": 1}}],
             "transforms_mode": "replace"},
            {"name": "prepend", "match": {"names": ["pre"]}, "transforms_mode": "prepend",
             "transforms": [{"type": "alias", "options": {"aliases": {"a": "b"}}}]},
        ],
    })
    analyst = Principal(id="a", roles={"analyst"})
    red = p.output_pipeline(tool(), analyst).transforms[1]
    assert red.strategies["aws_arn"].kind == "pseudonymize"
    assert red.strategies["secret"].kind == "redact"
    plain = p.output_pipeline(tool(), LOCAL).transforms[1]
    assert "aws_arn" not in plain.strategies
    assert [t.name for t in p.output_pipeline(tool("f", category="findings"), LOCAL).transforms] \
        == ["sanitize", "redact", "annotate"]
    assert [t.name for t in p.output_pipeline(tool("raw_x"), LOCAL).transforms] == ["project"]
    pre = p.output_pipeline(tool("pre"), LOCAL)
    # aliases always run after redaction, whatever the rule's mode
    assert [t.name for t in pre.transforms] == ["sanitize", "redact", "alias"]
    # aliases are reversed on input
    dep = p.input_pipeline(tool("pre"), LOCAL).transforms[-1]
    assert isinstance(dep, Depseudonymizer) and dep.aliases
    back, _ = run(p.input_pipeline(tool("pre"), LOCAL), {"x": "b"}, p, direction="input")
    assert back == {"x": "a"}


def test_custom_detectors_from_policy():
    p = Policy.load({
        "name": "custom-det",
        "detectors": [{"name": "employee_id", "entity": "employee_id", "category": "pii",
                       "pattern": r"\bEMP-\d{6}\b"}],
        "transforms": [{"type": "redact", "options": {"strategies": {"employee_id": "hash"}}}],
        "disabled_detectors": ["email"],
    })
    out, report = run(p.output_pipeline(tool(), LOCAL), "by EMP-123456 a@b.com", p)
    assert "EMP-123456" not in out and out.startswith("by employee_id:")
    assert "a@b.com" in out
    assert p.detectors().get("employee_id") is not None


def test_input_pipeline_without_reversible_output():
    p = Policy.load({"name": "plain", "transforms": [
        {"type": "redact", "options": {"strategies": {"secret": "redact"}}}]})
    assert p.input_pipeline(tool(), LOCAL) is IDENTITY
    p2 = Policy.load({"name": "sanitize-flag", "transforms": [
        {"type": "sanitize", "options": {"on_suspicious": "flag"}}]})
    assert p2.input_pipeline(tool(), LOCAL) is IDENTITY
    p3 = Policy.load({"name": "fence", "transforms": ["sanitize"]})
    assert isinstance(p3.output_pipeline(tool(), LOCAL).transforms[0], UntrustedTextGuard)
    assert isinstance(p3.input_pipeline(tool(), LOCAL).transforms[0], Depseudonymizer)


def test_preview_generic_pipeline():
    p = Policy.load("soc-analyst")
    analyst = Principal(id="a", roles={"analyst"})
    out, report = p.preview({"arn": ARN, "acct": "111111111111"}, None, analyst)
    assert out["arn"] != ARN and report["pseudonymized"]
    out2, _ = p.preview({"arn": ARN}, None, Principal(id="lead", roles={"lead"}))
    assert out2["arn"] == ARN


def test_soc_analyst_example_roles():
    p = Policy.load("soc-analyst")
    analyst = Principal(id="a", roles={"analyst"})
    lead = Principal(id="l", roles={"lead"})
    collector = Principal(id="c", roles={"collector"})
    live = tool("map_inventory", category="inventory", caps=[Capability.CLOUD_ACCESS])
    assert not p.is_allowed(live, analyst)
    assert p.is_allowed(live, collector)
    reveal = tool("reveal_token", caps=[Capability.REVEAL], sensitivity=Sensitivity.RESTRICTED)
    assert p.is_allowed(reveal, lead) and not p.is_allowed(reveal, analyst)
    assert not p.is_allowed(tool("export_report", category="export",
                                 caps=[Capability.WRITE_FS]), analyst)
    findings = tool("list_findings", category="findings")
    ann = [t for t in p.output_pipeline(findings, analyst).transforms if t.name == "annotate"]
    assert ann and ann[0].label_findings
    # account alias shown, and reversed on input
    out, _ = run(p.output_pipeline(tool(), lead), {"account": "111111111111"}, p,
                 principal=lead)
    assert out == {"account": "prod-payments"}
    back, _ = run(p.input_pipeline(tool(), lead), {"account": "prod-payments"}, p,
                  principal=lead, direction="input")
    assert back == {"account": "111111111111"}


def test_check_call_completion_kind_and_unknown_spec():
    p = Policy.load({"name": "c", "rate_limits": [{"rate": 1, "per": "hour",
                                                    "kinds": ["completion"]}]})
    prompt = PromptSpec(name="p", handler=lambda ctx: "")
    p.check_call(prompt, LOCAL, {"__completion__": "arg"})
    with pytest.raises(RateLimitedError):
        p.check_call(prompt, LOCAL, {"__completion__": "arg"})
    p.check_call(prompt, LOCAL, {})  # a normal prompt call is not a completion
    p.check_call(prompt, None, {})  # anonymous principal tolerated


def test_vault_persistence_via_policy(tmp_path):
    path = tmp_path / "vault.json"
    cfg = {"extends": "strict", "name": "persist",
           "vault": {"key": "persist-key", "path": str(path), "autosave": True}}
    p = Policy.load(cfg)
    out, _ = run(p.output_pipeline(tool(), LOCAL), {"arn": ARN}, p)
    assert path.exists()  # autosaved after new pseudonyms were issued
    p2 = Policy.load(cfg)  # a new process with the same key reloads the mappings
    back, _ = run(p2.input_pipeline(tool(), LOCAL), {"x": out["arn"]}, p2, direction="input")
    assert back == {"x": ARN}
