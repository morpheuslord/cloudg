"""Tests for the interactive HTML report (cloudg/renderers/html_report.py).

Scanner output (finding titles, descriptions, evidence, resource IDs) and
cloud metadata (asset names, account IDs) end up in report.html. None of it
may be able to add markup or script to the page.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess

import pytest

from cloudg.renderers import html_report
from cloudg.renderers.html_report import (
    VENDORED_LIBRARIES,
    HTMLReportGenerator,
    script_json,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    ComplianceResult,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)

IMG = "<img src=x onerror=alert(1)>"
BREAKOUT = "</script><script>alert(1)</script>"
COMMENT = "<!--<script>"
PAYLOADS = (IMG, BREAKOUT, COMMENT)
TEMPLATE = html_report._resolve_template_dir() / "report.html.j2"


def _hostile_scan() -> ScanResult:
    payload = f"{IMG} {BREAKOUT} {COMMENT}"
    asset = CloudAsset(
        id="i-1",
        arn=f"arn:aws:ec2:us-east-1:1:instance/{IMG}",
        name=f"web {BREAKOUT}",
        asset_type=AssetType.EC2,
        provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="111",
        metadata={"vpc_id": f"vpc {IMG}", "subnet_id": f"subnet {BREAKOUT}"},
    )
    finding = Finding(
        resource_id="i-1",
        resource_arn=f"arn:{IMG}",
        severity=Severity.HIGH,
        title=f"Title {payload}",
        description=f"Description {payload}",
        evidence=f"Evidence {payload}",
        remediation=f"Remediation {payload}",
        source_tool=f"tool {IMG}",
        compliance_frameworks=[f"CIS {IMG}", f"PCI {BREAKOUT}"],
    )
    compliance = ComplianceResult(
        framework=f"CIS {IMG}",
        control_id="1.1",
        status=ComplianceStatus.FAIL,
        finding_ids=[finding.id],
    )
    return ScanResult(
        account_id=f"acct {IMG}",
        assets=[asset],
        findings=[finding],
        compliance=[compliance],
    )


def _graph_json() -> dict:
    return {
        "nodes": [{"id": "i-1", "name": f"web {BREAKOUT}", "type": "EC2", "arn": IMG}],
        "links": [],
    }


def _render(tmp_path, **kwargs) -> str:
    gen = HTMLReportGenerator(output_dir=str(tmp_path), **kwargs)
    path = gen.generate(_hostile_scan(), graph_json=_graph_json())
    return path.read_text(encoding="utf-8")


def _main_script(page: str) -> str:
    """The report's own script element (the last one in the page)."""
    start = page.rindex("<script>") + len("<script>")
    return page[start : page.index("</script>", start)]


# ── Data embedding ──


def test_script_json_escapes_markup_and_round_trips():
    value = {"t": f"{BREAKOUT} {COMMENT} & 'q' {IMG}"}
    out = script_json(value)
    for ch in "<>&'":
        assert ch not in out
    assert json.loads(out) == value


def test_hostile_values_never_appear_unescaped(tmp_path):
    page = _render(tmp_path)
    for payload in PAYLOADS:
        assert payload not in page
    assert "onerror=alert(1)>" not in page
    # Exactly the two library scripts plus the report's own script: no
    # value closed a script element or opened a new one
    assert len(re.findall(r"<script\b", page, re.IGNORECASE)) == 3
    assert len(re.findall(r"</script", page, re.IGNORECASE)) == 3


def test_header_values_are_autoescaped(tmp_path):
    page = _render(tmp_path)
    assert "Account: acct &lt;img src=x onerror=alert(1)&gt;" in page


def test_fallback_report_escapes(tmp_path):
    gen = HTMLReportGenerator(template_dir=str(tmp_path / "missing"), output_dir=str(tmp_path))
    page = gen.generate(_hostile_scan()).read_text(encoding="utf-8")
    for payload in PAYLOADS:
        assert payload not in page
    assert "Title &lt;img src=x onerror=alert(1)&gt;" in page


# ── Client-side rendering ──


def test_template_builds_markup_only_through_the_escaping_tag():
    """Every template literal that holds a tag goes through html``, and
    nothing writes markup through another sink."""
    script = TEMPLATE.read_text(encoding="utf-8").rsplit("<script>", 1)[1]
    for sink in ("insertAdjacentHTML", "outerHTML", "document.write", ".html("):
        assert sink not in script
    literals = re.findall(r"([\w$.]*)`([^`]*)`", script)
    assert literals
    for tag, body in literals:
        if re.search(r"<[A-Za-z/]", body):
            assert tag == "html", f"untagged markup literal: {body[:60]!r}"
    # No markup assembled from quoted strings either
    assert not re.search(r"""['"]<[A-Za-z/]""", script)


_NODE_DOM_STUB = r"""
const elements = {};
function makeEl(id) {
    const el = {
        id, innerHTML: '', textContent: '', value: '', style: {}, dataset: {},
        children: [], listeners: {},
        classList: { add() {}, remove() {} },
        appendChild(child) { this.children.push(child); return child; },
        addEventListener(type, fn) { this.listeners[type] = fn; },
        querySelectorAll() { return []; },
    };
    return el;
}
globalThis.document = {
    getElementById(id) { return elements[id] || (elements[id] = makeEl(id)); },
    querySelectorAll() { return []; },
    createElement(tag) { return makeEl(tag); },
};
"""

_NODE_RUN = r"""
renderFindings(findingsData);
const rows = document.getElementById('findings-body').innerHTML;
showDetail(0);
const detail = document.getElementById('detail-content').innerHTML;
renderCompliance();
const compliance = document.getElementById('compliance-grid').innerHTML;
const probe = escapeHtml(`<a href="x" title='y'>&</a>`);
const empty = [escapeHtml(null), escapeHtml(undefined), escapeHtml(0)];
console.log(JSON.stringify({rows, detail, compliance, probe, empty}));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_rendered_markup_is_escaped_in_the_browser_code(tmp_path):
    """Run the report's script in node (with a small DOM stand-in) and
    check the markup it writes into the page."""
    script = _main_script(_render(tmp_path))
    script = script[: script.index("// ── Init ──")]
    js = tmp_path / "report.js"
    js.write_text(_NODE_DOM_STUB + script + _NODE_RUN, encoding="utf-8")
    proc = subprocess.run(
        ["node", str(js)], capture_output=True, text=True, timeout=60, check=False
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)

    assert out["probe"] == "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
    assert out["empty"] == ["", "", "0"]
    for key in ("rows", "detail", "compliance"):
        markup = out[key]
        assert markup
        for payload in PAYLOADS:
            assert payload not in markup
        assert "&lt;img src=x onerror=alert(1)&gt;" in markup
        # The only tags are the template's own
        tags = set(re.findall(r"<([a-zA-Z0-9]+)", markup))
        assert tags <= {"tr", "td", "span", "code", "h2", "div", "pre", "h4"}, tags
    assert 'data-index="0"' in out["rows"]
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in out["detail"]


# ── Offline libraries (report.inline_js) ──


def test_inline_js_embeds_the_vendored_libraries(tmp_path):
    page = _render(tmp_path)
    assert "cdn.jsdelivr.net" not in page
    assert "<script src=" not in page
    assert "Chart.js v4.4.0" in page
    assert "d3js.org v7.9.0" in page


def test_inline_js_false_loads_pinned_cdn_builds_with_sri(tmp_path):
    page = _render(tmp_path, inline_js=False)
    for lib in VENDORED_LIBRARIES.values():
        assert f'<script src="{lib["cdn"]}" integrity="{lib["integrity"]}"' in page
    assert "Chart.js v4.4.0" not in page


def test_missing_vendor_files_fall_back_to_the_cdn(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(html_report, "_VENDOR_DIR", tmp_path / "nowhere")
    page = _render(tmp_path)
    assert VENDORED_LIBRARIES["d3"]["cdn"] in page
    assert "load it from the CDN" in caplog.text


def test_vendored_files_match_their_sri_hashes_and_ship_licences():
    vendor = html_report._VENDOR_DIR
    for lib in VENDORED_LIBRARIES.values():
        data = (vendor / lib["file"]).read_bytes()
        digest = base64.b64encode(hashlib.sha384(data).digest()).decode()
        assert lib["integrity"] == f"sha384-{digest}"
        assert b"</script" not in data.lower()
    for name in ("NOTICE", "LICENSE-chartjs.md", "LICENSE-d3.txt"):
        assert (vendor / name).is_file()
