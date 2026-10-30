"""Render the pipeline result as JSON and a self-contained HTML report.

The HTML shows exactly what PS-02 asks to display for each issue: severity
rationale, exact affected code location, the patch diff + rationale, and the
test status (exploit blocked? regression green?).
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from .pipeline import PipelineResult

_BADGE = {
    "FIXED & VERIFIED": ("#15803d", "#dcfce7"),
    "PATCH BREAKS APP": ("#b45309", "#fef3c7"),
    "PATCH INEFFECTIVE": ("#b91c1c", "#fee2e2"),
    "NOT CONFIRMED (likely false positive)": ("#64748b", "#f1f5f9"),
    "ERROR": ("#b91c1c", "#fee2e2"),
}


def to_dict(result: PipelineResult) -> dict:
    issues = []
    for it in result.issues:
        f = it.finding
        v = it.verification
        issues.append({
            "rule_id": f.rule_id,
            "cwe": f.cwe,
            "title": f.title,
            "severity": f.severity.value,
            "severity_rationale": f.severity_rationale,
            "location": f"{f.file}:{f.line}",
            "snippet": f.snippet,
            "confirmed": it.confirmed,
            "exploit_evidence": it.exploit_evidence,
            "status": it.status,
            "patch_rationale": v.patch_rationale if v else None,
            "diff": v.diff if v else None,
            "regression_after": [
                {"name": c.name, "passed": c.passed} for c in v.regression_after
            ] if v else None,
            "exploit_blocked_after": (not v.patched_exploited) if v else None,
            "accepted": v.accepted if v else None,
        })
    return {
        "target": result.target,
        "summary": {"confirmed": result.confirmed, "fixed": result.fixed,
                    "total_findings": len(result.issues)},
        "issues": issues,
    }


def write_json(result: PipelineResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(to_dict(result), indent=2))


def write_html(result: PipelineResult, path: str | Path) -> None:
    d = to_dict(result)
    rows = []
    for it in d["issues"]:
        color, bg = _BADGE.get(it["status"], ("#334155", "#f1f5f9"))
        reg = it["regression_after"] or []
        reg_pass = sum(1 for c in reg if c["passed"])
        exploit_line = ("✓ blocked" if it["exploit_blocked_after"]
                        else "✗ still exploitable") if it["confirmed"] else "—"
        diff_html = (f"<pre class='diff'>{_color_diff(it['diff'])}</pre>"
                     if it["diff"] else "<p class='muted'>no patch applied</p>")
        rows.append(f"""
        <section class="card">
          <div class="head">
            <div>
              <span class="cwe">{html.escape(it['cwe'])}</span>
              <span class="title">{html.escape(it['title'])}</span>
            </div>
            <span class="badge" style="color:{color};background:{bg}">{html.escape(it['status'])}</span>
          </div>
          <table class="meta">
            <tr><th>Severity</th><td><b>{it['severity'].upper()}</b> — {html.escape(it['severity_rationale'])}</td></tr>
            <tr><th>Location</th><td><code>{html.escape(it['location'])}</code></td></tr>
            <tr><th>Offending code</th><td><code>{html.escape(it['snippet'])}</code></td></tr>
            <tr><th>Exploit (proof it's real)</th><td>{html.escape(it['exploit_evidence'])}</td></tr>
            <tr><th>Patch rationale</th><td>{html.escape(it['patch_rationale'] or '—')}</td></tr>
            <tr><th>Test status</th><td>exploit after patch: <b>{exploit_line}</b> &nbsp;·&nbsp; regression: <b>{reg_pass}/{len(reg)} passing</b></td></tr>
          </table>
          {diff_html}
        </section>""")

    s = d["summary"]
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PatchProof Report</title>
<style>
  :root {{ --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --accent:#1e3a8a; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         color:var(--ink); max-width:900px; margin:0 auto; padding:24px 16px; background:#fff; }}
  h1 {{ margin:0 0 4px; }}
  .sub {{ color:var(--muted); margin:0 0 16px; }}
  .kpis {{ display:flex; gap:12px; margin:0 0 20px; }}
  .kpi {{ flex:1; background:#f1f5f9; border:1px solid var(--line); border-radius:10px; padding:12px; text-align:center; }}
  .kpi b {{ display:block; font-size:26px; color:var(--accent); }}
  .kpi span {{ color:var(--muted); font-size:12px; }}
  .card {{ border:1px solid var(--line); border-radius:12px; padding:16px; margin:0 0 16px; }}
  .head {{ display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:10px; }}
  .cwe {{ font:600 12px/1 ui-monospace,monospace; background:#eef2ff; color:var(--accent); padding:4px 7px; border-radius:6px; margin-right:8px; }}
  .title {{ font-weight:600; }}
  .badge {{ font:600 12px/1 sans-serif; padding:6px 10px; border-radius:999px; white-space:nowrap; }}
  table.meta {{ width:100%; border-collapse:collapse; margin:6px 0; }}
  table.meta th {{ text-align:left; color:var(--muted); font-weight:500; width:190px; vertical-align:top; padding:4px 8px 4px 0; font-size:13px; }}
  table.meta td {{ padding:4px 0; font-size:13px; }}
  code {{ background:#f1f5f9; padding:1px 5px; border-radius:4px; font-size:12px; }}
  pre.diff {{ background:#0f172a; color:#e2e8f0; padding:12px; border-radius:8px; overflow:auto; font-size:12px; line-height:1.5; }}
  pre.diff .add {{ color:#4ade80; }} pre.diff .del {{ color:#f87171; }} pre.diff .hdr {{ color:#94a3b8; }}
  .muted {{ color:var(--muted); }}
  footer {{ color:var(--muted); font-size:12px; margin-top:24px; border-top:1px solid var(--line); padding-top:10px; }}
</style></head><body>
<h1>🛡️ PatchProof Report</h1>
<p class="sub">Find the flaw, prove the fix. Target: <code>{html.escape(d['target'])}</code></p>
<div class="kpis">
  <div class="kpi"><b>{s['total_findings']}</b><span>findings</span></div>
  <div class="kpi"><b>{s['confirmed']}</b><span>confirmed by exploit</span></div>
  <div class="kpi"><b>{s['fixed']}</b><span>fixed &amp; verified</span></div>
</div>
{''.join(rows)}
<footer>Every finding above is confirmed by an executable exploit before it is acted on, and every accepted
fix is proven to block that exploit while the regression suite stays green. Synthetic data only.</footer>
</body></html>"""
    Path(path).write_text(doc)


def _color_diff(diff: str) -> str:
    out = []
    for line in diff.splitlines():
        e = html.escape(line)
        if line.startswith("+") and not line.startswith("+++"):
            out.append(f"<span class='add'>{e}</span>")
        elif line.startswith("-") and not line.startswith("---"):
            out.append(f"<span class='del'>{e}</span>")
        elif line.startswith(("@@", "+++", "---")):
            out.append(f"<span class='hdr'>{e}</span>")
        else:
            out.append(e)
    return "\n".join(out)
