"""Unified dashboard — one page, two layers."""
from __future__ import annotations

import html
from pathlib import Path

from .core import Layer, Status
from .platform import PlatformResult

_STATUS_COLOR = {
    Status.BLOCKED: ("#b91c1c", "#fee2e2"),
    Status.HELD: ("#b45309", "#fef3c7"),
    Status.ALLOWED: ("#15803d", "#dcfce7"),
    Status.FIXED: ("#15803d", "#dcfce7"),
    Status.REJECTED: ("#b45309", "#fef3c7"),
    Status.UNCONFIRMED: ("#64748b", "#f1f5f9"),
}


def _card(e) -> str:
    color, bg = _STATUS_COLOR.get(e.status, ("#334155", "#f1f5f9"))
    link = (f"<div class='link'>↳ triggered by runtime block on "
            f"<code>{html.escape(e.links[0])}</code></div>" if e.links else "")
    return f"""
    <div class="card">
      <div class="row">
        <span class="title">{html.escape(e.title)}</span>
        <span class="badge" style="color:{color};background:{bg}">{e.status.value.upper()}</span>
      </div>
      <div class="sev">{html.escape(e.severity.upper())} &nbsp;·&nbsp; <code>{html.escape(e.ref)}</code></div>
      <div class="detail">{html.escape(e.detail)}</div>
      <div class="evidence">{html.escape(e.evidence[:260])}</div>
      {link}
    </div>"""


def write_html(result: PlatformResult, path: str | Path) -> None:
    c = result.store.counts()
    runtime_cards = "".join(_card(e) for e in result.runtime)
    code_cards = "".join(_card(e) for e in result.code)
    linked = (f"<p class='note'>A runtime block on "
              f"<b>{', '.join(result.triggered_scans)}</b> automatically triggered a "
              f"code scan of that tool's implementation — the Code column below is "
              f"the root-cause remediation.</p>" if result.triggered_scans else "")

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureAI Platform</title>
<style>
  :root {{ --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --accent:#1e3a8a; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         color:var(--ink); max-width:1000px; margin:0 auto; padding:24px 16px; }}
  h1 {{ margin:0 0 2px; }} .sub {{ color:var(--muted); margin:0 0 16px; }}
  .kpis {{ display:flex; gap:12px; margin-bottom:14px; }}
  .kpi {{ flex:1; background:#f1f5f9; border:1px solid var(--line); border-radius:10px; padding:12px; text-align:center; }}
  .kpi b {{ display:block; font-size:26px; color:var(--accent); }}
  .kpi span {{ color:var(--muted); font-size:12px; }}
  .note {{ background:#eff6ff; border:1px solid #bfdbfe; color:#1e3a8a; padding:10px 12px; border-radius:10px; font-size:13px; }}
  .cols {{ display:flex; gap:16px; align-items:flex-start; }}
  .col {{ flex:1; min-width:0; }}
  .col h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.04em; color:var(--accent); border-bottom:2px solid var(--accent); padding-bottom:6px; }}
  .card {{ border:1px solid var(--line); border-radius:12px; padding:12px; margin-bottom:12px; }}
  .row {{ display:flex; justify-content:space-between; align-items:center; gap:8px; }}
  .title {{ font-weight:600; font-size:14px; }}
  .badge {{ font:600 11px/1 sans-serif; padding:5px 9px; border-radius:999px; white-space:nowrap; }}
  .sev {{ color:var(--muted); font-size:12px; margin:4px 0; }}
  .detail {{ font-size:13px; margin:4px 0; }}
  .evidence {{ font-size:12px; color:var(--muted); font-family:ui-monospace,monospace; }}
  .link {{ margin-top:6px; font-size:12px; color:var(--accent); }}
  code {{ background:#f1f5f9; padding:1px 5px; border-radius:4px; font-size:12px; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:20px; border-top:1px solid var(--line); padding-top:10px; }}
</style></head><body>
<h1>🛡️ SecureAI Platform</h1>
<p class="sub">Guard the agent while it runs — and harden the code it runs on. One platform, two layers.</p>
<div class="kpis">
  <div class="kpi"><b>{c['runtime_blocked']}</b><span>runtime attacks blocked</span></div>
  <div class="kpi"><b>{c['code_fixed']}</b><span>code vulns fixed &amp; verified</span></div>
  <div class="kpi"><b>{len(result.triggered_scans)}</b><span>auto-triggered code scans</span></div>
</div>
{linked}
<div class="cols">
  <div class="col"><h2>Runtime · AgentShield</h2>{runtime_cards}</div>
  <div class="col"><h2>Code · PatchProof</h2>{code_cards}</div>
</div>
<footer>Runtime decisions enforce the tool boundary (allow / hold / block); code results are
exploit-confirmed and gate-verified fixes. The bridge links a runtime block to the code scan it triggered.</footer>
</body></html>"""
    Path(path).write_text(doc)
