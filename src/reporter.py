import json
import os
from datetime import datetime

from config import REPORTS_DIR


# Colour per validation status
_STATUS_COLOUR = {
    "CONFIRMED EXPLOITABLE": "#c0392b",
    "NOT REPRODUCED": "#7f8c8d",
    "PENDING": "#e67e22",
}


def _validation_html(validation_results: list) -> str:
    if not validation_results:
        return ""
    rows = ""
    for v in validation_results:
        action = v.get("action", {})
        result = v.get("result", {})
        status = v.get("status", "PENDING")
        colour = _STATUS_COLOUR.get(status, "#7f8c8d")
        rows += f"""
        <div class="validation-result">
            <span class="status-badge" style="background:{colour}">{status}</span>
            <p><strong>Action:</strong> {action.get('action', '')}</p>
            <p><strong>Endpoint:</strong> {action.get('endpoint', '')}</p>
            <p><strong>Payload:</strong> <code>{action.get('payload', '')}</code></p>
            <p><strong>Signal:</strong> {result.get('success_signal', '')}</p>
            <p><strong>Confidence:</strong> {result.get('confidence', '')}</p>
        </div>"""
    return f"<h2>Validation Results</h2>{rows}"


def _recon_html(recon_data: dict) -> str:
    if not recon_data:
        return ""
    ep_count = len(recon_data.get("endpoints", []))
    form_count = len(recon_data.get("forms", []))
    xhr_count = len(recon_data.get("client_behaviour", []))

    endpoints_html = "".join(f"<li>{e}</li>" for e in recon_data.get("endpoints", []))

    forms_html = ""
    for form in recon_data.get("forms", []):
        fields = ", ".join(
            f"{f['name']} ({f['type']})" for f in form.get("fields", []) if f.get("name")
        )
        forms_html += (
            f"<li><strong>{form.get('method','?')}</strong> {form.get('action','')} "
            f"&mdash; fields: {fields or 'none'}</li>"
        )

    inputs_html = "".join(
        f"<li>{i.get('param')} ({i.get('type')}) @ {i.get('url')}</li>"
        for i in recon_data.get("inputs", [])
    )

    headers_html = ""
    for url, hdrs in recon_data.get("headers", {}).items():
        interesting = {
            k: v for k, v in hdrs.items()
            if k.lower() in ("server", "x-powered-by", "content-type", "set-cookie",
                             "x-frame-options", "content-security-policy", "strict-transport-security")
        }
        if interesting:
            rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in interesting.items())
            headers_html += f"<p><strong>{url}</strong></p><table>{rows}</table>"

    xhr_html = "".join(
        f"<li>{x.get('method')} {x.get('url')}</li>"
        for x in recon_data.get("client_behaviour", [])
    ) or "<li>None detected</li>"

    cookies_html = "".join(
        f"<li><code>{c.get('name')}={c.get('value','')[:40]}{'...' if len(c.get('value',''))>40 else ''}</code> "
        f"(domain: {c.get('domain','?')})</li>"
        for c in recon_data.get("session_cookies", [])
    ) or "<li>None</li>"

    return f"""
    <h2>Recon Details</h2>
    <div class="meta">
        <p><strong>Endpoints crawled:</strong> {ep_count} &nbsp;|&nbsp;
           <strong>Forms found:</strong> {form_count} &nbsp;|&nbsp;
           <strong>XHR/fetch calls:</strong> {xhr_count}</p>
    </div>
    <details><summary><strong>All Endpoints ({ep_count})</strong></summary>
        <ul class="detail-list">{endpoints_html}</ul></details>
    <details><summary><strong>Forms ({form_count})</strong></summary>
        <ul class="detail-list">{forms_html}</ul></details>
    <details><summary><strong>Inputs Observed ({len(recon_data.get('inputs',[]))})</strong></summary>
        <ul class="detail-list">{inputs_html}</ul></details>
    <details><summary><strong>Response Headers</strong></summary>
        <div class="detail-list">{headers_html or 'None captured'}</div></details>
    <details><summary><strong>XHR / Fetch Calls</strong></summary>
        <ul class="detail-list">{xhr_html}</ul></details>
    <details><summary><strong>Session Cookies Passed to Scanner</strong></summary>
        <ul class="detail-list">{cookies_html}</ul></details>"""


def _llm_context_html(ctx: dict) -> str:
    if not ctx:
        return ""

    phase2_summary = ctx.get("phase2_recon_summary", "") or "N/A"

    phase2_prompt = ctx.get("phase2_selection_prompt", [])
    prompt_html = ""
    for msg in phase2_prompt:
        prompt_html += (
            f"<p><strong>[{msg.get('role','?').upper()}]</strong></p>"
            f"<pre>{msg.get('content','')}</pre>"
        )

    vuln_eps = ctx.get("phase3_vuln_endpoints", [])
    vuln_html = "".join(f"<li>{e}</li>" for e in vuln_eps) or "<li>None</li>"

    hc = ctx.get("phase3_high_critical_passed", [])
    hc_html = f"<pre>{json.dumps(hc, indent=2)}</pre>" if hc else "<p>None (Phase 3 triggered from recon endpoints only)</p>"

    return f"""
    <h2>LLM Context</h2>
    <details><summary><strong>Phase 2 — Recon Summary Sent to LLM</strong></summary>
        <pre class="llm-ctx">{phase2_summary}</pre></details>
    <details><summary><strong>Phase 2 — Full Selection Prompt</strong></summary>
        <div class="llm-ctx">{prompt_html}</div></details>
    <details><summary><strong>Phase 3 — Vuln Endpoints Passed to LLM ({len(vuln_eps)})</strong></summary>
        <ul class="detail-list">{vuln_html}</ul></details>
    <details><summary><strong>Phase 3 — High/Critical Findings Passed to LLM</strong></summary>
        {hc_html}</details>"""


def _token_usage_html(usage: dict) -> str:
    if not usage:
        return ""
    p = usage.get("prompt_tokens", 0)
    c = usage.get("completion_tokens", 0)
    t = usage.get("total_tokens", 0)
    return (
        f"<p><strong>Token usage:</strong> "
        f"{t} total &nbsp;({p} prompt + {c} completion)</p>"
    )


def save_report(data: dict) -> tuple[str, str]:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(REPORTS_DIR, f"report_{ts}.json")
    # Exclude raw_output from JSON to keep it readable; it's terminal noise
    json_data = {k: v for k, v in data.items() if k != "raw_output"}
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2)

    html_path = os.path.join(REPORTS_DIR, f"report_{ts}.html")

    findings_html = ""
    for finding in data.get("findings", []):
        # Per-finding validation block (if any matched)
        matched = [
            v for v in data.get("validation_results", [])
            if v.get("action", {}).get("notes", "").lower() in finding.get("title", "").lower()
            or finding.get("title", "").lower() in v.get("action", {}).get("notes", "").lower()
        ]
        val_snippet = ""
        for v in matched:
            status = v.get("status", "PENDING")
            colour = _STATUS_COLOUR.get(status, "#7f8c8d")
            val_snippet += (
                f'<span class="status-badge" style="background:{colour}">'
                f'{status}</span> '
                f'{v["result"].get("success_signal", "")}'
            )

        findings_html += f"""
        <div class="finding">
            <h3>{finding.get('title', 'Finding')}</h3>
            <p><strong>Severity:</strong> {finding.get('severity', 'Unknown')}</p>
            <p><strong>Description:</strong> {finding.get('description', '')}</p>
            <p><strong>Evidence:</strong> {finding.get('evidence', '')}</p>
            <p><strong>Remediation:</strong> {finding.get('remediation', '')}</p>
            {f'<p><strong>Validation:</strong> {val_snippet}</p>' if val_snippet else ''}
        </div>"""

    recon_section = _recon_html(data.get("recon_data", {}))
    validation_section = _validation_html(data.get("validation_results", []))
    llm_context_section = _llm_context_html(data.get("llm_context", {}))

    with open(html_path, "w") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>miniBravos Report — {ts}</title>
  <style>
    body {{ font-family: sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; background: #f9f9f9; }}
    h1 {{ color: #c0392b; }}
    h2 {{ color: #2c3e50; margin-top: 32px; }}
    .meta {{ background: #fff; border: 1px solid #ddd; padding: 16px; border-radius: 6px; margin-bottom: 24px; }}
    .finding {{ background: #fff; border-left: 4px solid #c0392b; padding: 16px; margin-bottom: 16px; border-radius: 4px; }}
    .finding h3 {{ margin-top: 0; }}
    .validation-result {{ background: #fff; border-left: 4px solid #2980b9; padding: 16px; margin-bottom: 12px; border-radius: 4px; }}
    .status-badge {{ color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }}
    .summary {{ background: #fff; border: 1px solid #ddd; padding: 16px; border-radius: 6px; margin-top: 24px; white-space: pre-wrap; }}
    code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 0.9em; }}
    details {{ background: #fff; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 8px; }}
    details summary {{ padding: 10px 14px; cursor: pointer; user-select: none; }}
    details summary:hover {{ background: #f0f0f0; }}
    details[open] summary {{ border-bottom: 1px solid #ddd; }}
    .detail-list {{ margin: 0; padding: 12px 12px 12px 28px; font-size: 0.9em; word-break: break-all; }}
    .detail-list li {{ margin-bottom: 4px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 0.85em; }}
    td {{ border: 1px solid #ddd; padding: 6px 10px; vertical-align: top; word-break: break-all; }}
    pre {{ margin: 0; padding: 12px; background: #f7f7f7; font-size: 0.82em; white-space: pre-wrap; word-break: break-all; }}
    .llm-ctx {{ padding: 12px; font-size: 0.85em; }}
  </style>
</head>
<body>
  <h1>miniBravos Scan Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> {data['target']}</p>
    <p><strong>Scope:</strong> {data['scope']}</p>
    <p><strong>Template:</strong> {data['template_used']}</p>
    <p><strong>Model:</strong> {data.get('model', 'unknown')}</p>
    <p><strong>Timestamp:</strong> {data['timestamp']}</p>
    {_token_usage_html(data.get('token_usage', {}))}
  </div>
  {recon_section}
  {llm_context_section}
  <h2>Findings</h2>
  {findings_html if findings_html else '<p>No findings extracted.</p>'}
  {validation_section}
  <h2>Agent Interpretation</h2>
  <div class="summary">{data.get('interpretation', '')}</div>
</body>
</html>""")

    return json_path, html_path
