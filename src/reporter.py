import json
import os
from datetime import datetime

from config import REPORTS_DIR


def save_report(data: dict) -> tuple[str, str]:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(REPORTS_DIR, f"report_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    html_path = os.path.join(REPORTS_DIR, f"report_{ts}.html")
    findings_html = ""
    for finding in data.get("findings", []):
        findings_html += f"""
        <div class="finding">
            <h3>{finding.get('title', 'Finding')}</h3>
            <p><strong>Severity:</strong> {finding.get('severity', 'Unknown')}</p>
            <p><strong>Description:</strong> {finding.get('description', '')}</p>
            <p><strong>Evidence:</strong> {finding.get('evidence', '')}</p>
            <p><strong>Remediation:</strong> {finding.get('remediation', '')}</p>
        </div>"""

    with open(html_path, "w") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>miniBravos Report — {ts}</title>
  <style>
    body {{ font-family: sans-serif; max-width: 860px; margin: 40px auto; padding: 0 20px; background: #f9f9f9; }}
    h1 {{ color: #c0392b; }}
    .meta {{ background: #fff; border: 1px solid #ddd; padding: 16px; border-radius: 6px; margin-bottom: 24px; }}
    .finding {{ background: #fff; border-left: 4px solid #c0392b; padding: 16px; margin-bottom: 16px; border-radius: 4px; }}
    .finding h3 {{ margin-top: 0; }}
    .summary {{ background: #fff; border: 1px solid #ddd; padding: 16px; border-radius: 6px; margin-top: 24px; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>miniBravos Scan Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> {data['target']}</p>
    <p><strong>Scope:</strong> {data['scope']}</p>
    <p><strong>Template:</strong> {data['template_used']}</p>
    <p><strong>Timestamp:</strong> {data['timestamp']}</p>
  </div>
  <h2>Findings</h2>
  {findings_html if findings_html else '<p>No findings extracted.</p>'}
  <h2>Agent Interpretation</h2>
  <div class="summary">{data.get('interpretation', '')}</div>
</body>
</html>""")

    return json_path, html_path
