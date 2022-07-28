import json
import html
import datetime
from pathlib import Path
from typing import List

from ..engines.base import Finding, Severity


SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e74c3c",
    "MEDIUM":   "#e67e22",
    "LOW":      "#f1c40f",
    "INFO":     "#3498db",
}

SEVERITY_BADGES = {
    "CRITICAL": "background:#c0392b;color:#fff",
    "HIGH":     "background:#e74c3c;color:#fff",
    "MEDIUM":   "background:#e67e22;color:#fff",
    "LOW":      "background:#f1c40f;color:#222",
    "INFO":     "background:#3498db;color:#fff",
}


class Reporter:
    def __init__(self, scan_result):
        self.result = scan_result

    def save_json(self, path: str) -> str:
        output = Path(path)
        output.write_text(json.dumps(self.result.to_dict(), indent=2))
        return str(output)

    def save_html(self, path: str) -> str:
        output = Path(path)
        output.write_text(self._build_html())
        return str(output)

    def _build_html(self) -> str:
        meta     = self.result.metadata
        findings = self.result.findings

        scan_time  = meta.get("scan_start", "N/A")
        duration   = meta.get("duration_seconds", "N/A")
        total      = meta.get("total_findings", 0)
        by_sev     = meta.get("findings_by_severity", {})
        engines    = ", ".join(meta.get("engines_run", []))

        rows = ""
        for i, f in enumerate(findings):
            badge_style = SEVERITY_BADGES.get(f.severity.value, "")
            evidence_json = html.escape(json.dumps(f.evidence, indent=2), quote=False)
            title = html.escape(f.title, quote=False)
            desc = html.escape(f.description, quote=False)
            remed = html.escape(f.remediation, quote=False)
            endpoint = html.escape(f.endpoint, quote=False)
            engine = html.escape(f.engine, quote=False)
            rows += f"""
            <tr>
                <td>{i + 1}</td>
                <td><span class="badge" style="{badge_style}">{f.severity.value}</span></td>
                <td>{engine}</td>
                <td class="mono">{endpoint}</td>
                <td><strong>{title}</strong><br><small>{desc}</small></td>
                <td><pre class="evidence">{evidence_json}</pre></td>
                <td><small>{remed}</small></td>
            </tr>"""

        summary_cards = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = by_sev.get(sev, 0)
            color = SEVERITY_COLORS.get(sev, "#999")
            summary_cards += f"""
            <div class="card" style="border-top:4px solid {color}">
                <div class="card-count" style="color:{color}">{count}</div>
                <div class="card-label">{sev}</div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APIStrike Scan Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; padding: 24px; }}
        h1 {{ color: #fff; font-size: 28px; margin-bottom: 4px; }}
        .subtitle {{ color: #888; font-size: 13px; margin-bottom: 24px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
        .meta-item {{ background: #1a1d27; border-radius: 8px; padding: 12px 16px; }}
        .meta-item label {{ font-size: 11px; text-transform: uppercase; color: #666; display: block; margin-bottom: 4px; }}
        .meta-item span {{ font-size: 14px; color: #ccc; }}
        .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }}
        .card {{ background: #1a1d27; border-radius: 8px; padding: 16px 24px; text-align: center; flex: 1; min-width: 100px; }}
        .card-count {{ font-size: 32px; font-weight: 700; }}
        .card-label {{ font-size: 11px; text-transform: uppercase; color: #888; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a1d27; border-radius: 10px; overflow: hidden; }}
        th {{ background: #12151e; color: #aaa; font-size: 11px; text-transform: uppercase; padding: 12px 14px; text-align: left; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid #22263a; font-size: 13px; vertical-align: top; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #1e2235; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; }}
        .mono {{ font-family: monospace; font-size: 12px; color: #7ec8e3; word-break: break-all; }}
        pre.evidence {{ background: #12151e; border-radius: 6px; padding: 10px; font-size: 11px; color: #a8d8a8; overflow-x: auto; max-width: 300px; white-space: pre-wrap; word-break: break-all; }}
        .no-findings {{ text-align: center; padding: 40px; color: #666; }}
    </style>
</head>
<body>
    <h1>&#9889; APIStrike Scan Report</h1>
    <p class="subtitle">Generated {scan_time} &nbsp;|&nbsp; Duration: {duration}s &nbsp;|&nbsp; Engines: {engines}</p>

    <div class="meta-grid">
        <div class="meta-item"><label>Total Findings</label><span>{total}</span></div>
        <div class="meta-item"><label>Endpoints Probed</label><span>{meta.get("endpoints_probed", "N/A")}</span></div>
        <div class="meta-item"><label>Scan Duration</label><span>{duration}s</span></div>
        <div class="meta-item"><label>Engines Active</label><span>{engines}</span></div>
    </div>

    <div class="summary">{summary_cards}</div>

    {'<table><thead><tr><th>#</th><th>Severity</th><th>Engine</th><th>Endpoint</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>' + rows + '</tbody></table>'
      if findings else '<div class="no-findings">No findings detected.</div>'}
</body>
</html>"""
