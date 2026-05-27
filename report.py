from pathlib import Path
import json
from html import escape

def write_outputs(alerts, out_dir: str):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'alerts.json').write_text(json.dumps(alerts, indent=2), encoding='utf-8')
    rows = []
    for alert in alerts:
        actions = ''.join('<li>' + escape(a) + '</li>' for a in alert.get('recommended_actions', []))
        mitre = ', '.join(alert.get('mitre', []))
        rows.append("<tr class='" + escape(alert['severity']) + "'><td>" + escape(alert['alert_id']) + "</td><td>" + escape(alert['title']) + "</td><td>" + escape(alert['user']) + "</td><td>" + escape(alert['source_ip']) + "</td><td>" + escape(alert['host']) + "</td><td>" + str(alert['score']) + "</td><td>" + escape(alert['severity']) + "</td><td>" + escape(mitre) + "</td><td><ul>" + actions + "</ul></td></tr>")
    html = """<!doctype html><html><head><meta charset='utf-8'><title>SOC Triage Report</title><style>
body { font-family: Arial, sans-serif; margin: 24px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
th { background: #f4f4f4; }
.Critical { background: #ffd7d7; }
.High { background: #ffe7cc; }
.Medium { background: #fff7cf; }
.Low { background: #e8f5e9; }
</style></head><body><h1>SOC Triage Report</h1><p>Generated alerts: """ + str(len(alerts)) + """</p><table><thead><tr><th>ID</th><th>Title</th><th>User</th><th>IP</th><th>Host</th><th>Score</th><th>Severity</th><th>MITRE</th><th>Actions</th></tr></thead><tbody>""" + ''.join(rows) + """</tbody></table></body></html>"""
    (out / 'report.html').write_text(html, encoding='utf-8')
