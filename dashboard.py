import argparse
import json
from pathlib import Path
from html import escape

def build_dashboard(alerts_path: str, out_path: str):
    alerts = json.loads(Path(alerts_path).read_text(encoding='utf-8'))
    severity_counts = {}
    for alert in alerts:
        severity_counts[alert['severity']] = severity_counts.get(alert['severity'], 0) + 1
    cards = ''.join("<div class='card'><h3>" + escape(k) + "</h3><p>" + str(v) + "</p></div>" for k, v in sorted(severity_counts.items()))
    rows = ''.join("<tr><td>" + escape(a['alert_id']) + "</td><td>" + escape(a['title']) + "</td><td>" + escape(a['severity']) + "</td><td>" + str(a['score']) + "</td><td>" + escape(a['host']) + "</td><td>" + escape(a['source_ip']) + "</td></tr>" for a in alerts)
    html = """<!doctype html><html><head><meta charset='utf-8'><title>SOC Dashboard</title><style>
body { font-family: Arial, sans-serif; margin: 24px; }
.grid { display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: #f6f8fa; border: 1px solid #ddd; border-radius: 12px; padding: 12px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
</style></head><body><h1>SOC Dashboard</h1><div class='grid'>""" + cards + """</div><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Score</th><th>Host</th><th>Source IP</th></tr></thead><tbody>""" + rows + """</tbody></table></body></html>"""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(html, encoding='utf-8')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--alerts', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    build_dashboard(args.alerts, args.out)
    print('Wrote dashboard to ' + args.out)

if __name__ == '__main__':
    main()
