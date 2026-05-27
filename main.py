import argparse
from pathlib import Path
from .parser import parse_log_file
from .config import load_rules
from .enrich import load_ioc_feed, enrich_ip
from .detections import detect
from .correlation import correlate
from .scoring import score_alert
from .recommendations import recommend_actions
from .report import write_outputs
from .github_security import load_github_security_events
from .models import Alert

def build_alerts(input_path: str, ioc_path: str, rules_path: str, github_events_path: str = None):
    events = parse_log_file(input_path)
    rule_doc = load_rules(rules_path)
    ioc_feed = load_ioc_feed(ioc_path)
    ioc_lookup = lambda ip: enrich_ip(ip, ioc_feed)
    detections = correlate(detect(events, rule_doc.get('rules', []), ioc_lookup))
    alerts = []
    for idx, d in enumerate(detections, start=1):
        enrichment = ioc_lookup(d['ip'])
        boost = 10 if d['rule_name'].startswith('correlated_') else 0
        score, severity = score_alert(d['base_score'], d['user'], d['count'], enrichment, correlation_boost=boost)
        alert = Alert(alert_id=f'SOC-{idx:04d}', title=d['title'], rule_name=d['rule_name'], user=d['user'], source_ip=d['ip'], host=d['host'], count=d['count'], score=score, severity=severity, mitre=d.get('mitre', []), ioc_enrichment=enrichment, correlation_notes=d.get('correlation_notes', []), recommended_actions=recommend_actions(d['rule_name']))
        alerts.append(alert.to_dict())
    if github_events_path and Path(github_events_path).exists():
        gh_events = load_github_security_events(github_events_path)
        for gh_idx, evt in enumerate(gh_events, start=len(alerts)+1):
            score = 75 if evt.get('severity') == 'high' else 55
            severity = 'High' if score >= 60 else 'Medium'
            alerts.append(Alert(alert_id=f'SOC-{gh_idx:04d}', title='GitHub security event: ' + str(evt.get('event_type')), rule_name='github_security_event', user=evt.get('actor', 'unknown'), source_ip='n/a', host=evt.get('repo', 'github'), count=1, score=score, severity=severity, mitre=[], ioc_enrichment={'reputation':'n/a','confidence':0,'source':'github_events'}, correlation_notes=[evt.get('detail','')], recommended_actions=['Review GitHub security finding details','Validate remediation status in repository']).to_dict())
    return alerts

def main():
    parser = argparse.ArgumentParser(description='SOC triage and enrichment pipeline')
    parser.add_argument('--input', required=True)
    parser.add_argument('--ioc', required=True)
    parser.add_argument('--rules', required=True)
    parser.add_argument('--github-events', default='data/github_events.json')
    parser.add_argument('--out', default='output')
    args = parser.parse_args()
    alerts = build_alerts(args.input, args.ioc, args.rules, args.github_events)
    write_outputs(alerts, args.out)
    print('Generated ' + str(len(alerts)) + ' alerts into ' + args.out)

if __name__ == '__main__':
    main()
