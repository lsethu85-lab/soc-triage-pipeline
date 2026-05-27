from collections import defaultdict

def correlate(detections):
    grouped = defaultdict(list)
    for det in detections:
        grouped[(det['ip'], det['user'], det['host'])].append(det)
    correlated = list(detections)
    for (ip, user, host), dets in grouped.items():
        names = {d['rule_name'] for d in dets}
        if {'bruteforce_login', 'suspicious_admin_success', 'privilege_escalation'}.issubset(names):
            total = sum(int(d['count']) for d in dets)
            correlated.append({'rule_name': 'correlated_account_takeover_chain', 'title': 'Bruteforce followed by admin login and privilege escalation', 'ip': ip, 'user': user, 'host': host, 'count': total, 'base_score': 85, 'mitre': ['T1110', 'T1078', 'TA0004'], 'events': sum([d.get('events', []) for d in dets], []), 'correlation_notes': ['Observed failed login sequence', 'Observed admin login success', 'Observed privilege escalation attempt']})
    return correlated
