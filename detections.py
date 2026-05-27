from collections import defaultdict

def _rule_matches(event, rule, enrichment):
    if 'action_equals' in rule and event.action != rule['action_equals']:
        return False
    if 'action_contains' in rule and rule['action_contains'] not in event.action:
        return False
    if 'user_in' in rule and event.user.lower() not in [u.lower() for u in rule['user_in']]:
        return False
    if 'exclude_ioc_reputation' in rule and enrichment.get('reputation') in set(rule['exclude_ioc_reputation']):
        return False
    return True

def detect(events, rules, ioc_lookup):
    detections = []
    grouped = defaultdict(list)
    for event in events:
        grouped[(event.ip, event.user, event.host)].append(event)
    for rule in rules:
        if rule['name'] == 'bruteforce_login':
            for (ip, user, host), evts in grouped.items():
                subset = [e for e in evts if e.action == rule.get('action_equals')]
                if len(subset) >= int(rule.get('threshold', 1)):
                    detections.append({'rule_name': rule['name'], 'title': rule['title'], 'ip': ip, 'user': user, 'host': host, 'count': len(subset), 'base_score': rule['base_score'], 'mitre': rule.get('mitre', []), 'events': [e.timestamp for e in subset]})
        else:
            for event in events:
                enrichment = ioc_lookup(event.ip)
                if _rule_matches(event, rule, enrichment):
                    detections.append({'rule_name': rule['name'], 'title': rule['title'], 'ip': event.ip, 'user': event.user, 'host': event.host, 'count': 1, 'base_score': rule['base_score'], 'mitre': rule.get('mitre', []), 'events': [event.timestamp]})
    return detections
