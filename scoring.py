def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))

def score_alert(base_score: int, user: str, event_count: int, enrichment: dict, correlation_boost: int = 0):
    score = int(base_score)
    reputation = enrichment.get('reputation', 'unknown')
    if reputation == 'malicious':
        score += 25
    elif reputation == 'suspicious':
        score += 15
    if str(user).lower() in {'admin', 'administrator', 'root'}:
        score += 10
    if event_count >= 10:
        score += 10
    elif event_count >= 5:
        score += 5
    score += int(correlation_boost)
    score = clamp(score)
    if score >= 80:
        severity = 'Critical'
    elif score >= 60:
        severity = 'High'
    elif score >= 30:
        severity = 'Medium'
    else:
        severity = 'Low'
    return score, severity
