def recommend_actions(rule_name: str):
    mapping = {
        'bruteforce_login': [
            'Review authentication logs and account lockout status',
            'Block or challenge the source IP if malicious',
            'Reset or protect the affected account with MFA'
        ],
        'privilege_escalation': [
            'Inspect endpoint process tree and audit logs',
            'Validate whether the privilege change was approved',
            'Isolate affected host if activity is unauthorized'
        ],
        'suspicious_admin_success': [
            'Verify admin sign-in origin and business justification',
            'Collect related authentication and endpoint logs',
            'Reset credentials if compromise is suspected'
        ],
        'ransomware_keyword': [
            'Isolate impacted endpoint or file server',
            'Preserve forensic evidence and review file operations',
            'Validate backup integrity and scope of encryption'
        ],
        'correlated_account_takeover_chain': [
            'Treat as high-priority account compromise',
            'Suspend the account and rotate credentials',
            'Hunt across hosts for lateral movement or persistence'
        ]
    }
    return mapping.get(rule_name, ['Review event context and escalate as needed'])
