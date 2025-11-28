import re
ATTACK_PATTERS={
    "brute_force":r"brute\s*force|failed\slogins?|failed|login\s*failed|password\s*spray",
    "lateral_movement":r"lateral\s*movement|rdp|smb|psexec",
    "data_exfiltration":r"exfil|large\s*upload|data\s*transfer",
    "privilege_escalation":r"priv.*esc|sudo|runas|elevated?|elevation",
    "phishing":r"suspicious\s*email|malicious\s*email|s*email|malicious|s*link"
}
ATTACK_TO_SOURCE = {
    'brute_force': ['Office365', 'Windows Security 4625', 'VPN logs'],
    'lateral_movement': ['Windows Security 4624', 'EDR', 'Network logs'],
    'data_exfiltration': ['Firewall', 'Proxy', 'Cloud storage logs'],
    'privilege_escalation': ['Windows Security 4672', 'Linux auth logs'],
    'phishing': ['Email gateway', 'Office365 audit logs']
}
DEFAULT_THRESHOLDS = {
    'brute_force': {'threshold': 10, 'time_window': '5m'},
    'lateral_movement': {'threshold': 3, 'time_window': '15m'},
    'data_exfiltration': {'threshold': 100, 'time_window': '1h'},
    'privilege_escalation': {'threshold': 5, 'time_window': '10m'},
    'phishing': {'threshold': 1, 'time_window': 'N/A'}
}
MITRE_MAPPING = {
    'brute_force': ['T1110'],
    'lateral_movement': ['T1021', 'T1078'],
    'data_exfiltration': ['T1041', 'T1567'],
    'privilege_escalation': ['T1068', 'T1548'],
    'phishing': ['T1566']
}

SOURCES = {
        'office365': ['office365', 'o365', 'azure ad'],
        'Windows Security': ['windows', 'event', '4625', '4624'],
        'VPN': ['vpn'],
        'EDR': ['edr', 'crowdstrike', 'defender'],
        'Firewall': ['firewall', 'palo alto'],
        'Proxy': ['proxy'],
        'Email gateway': ['email', 'gateway', 'proofpoint']
    }