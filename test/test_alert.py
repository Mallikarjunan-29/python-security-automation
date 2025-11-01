import sys
import os
sys.path.append(os.getcwd())
from ai_projects import day1_alertclassifier

test_cases = [
    {
        "name": "Clear Attack",
        "alert": {
            "user": "alice@company.com",
            "source_ip": "185.220.101.52",
            "failed_logins": 8,
            "success": True,
            "time": "02:00",
            "location": "Moscow, RU"
        },
        "expected": "TRUE_POSITIVE"
    },
    {
        "name": "Normal Admin",
        "alert": {
            "user": "admin@company.com",
            "source_ip": "10.50.1.100",
            "failed_logins": 2,
            "success": True,
            "time": "09:00",
            "location": "New York, US"
        },
        "expected": "FALSE_POSITIVE"
    },
    {
        "name": "Unclear Case",
        "alert": {
            "user": "bob@company.com",
            "source_ip": "203.0.113.50",
            "failed_logins": 4,
            "success": True,
            "time": "18:30",
            "location": "London, UK"
        },
        "expected": "NEEDS_REVIEW"
    }
]

for alerts in test_cases:
    print(f"Analysing the alert {alerts['name']}")
    try:
        ai_output=day1_alertclassifier.classify_alert(alerts['alert'])
        if ai_output:
            result_json=day1_alertclassifier.parse_alert_json(ai_output)
            if result_json:
                if result_json:
                    print("AI ANALYSIS RESULt")
                    print("==================\n")
                    print(f"Classification: {result_json['classification']}\n")
                    print(f"Confidence: {result_json['confidence']}\n")
                    print(f"Reasoning: {result_json['reasoning']}\n")
                else:
                    print("No Response")
            else:
                print("Parsing failed")
        else:
            print("No AI response")
    except Exception as e:
        print(e)
