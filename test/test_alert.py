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
successful_classifications = 0
total_prompt_tokens = 0
total_completion_tokens = 0
for alerts in test_cases:
    print(f"="*50)
    print(f"Analysing the alert {alerts['name']}")
    print(f"="*50)
    try:
        ai_output,token_count=day1_alertclassifier.classify_alert(alerts['alert'])
        if ai_output:
            result_json=day1_alertclassifier.parse_alert_json(ai_output)
            if result_json:
                if result_json:
                    print(f"Classification: {result_json['classification']}\n")
                    print(f"Confidence: {result_json['confidence']}\n")
                    print(f"ThreatIntel: {result_json['ThreatIntel']}\n")
                    print(f"Reasoning: {result_json['reasoning']}\n")
                else:
                    print("No Response")
            else:
                print("Parsing failed")
        else:
            print("No AI response")
        if token_count:
            total_prompt_tokens += token_count["PromptToken"]
            total_completion_tokens += token_count["CandidateToken"]
            successful_classifications += 1
            cost = day1_alertclassifier.calculate_cost(token_count)
            print(f"Token Usage: {token_count}\n")
            print(f"Cost of this alert analysis: ${cost}\n")
        else:
            print("Token count not available\n")
    except Exception as e:
        print(e)
print("BATCH SUMMARY")
print("="*60)
print(f"Total Successful Classifications: {successful_classifications}")
print(f"Total Token Usage: {total_prompt_tokens+total_completion_tokens}")
print(f"Total Cost: ${day1_alertclassifier.calculate_cost({'PromptToken': total_prompt_tokens, 'CandidateToken': total_completion_tokens})}")