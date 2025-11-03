import sys
import json
import os
sys.path.append(os.getcwd())
from ai_projects import day1_alertclassifier
from src import logger_config
from src.cache_handler import CacheHandler

from logging import getLogger
logger=getLogger(__name__)
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
total_hits=0
cache_hits=0
cache_data={}
#Cache load
base_path=os.getcwd()
cache_path=os.path.join(base_path,"cache")
os.makedirs(cache_path,exist_ok=True)
#file_name=f"{str(alert['source_ip']).replace(".","_")}.json"
file_name="cache.json"
file_path=os.path.join(cache_path,file_name)
cachehandler= CacheHandler()
cachehandler.file_path=file_path
if os.path.exists(file_path):
    cache_data=cachehandler.load_cache() # Loading existing cache
if cache_data:
    cache_data=cachehandler.prune_old_cache(cache_data) # Pruning old cache
for alerts in test_cases:
    total_hits+=1
    print(f"="*50)
    print(f"Analysing the alert {alerts['name']}")
    print(f"="*50)
    try:
        logger.debug("Classifying alert")
        ai_output,token_count,cache_data=day1_alertclassifier.classify_alert(alerts['alert'],cache_data)
        if ai_output:
            logger.debug("Parsing alert")
            result_json=day1_alertclassifier.parse_alert_json(ai_output)
            if result_json:
                print(f"Classification: {result_json['classification']}\n")
                print(f"Confidence: {result_json['confidence']}\n")
                print(f"Reasoning: {result_json['reasoning']}\n")
            else:
                print("Parsing failed")
                logger.error("No AI Response")
        else:
            print("No AI response")
            logger.error("No AI Response")
        if token_count:
            total_prompt_tokens += token_count["PromptToken"]
            total_completion_tokens += token_count["CandidateToken"]
            successful_classifications += 1
            cost = day1_alertclassifier.calculate_cost(token_count)
            print(f"Token Usage: {token_count}\n")
            print(f"Cost of this alert analysis: ${cost}\n")
        else:
            logger.error("Token count not available\n")
            print("Token count not available\n")
    except Exception as e:
        logger.error(e)
        print(e)
if cache_data:
    cachehandler.cache_ip(cache_data)

print("BATCH SUMMARY")
print("="*60)
print(f"Total Successful Classifications: {successful_classifications}")
print(f"Total Token Usage: {total_prompt_tokens+total_completion_tokens}")
print(f"Total Cost: ${day1_alertclassifier.calculate_cost({'PromptToken': total_prompt_tokens, 'CandidateToken': total_completion_tokens})}")
for keys,values in cache_data.items():
    print(f"cache hits for {keys} = {values['CacheHit']}")