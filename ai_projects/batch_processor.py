import sys
import time
import copy
import json
import os
sys.path.append(os.getcwd())
from ai_projects import day1_alertclassifier
from src import logger_config
from src.cache_handler import CacheHandler
from concurrent.futures import ThreadPoolExecutor,as_completed
from logging import getLogger
logger=getLogger(__name__)


test_cases =[
  {
    "name": "Brute Force Attack 1",
    "alert": {
      "user": "alice@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 8,
      "success": True,
      "time": "02:00",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "TOR exit node, brute force pattern"
  },
  {
    "name": "Brute Force Attack 2",
    "alert": {
      "user": "bob@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 9,
      "success": True,
      "time": "02:15",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same attacker, different target - SHOULD CACHE"
  },
  {
    "name": "Brute Force Attack 3",
    "alert": {
      "user": "charlie@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 7,
      "success": True,
      "time": "02:30",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same attacker, third target - SHOULD CACHE"
  },
  {
    "name": "Password Spray 1",
    "alert": {
      "user": "david@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 1,
      "success": True,
      "time": "03:00",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Different pattern (low failures), different IP"
  },
  {
    "name": "Password Spray 2",
    "alert": {
      "user": "eve@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 2,
      "success": True,
      "time": "03:05",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, similar pattern - depends on cache strategy"
  },
  {
    "name": "Legitimate User - Typo",
    "alert": {
      "user": "frank@company.com",
      "source_ip": "10.0.5.100",
      "failed_logins": 2,
      "success": True,
      "time": "09:15",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, business hours, low failures"
  },
  {
    "name": "Legitimate User - VPN",
    "alert": {
      "user": "grace@company.com",
      "source_ip": "203.0.113.25",
      "failed_logins": 1,
      "success": True,
      "time": "10:00",
      "location": "San Francisco, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Clean IP, business hours"
  },
  {
    "name": "Suspicious - Off Hours Internal",
    "alert": {
      "user": "admin@company.com",
      "source_ip": "10.0.10.50",
      "failed_logins": 5,
      "success": True,
      "time": "23:00",
      "location": "Internal"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Internal but suspicious pattern (admin + night + failures)"
  },
  {
    "name": "Credential Stuffing 1",
    "alert": {
      "user": "henry@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 0,
      "success": True,
      "time": "04:00",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Success without failures (leaked creds)"
  },
  {
    "name": "Credential Stuffing 2",
    "alert": {
      "user": "iris@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 0,
      "success": True,
      "time": "04:02",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, same pattern - SHOULD CACHE"
  },
  {
    "name": "Failed Brute Force",
    "alert": {
      "user": "jack@company.com",
      "source_ip": "185.220.102.88",
      "failed_logins": 15,
      "success": False,
      "time": "05:00",
      "location": "Russia"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Attack attempt (failed, but still attack)"
  },
  {
    "name": "Service Account - Normal",
    "alert": {
      "user": "svc-backup@company.com",
      "source_ip": "10.0.2.50",
      "failed_logins": 1,
      "success": True,
      "time": "02:00",
      "location": "Internal"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Service account, internal, scheduled job"
  },
  {
    "name": "VPN Reconnection",
    "alert": {
      "user": "karen@company.com",
      "source_ip": "10.50.1.100",
      "failed_logins": 3,
      "success": True,
      "time": "14:00",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, business hours, low failures"
  },
  {
    "name": "Travel - Legitimate",
    "alert": {
      "user": "larry@company.com",
      "source_ip": "203.0.113.100",
      "failed_logins": 1,
      "success": True,
      "time": "08:00",
      "location": "London, UK"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Clean IP, business hours, but unusual location"
  },
  {
    "name": "Impossible Travel",
    "alert": {
      "user": "mary@company.com",
      "source_ip": "45.142.215.99",
      "failed_logins": 0,
      "success": True,
      "time": "09:00",
      "location": "China"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "If mary logged in from US 1 hour ago, this is impossible"
  }
]


total_timing={
    'TI_CacheLoad':0,
    'TI_CachePrune':0,
    'AI_CacheLoad':0,
    'AI_CachePrune':0,
    'TILookup':0,
    'TI_FromCache':0,
    'AI_ContentGenerate':0,
    'AI_FromCache':0,
    'ParseAlert':0,
    'CalculateCost':0,
    'TI_WriteCache':0,
    'AI_WriteCache':0
}
def process_single_alert(alerts,ti_cache_data,ai_cache_data,timing):
    try:
        alert_timing={
            'TI_CacheLoad':0,
            'TI_CachePrune':0,
            'AI_CacheLoad':0,
            'AI_CachePrune':0,
            'TILookup':0,
            'TI_FromCache':0,
            'AI_ContentGenerate':0,
            'AI_FromCache':0,
            'ParseAlert':0,
            'CalculateCost':0,
            'TI_WriteCache':0,
            'AI_WriteCache':0
            }
        alert_ti_cache_data=copy.deepcopy(ti_cache_data)
        alert_ai_cache_data=copy.deepcopy(ai_cache_data)
        total_prompt_tokens=0
        total_completion_tokens=0
        thoughts_token_count=0
        logger.debug("Classifying alert")
        thread_start=time.time()
        ai_output,token_count,alert_ti_cache_data,alert_ai_cache_data=day1_alertclassifier.classify_alert(alerts['alert'],alert_ti_cache_data,alert_ai_cache_data,alert_timing)
        if ai_output:
            logger.debug("Parsing alert")
            start_time=time.time()
            result_json=day1_alertclassifier.parse_alert_json(ai_output)
            end_time=time.time()-start_time
            alert_timing.update({"ParseAlert":end_time})
            if result_json:
                print(f"Classification: {result_json['classification']}\n")
                print(f"Confidence: {result_json['confidence']}\n")
                print(f"Reasoning: {result_json['reasoning']}")
            else:
                print("Parsing failed")
                logger.error("No AI Response")
        else:
            print("No AI response")
            logger.error("No AI Response")
        if token_count:
            total_prompt_tokens += token_count["PromptToken"]
            total_completion_tokens += token_count["CandidateToken"]
            if token_count["ThoughtsToken"]:
                thoughts_token_count+=token_count["ThoughtsToken"]
            
            if token_count["PromptToken"]==0:
                start_time=time.time()
                print("AI Response loaded from Cache, hence 0 cost")
                end_time=time.time()-start_time
                alert_timing.update({"CalculateCost":0})
            else:            
                start_time=time.time()
                cost = day1_alertclassifier.calculate_cost(token_count)
                end_time=time.time()-start_time
                alert_timing.update({"CalculateCost":end_time})
                print(f"Token Usage: {token_count}\n")
                print(f"Cost of this alert analysis: ${cost}\n")
        else:
            logger.error("Token count not available\n")
            print("Token count not available\n")
        thread_end=time.time()-thread_start
        output={
            "alert_name":alerts['name'],
            "Classification": result_json['classification'],
            "Confidence": result_json['confidence'],
            "Reasoning": result_json['reasoning'],
            "TotalTime":thread_end,
            "TimingBreakDown":alert_timing.copy(),
            "TI_Cache":alert_ti_cache_data.copy(),
            "AI_Cache":alert_ai_cache_data.copy()
        }
        return output
    except Exception as e:
        logger.error(e)


def test_function():
    try:
        
        total_time_start=time.time()
        timing={'TI_CacheLoad':0,
        'TI_CachePrune':0,
        'AI_CacheLoad':0,
        'AI_CachePrune':0,
        'TILookup':0,
        'TI_FromCache':0,
        'AI_ContentGenerate':0,
        'AI_FromCache':0,
        'ParseAlert':0,
        'CalculateCost':0,
        'TI_WriteCache':0,
        'AI_WriteCache':0}
        total_prompt_tokens = 0
        total_completion_tokens = 0
        thoughts_token_count = 0
        #Cache load
        cost=0
        base_path=os.getcwd()
        cache_path=os.path.join(base_path,"cache")
        os.makedirs(cache_path,exist_ok=True)
        #file_name=f"{str(alert['source_ip']).replace(".","_")}.json"
        ti_file_name="cache.json"
        ti_file_path=os.path.join(cache_path,ti_file_name)
        ai_file_name="ai_cache.json"
        ai_file_path=os.path.join(cache_path,ai_file_name)
        cachehandler= CacheHandler()
        ti_cache_data={}
        ai_cache_data={}
        #Loading TI cache
        if os.path.exists(ti_file_path):
            start_time=time.time()
            ti_cache_data=cachehandler.load_cache(ti_file_path) # Loading existing cache
            end_time=time.time()-start_time
            timing.update({"TI_CacheLoad":end_time})
        else:
            timing.update({"TI_CacheLoad":0})
        if ti_cache_data:
            start_time=time.time()
            ti_cache_data=cachehandler.prune_old_cache(ti_cache_data) # Pruning old cache
            end_time=time.time()-start_time
            timing.update({"TI_CachePrune":end_time})
        else:
            timing.update({"TI_CachePrune":0})
        if os.path.exists(ai_file_path):
            start_time=time.time()
            ai_cache_data=cachehandler.load_cache(ai_file_path) # Loading existing cache
            end_time=time.time()-start_time
            timing.update({"AI_CacheLoad":end_time})
        else:
            timing.update({"AI_CacheLoad":0})
        if ai_cache_data:
            start_time=time.time()
            ai_cache_data=cachehandler.prune_old_cache(ai_cache_data) # Pruning old cache
            end_time=time.time()-start_time
            timing.update({"AI_CachePrune":end_time})
        else:
            timing.update({"AI_CachePrune":0})

        
        #Batch Execution
        logger.debug("Threat Pool execution Started")
        batch_start=time.time()
        with ThreadPoolExecutor(max_workers=5) as exe:
            future=[exe.submit(process_single_alert,alert,ti_cache_data,ai_cache_data,timing) for alert in test_cases]
        batch_end=time.time()-batch_start
        logger.debug("Threat Pool execution ended")
        future_list=[]
        for results in as_completed(future):
            result=results.result()
            future_list.append(result)
            print(f"Alert:{result['alert_name']}finished in {result['TotalTime']}s | Class: {result['Classification']}")
            print(f"Timing Breakdown: {result['TimingBreakDown']}")
            alert_ti_data=result['TI_Cache']
            alert_ai_data=result['AI_Cache']
            ti_cache_data.update(alert_ti_data)
            ai_cache_data.update(alert_ai_data)

        print(f"Total batch time:{batch_end}")
        # Writing Cache
        
    
        if ti_cache_data:
            start_time=time.time()
            cachehandler.write_cache(ti_cache_data,ti_file_path)
            end_time=time.time()-start_time
            timing.update({"TI_WriteCache":end_time})
        if ai_cache_data:
            start_time=time.time()
            cachehandler.write_cache(ai_cache_data,ai_file_path)
            end_time=time.time()-start_time
            timing.update({"AI_WriteCache":end_time})
        total_time=time.time()-total_time_start
        print(f"Total run time:{total_time}")
        
    except Exception as e:
        logger.error(e)
        print(e)

test_function()

