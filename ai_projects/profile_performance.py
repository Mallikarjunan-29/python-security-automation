import time
from datetime import datetime
import sys
import os
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)
from src.cache_handler import CacheHandler
from ai_projects import day1_alertclassifier
from ai_projects import day2_threatintel

test={
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
    }

def profile_single_alert(test):

    """
    Time each step of alert processing

    Measure:
    1. Cache check time
    2. Threat intel lookup time (AbuseIPDB + VT)
    3. AI classification time
    4. Response parsing time
    5. Total time
    """
    timings = {}
    cache_handler=CacheHandler()
    base_path=os.getcwd()
    cache_dir=os.path.join(base_path,"cache")
    os.makedirs(cache_dir,exist_ok=True)
    file_path=os.path.join(cache_dir,"cache.json")
    cache_handler.file_path=file_path
    #Calculating Cache Load TAT
    start_time=time.time()
    cached_data=cache_handler.load_cache()
    timings["CacheLoad"]=time.time()-start_time
    #Calculating Cache Prune TAT
    start_time=time.time()
    pruned_cached_data=cache_handler.prune_old_cache(cached_data)
    timings["CachePrune"]=time.time()-start_time
    #Calculating Abuse API TAT
    start_time=time.time()
    abuse_response=day2_threatintel.abuseip_lookup(test['alert']['source_ip'])
    timings["AbuseAPI"]=time.time()-start_time
    #Calculating VT API TAT
    start_time=time.time()
    VT_response=day2_threatintel.vtip_lookup(test['alert']['source_ip'])
    timings["VTAPI"]=time.time()-start_time

    #Calculating Prompt Building TAT
    start_time=time.time()
    ai_prompt=day1_alertclassifier.build_prompt(test["alert"],abuse_response,VT_response)
    timings["Prompt"]=time.time()-start_time

    #Calculating Ai Content Generation TAT
    start_time=time.time()
    ai_response,token_data=day1_alertclassifier.ai_content_generate(ai_prompt)
    timings["AIContent"]=time.time()-start_time

    #Calculating Ai response Parsing TAT
    start_time=time.time()
    parsed_ai_response=day1_alertclassifier.parse_alert_json(ai_response)
    timings["Parsing"]=time.time()-start_time

    #Calculating Token Cost Calculation TAT
    start_time=time.time()
    AI_utilization_cost=day1_alertclassifier.calculate_cost(token_data)
    timings["TokenCost"]=time.time()-start_time
    print("="*50)
    print("TAT ANALYSIS")
    print("="*50)
    for items in timings:
        print(f"{items} : {timings[items]}")

    
     
     
     


profile_single_alert(test)
    