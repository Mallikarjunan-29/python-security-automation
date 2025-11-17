import sys
import time
import copy
import json
import os
sys.path.append(os.path.join(os.getcwd()))
from src.alert_queue import queue_alert
from src import test_data
from ai_projects import day1_alertclassifier
from src import logger_config
from src.cache_handler import CacheHandler
from concurrent.futures import ThreadPoolExecutor,as_completed
from logging import getLogger
from ai_projects.week2_rag.day3_document_loader import load_all_documents
from src.root_path_calculator import find_project_root
from src.ai_response_handler import AI_response_handler

logger=getLogger(__name__)

ai_response_handler=AI_response_handler("security_docs")

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
    ai_output,token_count,response_key=day1_alertclassifier.classify_alert(alerts,alert_ti_cache_data,alert_ai_cache_data,alert_timing)
    #print(ai_output)
    if token_count:
        total_prompt_tokens += token_count["PromptToken"]
        total_completion_tokens += token_count["CandidateToken"]
        if token_count["ThoughtsToken"]:
            thoughts_token_count+=token_count["ThoughtsToken"]
        
        if token_count["PromptToken"]==0:
            start_time=time.time()
            #print("AI Response loaded from Cache, hence 0 cost")
            end_time=time.time()-start_time
            alert_timing.update({"CalculateCost":0})
        else:            
            start_time=time.time()
            cost = day1_alertclassifier.calculate_cost(token_count)
            end_time=time.time()-start_time
            alert_timing.update({"CalculateCost":end_time})
           # print(f"Token Usage: {token_count}\n")
            #print(f"Cost of this alert analysis: ${cost}\n")
    else:
        logger.error("Token count not available\n")
       # print("Token count not available\n")
    thread_end=time.time()-thread_start
    # ============================================================
    # SECTION FOR FETCHING RUNBOOKS
    # ============================================================
    result=ai_response_handler.search(ai_output['semantic'])
    #print(result['distances'][0])
    # ============================================================
    # SECTION FOR FETCHING RUNBOOKS END
    # ============================================================
        
    output={
        "alert":alerts,
        "Classification": ai_output['classification'],
        "Confidence": ai_output['confidence'],
        "Reasoning": ai_output['reasoning'],
        "AISeverity":ai_output['severity'],
        "TotalTime":thread_end,
        "TimingBreakDown":alert_timing.copy(),
        "TI_Cache":alert_ti_cache_data.copy(),
        "AI_Cache":alert_ai_cache_data.copy(),
        "AIResponseKey":response_key,
    }
    
    if result['documents'] and  len(result['documents'][0])>0:
        output.update({"runbooks":result['documents'][0][0]})
    return output
  except Exception as e:
      logger.error(e)


def test_function(alerts):
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
        #Cache load
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
            logger.debug("Loading ti cache")
            start_time=time.time()
            ti_cache_data=cachehandler.load_cache(ti_file_path) # Loading existing cache
            end_time=time.time()-start_time
            logger.debug("TI cache loaded")
            timing.update({"TI_CacheLoad":end_time})
        else:
            logger.debug("No TI Cache to Load")
            timing.update({"TI_CacheLoad":0})
        if ti_cache_data:
            logger.debug("Pruning TI cache")
            start_time=time.time()
            ti_cache_data=cachehandler.prune_old_cache(ti_cache_data) # Pruning old cache
            end_time=time.time()-start_time
            logger.debug("TI Cache pruned")
            timing.update({"TI_CachePrune":end_time})
        else:
            logger.debug("No TI Cache to prune")
            timing.update({"TI_CachePrune":0})
        if os.path.exists(ai_file_path):
            logger.debug("Loading AI cache")
            start_time=time.time()
            ai_cache_data=cachehandler.load_cache(ai_file_path) # Loading existing cache
            end_time=time.time()-start_time
            timing.update({"AI_CacheLoad":end_time})
            logger.debug("AI cache Loaded")
        else:
            timing.update({"AI_CacheLoad":0})
            logger.debug("No AI cache to load")
        if ai_cache_data:
            logger.debug("Pruning AI cache")
            start_time=time.time()
            ai_cache_data=cachehandler.prune_old_cache(ai_cache_data) # Pruning old cache
            end_time=time.time()-start_time
            timing.update({"AI_CachePrune":end_time})
            logger.debug("AI cache pruned")
        else:
            logger.debug("No AI cache to prune")
            timing.update({"AI_CachePrune":0})
        
        # ============================================================
        # SECTION FOR STORING RUNBOOKS
        # ============================================================
        # ------------------------------------------------------------
        # FETCHING SECURITY DOCUMENTS FROM KB
        # ------------------------------------------------------------
        project_root=find_project_root()
        doc_path=os.path.join(project_root,"data/security_docs")
        chromadata=load_all_documents(doc_path)
        # ------------------------------------------------------------
        # INDEXING THE DOC INTO EPHEMERAL CLIENT
        # ------------------------------------------------------------
        
        ai_response_handler.store_cache(chromadata)
        # ============================================================
        # SECTION FOR STORING RUNBOOKS END
        # ============================================================

        
        #Sorting Alert Queue
        test_alert=queue_alert(alerts)

        #Batch Execution
        logger.debug("Threat Pool execution Started")
        batch_start=time.time()
        with ThreadPoolExecutor(max_workers=3) as exe:
            future=[exe.submit(process_single_alert,alert,ti_cache_data,ai_cache_data,timing) for alert in test_alert]
        batch_end=time.time()-batch_start
        logger.debug("Threat Pool execution ended")
        future_list=[]
        for results in as_completed(future):
            result=results.result()
            future_list.append(result)
            #print(f"Alert finished in {result['TotalTime']}s | Class: {result['Classification']}")
            #print(f"Timing Breakdown: {result['TimingBreakDown']}")
           # New change. the ti and ai cache will be a list
            alert_ti_data=result['TI_Cache']
            alert_ai_data=result['AI_Cache']
            ti_cache_data.update(alert_ti_data)
            ai_cache_data.update(alert_ai_data)
        #print(f"Total batch time:{batch_end}")
        #print("="*50)
        
        
        # Writing Cache
        if ti_cache_data:
            logger.debug("Caching TI data")
            start_time=time.time()
            cachehandler.write_cache(ti_cache_data,ti_file_path)
            end_time=time.time()-start_time
            timing.update({"TI_WriteCache":end_time})
            logger.debug("TI data Cached")
        if ai_cache_data:
            logger.debug("Caching AI data")
            start_time=time.time()
            cachehandler.write_cache(ai_cache_data,ai_file_path)
            end_time=time.time()-start_time
            timing.update({"AI_WriteCache":end_time})
            logger.debug("AI data cached")
        total_time=time.time()-total_time_start
        #print(f"Total run time:{total_time}")
        return future_list,total_time
    except Exception as e:
        logger.error(e)
        print(e)


if __name__=="__main__":
    test_alert = {
    "alert_id": "ALERT-20251115-002",
    "source_ip": "10.10.20.15",
    "destination_ip": "172.16.5.100",
    "source_port": 445,
    "destination_port": 3389,
    "protocol": "TCP",
    "alert_name": "Suspicious RDP Connection Attempt",
    "severity": "High",
    "timestamp": "2025-11-15T12:20:00Z",
    "description": "Detected multiple RDP login attempts from internal host 10.10.20.15 to 172.16.5.100 over port 3389 within 10 minutes.",
    "ioc": {
        "ips": ["10.10.20.15"],
        "urls": [],
        "domains": []
    }
}

if __name__=="__main__":
    print(test_function(test_alert))


