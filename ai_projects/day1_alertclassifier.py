from google import genai
import os
from dotenv import load_dotenv
load_dotenv()
import re
from datetime import datetime,timedelta
import json
import time
import sys
import json
import time
from ai_projects import day2_threatintel
sys.path.append(os.getcwd())
from src import logger_config
from src.logger_config import get_logger
logger=get_logger(__name__)

def build_prompt(alert,abuse_response,vt_response):
    """
    Takes Alert dictionary and builds a prompt
    """
    prompt = f"""
You are a SOC analyst
Analyze this login alert
- User:{alert['user']}
- SourceIP:{alert['source_ip']}
- Number of Login Failures: {alert['failed_logins']}
- Login Status: {alert['success']} 
- Time of activity: {alert['time']}
- IP location: {alert['location']}

This is what the threat intel feeds say about the IP
AbuseIPDB:{abuse_response}
VirusTotal:{vt_response}

Is this suspicious?
Classify as :
 - TRUE_POSITIVE (real attack)
 - FALSE_POSITIVE (legitimate behaviour)
 - NEEDS_REVIEW (uncler)

 Think step by step, use Threat Intel enrichment provided to aid your reasoning and then provide:
 1. Classification
 2. Confidence Score (0-100%)
 3. Reasoning - 3 bullets , 50 words each
                
 Format as Json:
 {{
    "classification":"TRUE_POSITIVE",
    "confidence":95,
    "reasoning": "
                - how you arrived at the result?
                - what is the supporting data?
                - what makes the classfication fool proof"
 }}
"""
    return prompt

def classify_alert(alert,cache_data,max_retries=3,):
    """
    Alert -> Threat Intel -> Cache -> AI -> classification
    """
    ip_to_check=alert['source_ip']
    itemtocheck=cache_data.get(ip_to_check,0)
    if not cache_data:
        abuse_response,vt_response=day2_threatintel.ip_lookup(ip_to_check)
        data_to_cache={
            "IP":ip_to_check,
            "AbuseIntel":abuse_response,
            "VTIntel":vt_response,
            "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "CacheHit":0
            }
        cache_data.update({ip_to_check:data_to_cache})
    elif itemtocheck==0:
        abuse_response,vt_response=day2_threatintel.ip_lookup(ip_to_check)
        data_to_cache={
            "IP":ip_to_check,
            "AbuseIntel":abuse_response,
            "VTIntel":vt_response,
            "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "CacheHit":0
            }
        cache_data.update({ip_to_check:data_to_cache})
    else:
        abuse_response=cache_data[ip_to_check]['AbuseIntel']
        vt_response=cache_data[ip_to_check]['VTIntel'] 
        cache_data[ip_to_check]['CacheHit']+=1
    
    for attempts in range(max_retries):
        try:
            gemini_key=os.getenv('GEMINIKEY')
            client=genai.Client(api_key=gemini_key)
            response=client.models.generate_content(
                model='gemini-2.5-flash',contents=build_prompt(alert,abuse_response,vt_response)
            )
            token_data={
                "PromptToken":getattr(response.usage_metadata,"prompt_token_count",0),
                "TotalToken":getattr(response.usage_metadata,"total_token_count",0),
                "CandidateToken":getattr(response.usage_metadata,"candidates_token_count",0),
                "ToolUsePromptToken":getattr(response.usage_metadata,"tool_use_prompt_token_count",0),
                "CacheToken":getattr(response.usage_metadata,"cache_token_count",0),
                "ThoughtsToken":getattr(response.usage_metadata,"thoughts_token_count",0)
            }
            return response.text,token_data,cache_data
        except Exception as e:
            if attempts < max_retries - 1:
                print(f"Attempt {attempts + 1} failed: {e}. Retrying...")
                time.sleep(2**attempts)
                continue
            logger.error(e)
            return None


def parse_alert_json(ai_output):
    """
    Parse the results of AI output to format a clean Output
    """
    try:
        json_output=re.search(r"\{.*?\}",ai_output,re.DOTALL)
        if json_output:
            result=json_output.group()
            result_json=json.loads(result)
            return result_json
        else:
            return None   
    except Exception as e:
        logger.error(e)
        return None

def calculate_cost(token):
    try:
        prompt_token_cost=1 #$ per 1M tokens
        output_token_cost=10 #$ per 1M tokens
        total_cost=prompt_token_cost*token["PromptToken"]/1_000_000 + output_token_cost*token["CandidateToken"]/1_000_000
        return total_cost
    except Exception as e:
        logger.error(e)
        return None

def cache_ip(file_path,data):
    logger.debug(f"Caching ip {data['IP']}")
    try:
        with open (file_path,"w") as f:
            json.dump(data,f,indent=4)           
    except Exception as e:
        logger.error(e)

def load_cache(file_path):
    try:
        with open(file_path,"r") as f:
           data= json.load(f)
        return data
    except Exception as e:
        logger.error(e)

def prune_old_cache(cache_dump):
    logger.debug("Pruning old cache")
    ttl=3600
    try:
        listofkeys=list(cache_dump.keys())
        prunecount=0
        for keys in listofkeys:
            logger.debug(f"Checking {keys} for pruning ")
            timestamp=cache_dump[keys].get("Timestamp","")
            timediff=datetime.now()-datetime.strptime(timestamp,"%Y-%m-%d %H:%M:%S")
            if timediff>timedelta(seconds=ttl):
                cache_dump.pop(keys)
                prunecount+=1
        logger.debug(f"Pruned item count: {prunecount}")
        return cache_dump
    except Exception as e:
        logger.error(e)
        return None