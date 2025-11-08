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
from src.rate_limiter import GeminiRateLimiter
from src import logger_config
from src.logger_config import get_logger
logger=get_logger(__name__)
import hashlib

def build_prompt(alert,abuse_response,vt_response):
    logger.debug("Prompt Building Started")
    """
    Takes Alert dictionary and builds a prompt
    """
    human_override=f"- Analyst Override:{alert['human_override'] if 'human_override' in alert and alert['human_override']!="" else ""}"
    prompt = f"""
You are a SOC analyst
Analyze this login alert
- alert:{json.dumps(alert,indent=4)}
{human_override}

This is what the threat intel feeds say about the IP
AbuseIPDB:{abuse_response}
VirusTotal:{vt_response}

Is this suspicious?
Classify as :
 - TRUE_POSITIVE (real attack)
 - FALSE_POSITIVE (legitimate behaviour)
 - NEEDS_REVIEW (uncler)

 INSTRUCTIONS:
- ONLY output a single JSON object with the exact keys: classification, confidence, reasoning.
- classification: one of "TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW" (string).
- confidence: integer 0-100 (no % sign).
- severity: one of "Critical","High","Medium","Low"
- reasoning: array of exactly 3 strings. Each string max 50 words. No bullet characters, no newlines inside items.
- Do NOT output any extra text, commentary, or code fences. Output must be parseable by json.loads().
- Include Analyst override if available

OUTPUT_SCHEMA:
{{
  "classification": "TRUE_POSITIVE",
  "confidence": 95,
  "severity": "Critical",
  "reasoning": [
    "One-sentence reason 1 (<=50 words).",
    "One-sentence reason 2 (<=50 words).",
    "One-sentence reason 3 (<=50 words)."
  ]
}}
"""
    logger.debug("Prompt Building ended")
    return prompt

def classify_alert(alert,ti_cache_data,ai_cache_data,timing,max_retries=3):
    """
    Alert -> Threat Intel -> Cache -> AI -> classification
    """
    try:
        ip_to_check=alert['source_ip']
        itemtocheck=ti_cache_data.get(ip_to_check,0)
        alert_ti_cache={}
        alert_ai_cache={}
        # Loading TI cache data based on conditions
        if not ti_cache_data:
            abuse_response,vt_response=update_ti_cache(alert_ti_cache,timing,ip_to_check)
            timing.update({"TI_FromCache":0})
        elif itemtocheck==0:
            abuse_response,vt_response=update_ti_cache(alert_ti_cache,timing,ip_to_check)
            timing.update({"TI_FromCache":0})
        else:
            logger.debug("Loading TI Response from cache started")
            start_time=time.time()
            alert_ti_cache={ip_to_check:ti_cache_data.get(ip_to_check,0)}
            abuse_response=alert_ti_cache[ip_to_check]['AbuseIntel']
            vt_response=alert_ti_cache[ip_to_check]['VTIntel'] 
            end_time=time.time()-start_time
            timing.update({"TI_FromCache":end_time})
            alert_ti_cache[ip_to_check]['CacheHit']+=1        
            logger.debug("Loading TI Response from cache ended")

        #Loading AI response checker
        response_data= json.dumps({"alert":alert,"AbuseTI":alert_ti_cache[ip_to_check]['AbuseIntel'],"VTTI":alert_ti_cache[ip_to_check]['VTIntel']},sort_keys=True)
        response_key=hashlib.md5(response_data.encode()).hexdigest()
        response_to_check=ai_cache_data.get(response_key,"") if ai_cache_data else ""
        if response_to_check != "":
            alert_ai_cache={response_key:ai_cache_data.get(response_key,"")}
            if alert_ai_cache[response_key]['AI_Response']['classification']!=alert_ai_cache[response_key]['Humanoverride'] and ai_cache_data.get(response_key,0).get('Humanoverride',0) =="" :
                start_time=time.time()
                alert['human_override']=alert_ai_cache[response_key]['Humanoverride']
                ai_response,token_data=  update_ai_cache(alert,abuse_response,vt_response,max_retries,timing,response_key,alert_ai_cache)
                end_time=time.time()-start_time
                timing.update({"AI_FromCache":end_time})
            else:
                logger.debug("Loading AI Response from cache started")
                start_time=time.time()
                alert_ai_cache={response_key:ai_cache_data.get(response_key,"")}
                ai_response=alert_ai_cache[response_key]['AI_Response']
                human_override=alert_ai_cache[response_key]['Humanoverride']
                alert_ai_cache[response_key]['AI_CacheHit']+=1
                end_time=time.time()-start_time
                timing.update({"AI_FromCache":end_time})
                token_data={
                        "PromptToken":0,
                        "TotalToken":0,
                        "CandidateToken":0,
                        "ToolUsePromptToken":0,
                        "CacheToken":0,
                        "ThoughtsToken":0
                    }
                
                logger.debug("Loading AI Response from cache ended")
        else:
            alert['human_override']=""
            ai_response,token_data=  update_ai_cache(alert,abuse_response,vt_response,max_retries,timing,response_key,alert_ai_cache)
            timing.update({"AI_FromCache":0})   
        return ai_response,token_data,alert_ti_cache,alert_ai_cache,response_key
    except Exception as e:
        logger.error(e)


def ai_content_generate(ai_prompt,max_retries=3):
    gemini_rate_limiter=GeminiRateLimiter()
    logger.debug("AI Content Generated Started")
    for retries in range(max_retries):
        try:
            gemini_rate_limiter.wait_if_needed()
            gemini_key=os.getenv('GEMINIKEY')
            client=genai.Client(api_key=gemini_key)
            response=client.models.generate_content(
                model='gemini-2.5-flash-lite',contents=ai_prompt
            )
            token_data={
                "PromptToken":getattr(response.usage_metadata,"prompt_token_count",0),
                "TotalToken":getattr(response.usage_metadata,"total_token_count",0),
                "CandidateToken":getattr(response.usage_metadata,"candidates_token_count",0),
                "ToolUsePromptToken":getattr(response.usage_metadata,"tool_use_prompt_token_count",0),
                "CacheToken":getattr(response.usage_metadata,"cache_token_count",0),
                "ThoughtsToken":getattr(response.usage_metadata,"thoughts_token_count",0)
            }
            logger.debug("AI Content Generated ended")
            return response.text,token_data
        except Exception as e:
            logger.error(e)
            if e.code==429 or e.code == 503:
                time.sleep(2**retries)
                continue
            return None


def parse_alert_json(ai_output):
    logger.debug("AI output parsing started")
    """
    Parse the results of AI output to format a clean Output
    """
    try:
        json_output=re.search(r"\{.*?\}",ai_output,re.DOTALL)
        if json_output:
            result=json_output.group()
            result_json=json.loads(result)
            logger.debug("AI output parsing ended")
            return result_json
        else:
            logger.error("No Json to parse")
            return None   
    except Exception as e:
        logger.error(e)
        return None

def calculate_cost(token):
    logger.debug("Calculating Cost started")
    try:
        prompt_token_cost=1 #$ per 1M tokens
        output_token_cost=10 #$ per 1M tokens
        total_cost=prompt_token_cost*token["PromptToken"]/1_000_000 + output_token_cost*token["CandidateToken"]/1_000_000
        logger.debug("Calculating Cost ended")
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
    logger.debug("Cache loading started")
    try:
        with open(file_path,"r") as f:
           data= json.load(f)
           logger.debug("Cache loading ended")
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
        logger.debug("Pruning of cache ended")
        return cache_dump
    except Exception as e:
        logger.error(e)
        return None
    
def update_ti_cache(ti_cache_data,timing,ip_to_check):
    start_time=time.time()
    abuse_response,vt_response=day2_threatintel.ip_lookup(ip_to_check)
    end_time=time.time()-start_time
    timing.update({"TILookup":end_time})
    data_to_cache={
        "IP":ip_to_check,
        "AbuseIntel":abuse_response,
        "VTIntel":vt_response,
        "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "CacheHit":0
        }
    ti_cache_data.update({ip_to_check:data_to_cache})
    return abuse_response,vt_response

def update_ai_cache(alert,abuse_response,vt_response,max_retries,timing,response_key,ai_cache_data):
    for attempts in range(max_retries):
        try:
            logger.debug("Building Prompt for the alert")
            start_time=time.time()
            ai_prompt=build_prompt(alert,abuse_response,vt_response)
            logger.debug("Generating AI response")                
            ai_response,token_data=    ai_content_generate(ai_prompt)
            end_time=time.time()-start_time
            timing.update({"AI_ContentGenerate":end_time})
            logger.debug("Parsing AI output")
            start_time=time.time()                
            if ai_response:
                ai_output=parse_alert_json(ai_response)
            else:
                ai_output="No AI Response"
            end_time=time.time()-start_time
            timing.update({"ParseAlert":end_time})
            ai_data_to_cache={
                "Alert":alert,
                "AI_Response":ai_output,
                "TokenData":token_data,
                "AI_CacheHit":0,
                "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Humanoverride":alert['human_override'] if alert['human_override']!="" else ""
            }
            ai_cache_data.update({response_key:ai_data_to_cache})
            return ai_output,token_data
        except Exception as e:
            if attempts < max_retries - 1:
                print(f"Attempt {attempts + 1} failed: {e}. Retrying...")
                time.sleep(2**attempts)
                continue
            logger.error(e)
            return None
    
