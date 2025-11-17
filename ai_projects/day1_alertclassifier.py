from google import genai
import os
from dotenv import load_dotenv
from threading import Lock
load_dotenv()
import re
from datetime import datetime,timedelta
import json
import time
import sys
import json
import time
from threading import Lock
sys.path.append(os.getcwd())
from ai_projects import day2_threatintel
from src.rate_limiter import GeminiRateLimiter
from src import logger_config
from src.logger_config import get_logger
logger=get_logger(__name__)
import hashlib
from src.ioc_extractor import extract_ioc,extract_behavior
from concurrent.futures import ThreadPoolExecutor,as_completed
import chromadb
from src import ai_response_handler
from src.ai_response_handler import AI_response_handler
cache_lock=Lock()

def build_prompt(alert,ip_response,url_response,domain_response,human_override,behaviour):
    logger.debug("Prompt Building Started")
    """
    Takes Alert dictionary and builds a prompt
    """
    prompt_human_override=f"- Analyst Override:{human_override}" if human_override!="" else ""
    if ip_response:
        ip_intel=f"Threat Intel responses for the ip: {ip_response}"
    else:
        ip_intel=""
    if url_response:
        url_intel=f"Threat Intel responses for the url: {url_response}"
    else:
        url_intel=""
    if domain_response:
        domain_intel=f"Threat Intel responses for the domain: {domain_response}"
    else:
        domain_intel=""
    prompt = f"""
You are a SOC analyst
Analyze this alert
- alert:{json.dumps(alert,indent=4)}
- signature:{behaviour if behaviour!='' else 'none'} 
{prompt_human_override}

This is what the threat intel feeds say about the IP
{ip_intel}
{url_intel}
{domain_intel}

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
- reasoning: array of exactly 4 strings. Each string max 50 words. No bullet characters, no newlines inside items.
- Do NOT output any extra text, commentary, or code fences. Output must be parseable by json.loads().
- Include Analyst override if available
- Include IPs or Urls or domains given when you reason as the data will be fed to chromadb for future searches for the same alert
- First Sentence must always state the alert behaviour.
  1. The alert indicates multiple RDP login attemps from <source ip> to <destination ip> which is a sign of lateral movement
- semantic: Generate a runbook search query combining:
  1. Attack type (e.g., "Brute Force", "Lateral Movement")
  2. Key indicators (e.g., "RDP", "PowerShell", "DNS tunneling")
  3. MITRE technique ID if identifiable (e.g., T1110, T1021)
  
  Format: "Attack_Type Key_Indicator MITRE_ID"
  Example: "Brute Force Authentication T1110"
  Example: "Lateral Movement RDP T1021"

OUTPUT_SCHEMA:
{{
  "classification": "TRUE_POSITIVE",
  "confidence": 95,
  "severity": "Critical",
  "reasoning": [
    "One-sentence reason 1 (<=50 words).",
    "One-sentence reason 2 (<=50 words).",
    "One-sentence reason 3 (<=50 words).",
    "One-sentence reason 4 (<=50 words).",
  ],
  "semantic": "search query for runbook matching"
}}
"""
    logger.debug("Prompt Building ended")
    return prompt

def classify_alert(alert,ti_cache_data,ai_cache_data,timing,max_retries=3):
    """
    Alert -> Threat Intel -> Cache -> AI -> classification
    """
    try:
        """Including a porttion to extract IOCs"""
        logger.debug("calling IOC extractor")
        if isinstance(alert, dict):
            alert_text=json.dumps(alert)
        else:
            alert_text=alert
            
        ioc=extract_ioc(str(alert_text))
        logger.debug("Extracting IOCs finished")
        
        ip_response={}
        url_response={}
        domain_response={}
        handlers={
            "ips":process_ip,
            "urls":process_url,
            "domains":process_domain
        }
        logger.debug("Calling thread pool")
        with ThreadPoolExecutor(max_workers=6) as exe:
            futures=[]
            for categories,values in ioc.items():
                func=handlers[categories]
                for value in values:
                   futures.append( exe.submit(func,value,ti_cache_data,timing))
            logger.debug("Calling completed futures")
            for future in as_completed(futures):
                out=future.result()
                if out['category']=='ips':
                    ip_response.update({out['value']:out['result']})
                elif  out['category']=='urls':
                    url_response.update({out['value']:out['result']})
                elif  out['category']=='domains':
                    domain_response.update({out['value']:out['result']})
            logger.debug("Completed futures processed")
        logger.debug("Thread pool ended")
                
                
        #Query Text and Caching logic
        
        """        # Implementing Vector DB for AI response
        ai_resp_handler=AI_response_handler("ai_response")
        ai_response,token_data=ai_resp_handler.search(ioc,ip_response,url_response,domain_response,alert)
        if not ai_response:
            ai_response,token_data=  update_ai_cache(alert,ip_response,url_response,domain_response,max_retries,timing)
            ai_resp_handler.store_cache(ioc,ip_response,url_response,domain_response,ai_response,token_data,alert)
        
        return ai_response,token_data
                


        """
        #Loading AI response checker - Needs change. It will be IOC instead of alert
        
        response_key=generate_cache_key(ip_response,url_response,domain_response,ioc,alert)
        response_to_check=ai_cache_data.get(response_key,"") if ai_cache_data else ""
        if response_to_check != "":
            ai_cache_data={response_key:ai_cache_data.get(response_key,"")}
            if ai_cache_data[response_key]['AI_Response']['classification']!=ai_cache_data[response_key]['Humanoverride']:
                start_time=time.time()
                human_override=ai_cache_data[response_key]['Humanoverride']
                ai_response,token_data=  update_ai_cache(alert,ip_response,url_response,domain_response,max_retries,timing,response_key,ai_cache_data,human_override)
                end_time=time.time()-start_time
                timing.update({"AI_FromCache":end_time})
            else:
                logger.debug("Loading AI Response from cache started")
                start_time=time.time()
                ai_cache_data={response_key:ai_cache_data.get(response_key,"")}
                ai_response=ai_cache_data[response_key]['AI_Response']
                human_override=ai_cache_data[response_key]['Humanoverride']
                with cache_lock:
                    ai_cache_data[response_key]['AI_CacheHit']+=1
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
            human_override=""
            ai_response,token_data=  update_ai_cache(alert,ip_response,url_response,domain_response,max_retries,timing,response_key,ai_cache_data,human_override)
            timing.update({"AI_FromCache":0})   
        return ai_response,token_data,response_key 
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
# Ip Caching
def update_ti_cache(ti_cache_data,timing,ip_to_check):
    start_time=time.time()
    abuse_response,vt_response=day2_threatintel.ip_lookup(ip_to_check)
    end_time=time.time()-start_time
    timing.update({"IPTILookup":end_time})
    data_to_cache={
        "IP":ip_to_check,
        "AbuseIntel":abuse_response,
        "VTIntel":vt_response,
        "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "IPCacheHit":0
        }
    ti_cache_data.update({ip_to_check:data_to_cache})
    return abuse_response,vt_response

#URL Caching
def update_url_cache(ti_cache_data,timing,url):
    logger.debug("Updating url cache")
    start_time=time.time()
    vt_response,url_haus_response=day2_threatintel.url_lookup(url)
    end_time=time.time()-start_time
    timing.update({"URLTILookup":end_time})
    data_to_cache={
        "url":url,
        "URLHauseIntel":url_haus_response,
        "VTURLIntel":vt_response,
        "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "URLCacheHit":0
        }
    ti_cache_data.update({url:data_to_cache})
    return url_haus_response,vt_response

#Domain Caching
def update_domain_cache(ti_cache_data,timing,domain):
    start_time=time.time()
    vt_response=day2_threatintel.vt_domain_response(domain)
    end_time=time.time()-start_time
    timing.update({"DomainTILookup":end_time})
    data_to_cache={
        "domain":domain,
        "VTDomainIntel":vt_response,
        "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "DomainCacheHit":0
        }
    ti_cache_data.update({domain:data_to_cache})
    return vt_response

def update_ai_cache(alert,ip_response,url_response,domain_response,max_retries,timing,response_key,ai_cache_data,human_override=""):
    for attempts in range(max_retries):
        try:
            logger.debug("Building Prompt for the alert")
            start_time=time.time()
            ai_prompt=build_prompt(alert,ip_response,url_response,domain_response,human_override,extract_behavior(alert))
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
                "Humanoverride":human_override if human_override !="" else ""
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


def process_ip(ip,ti_cache_data,timing):
    logger.debug("Calling Process IPs")
    ip_to_check=ip
    itemtocheck=ti_cache_data.get(ip_to_check,0)
    
    # Loading TI cache data based on conditions
    if not ti_cache_data:
        abuse_response,vt_response=update_ti_cache(ti_cache_data,timing,ip_to_check)
        timing.update({"TI_FromCache":0})
    elif itemtocheck==0:
        abuse_response,vt_response=update_ti_cache(ti_cache_data,timing,ip_to_check)
        timing.update({"TI_FromCache":0})
    else:
        logger.debug("Loading TI Response from cache started")
        start_time=time.time()
        abuse_response=ti_cache_data[ip_to_check]['AbuseIntel']
        vt_response=ti_cache_data[ip_to_check]['VTIntel'] 
        end_time=time.time()-start_time
        timing.update({"TI_FromCache":end_time})
        with cache_lock:
            ti_cache_data[ip_to_check]['IPCacheHit']+=1        
        logger.debug("Loading TI Response from cache ended")
    process_ip_response={
        "category":"ips",
        "value":ip,
        "result":{
                "IP_Abuse_intel":abuse_response,
                "IP_VT_Intel":vt_response
        }
    }
    logger.debug("returning Process IPs")
    return process_ip_response





# Process URLs from/to cache
def process_url(url,ti_cache_data,timing):
    logger.debug("Calling Process urls")
    url_to_check=url
    itemtocheck=ti_cache_data.get(url_to_check,0)
    # Loading TI cache data based on conditions
    if not ti_cache_data:
        url_hause_response,vt_url_response=update_url_cache(ti_cache_data,timing,url_to_check)
        timing.update({"TI_FromCache":0})
    elif itemtocheck==0:
        url_hause_response,vt_url_response=update_url_cache(ti_cache_data,timing,url_to_check)
        timing.update({"TI_FromCache":0})
    else:
        logger.debug("Loading TI Response from cache started")
        start_time=time.time()
        url_hause_response=ti_cache_data[url_to_check]['URLHauseIntel']
        vt_url_response=ti_cache_data[url_to_check]['VTURLIntel'] 
        end_time=time.time()-start_time
        timing.update({"TI_FromCache":end_time})
        with cache_lock:
            ti_cache_data[url_to_check]['URLCacheHit']+=1        
        logger.debug("Loading TI Response from cache ended")  
    process_url_response={
        "category":"urls",
        "value":url,
        "result":{
                "URL_haus_response":url_hause_response,
                "vt_URL_response":vt_url_response
        }
    }
    logger.debug("returning Process urls")
    return process_url_response
    

# Process domains from/to cache
def process_domain(domain,ti_cache_data,timing):
    logger.debug("Calling Process domains")
    url_to_check=domain
    itemtocheck=ti_cache_data.get(url_to_check,0)   

    # Loading TI cache data based on conditions
    if not ti_cache_data:
        vt_domain_response=update_domain_cache(ti_cache_data,timing,url_to_check)
        timing.update({"TI_FromCache":0})
    elif itemtocheck==0:
        vt_domain_response=update_domain_cache(ti_cache_data,timing,url_to_check)
        timing.update({"TI_FromCache":0})
    else:
        logger.debug("Loading TI Response from cache started")
        start_time=time.time()
        vt_domain_response=ti_cache_data[url_to_check]['VTDomainIntel'] 
        end_time=time.time()-start_time
        timing.update({"TI_FromCache":end_time})
        with cache_lock:
            ti_cache_data[url_to_check]['DomainCacheHit']+=1        
        logger.debug("Loading TI Response from cache ended")
    process_domain_response={
        "category":"domains",
        "value":domain,
        "result":{
            "VT_domain_response":vt_domain_response
        }
    }   
    logger.debug("returning Process domains")
    return process_domain_response


def generate_cache_key(ip_response,url_response,domain_response,ioc,alert):
    try:
        logger.debug("Cache Key generated started")
        malicious_ip=[
                        data.get('IP_Abuse_intel',0).get('IP',0) for data in ip_response.values()
                        if data.get('IP_Abuse_intel') and data.get('IP_Abuse_intel',0).get('AbuseConfidenceScore',0) > 50
            ]
        
        malicious_url=[
                    data.get('vt_URL_response',0).get('url',0) for data in url_response.values()
                    if data.get('vt_URL_response') and data.get('vt_URL_response',0).get('stats',0).get('malicious',0)>0
        ]
        malicious_domain=[
                    data.get('VT_domain_response',0).get('Domain',0) for data in domain_response.values()
                    if data.get('VT_domain_response') and data.get('VT_domain_response',0).get('Stats',0).get('malicious',0)>0
        ]
        
        malicious_ioc={
        "ips":malicious_ip,
        "urls":malicious_url,
        "domain":malicious_domain
        }
        if len(malicious_ip)==0 and len(malicious_url)==0 and len(malicious_domain)==0:
            all_iocs=ioc.get("ips",[])+ioc.get('urls',[])+ioc.get('domains',[])
            all_iocs=sorted(set(all_iocs))
            ioc_fp=hashlib.sha256(",".join(all_iocs).encode()).hexdigest()[:12]
            normalized_alert={
                "ioc":ioc_fp,
                "behaviour":extract_behavior(alert)
            }
        else:
            normalized_alert={
                "ioc":malicious_ioc,
                "behaviour":extract_behavior(alert)
            }
        cache_key=hashlib.md5(json.dumps(normalized_alert,sort_keys=True).encode()).hexdigest()
        logger.debug("Cache Key generated ended")
        return cache_key
    except Exception as e:
        logger.error(str(e))
        logger.debug("Error in cache key generation")
        return None

if __name__=="__main__":
    alert="HIGH: Possible C2 traffic — src=192.168.50.13 dst=80.94.93.119:5000; suspicious-uri=/api/collect; method=POST; transfer=1.2MB; user-agent=Mozilla/5.0(Windows)"
    classify_alert(alert,{},{},{})
    

    
    