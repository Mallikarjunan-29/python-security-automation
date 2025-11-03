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

def classify_alert(alert,cache_hits,max_retries=3,):
    """
    Alert -> Threat Intel -> Cache -> AI -> classification
    """
    #Cache logic
    base_path=os.getcwd()
    cache_path=os.path.join(base_path,"cache")
    os.makedirs(cache_path,exist_ok=True)
    file_name=f"{str(alert['source_ip']).replace(".","_")}.json"
    file_path=os.path.join(cache_path,file_name)
    write_indicator=1
    if os.path.exists(file_path):
        cached_data=load_cache(file_path) #reading data from cache
        time_difference= datetime.now()-datetime.strptime((cached_data['Timestamp']),"%Y-%m-%d %H:%M:%S")
        if time_difference< timedelta(seconds=3600):
            logger.debug(f"Loading cache for the IP {alert['source_ip']}")
            write_indicator=0    
            abuse_response=cached_data['AbuseIntel']
            vt_response=cached_data['VTIntel'] 
            cache_hits+=1   
    if write_indicator==1:
        logger.debug(f"Loading TI data for the IP {alert['source_ip']}")
        abuse_response,vt_response=day2_threatintel.ip_lookup(alert['source_ip'])
        cache_data={
            "IP":alert['source_ip'],
            "AbuseIntel":abuse_response,
            "VTIntel":vt_response,
            "Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        cache_ip(file_path,cache_data) # Writing data to cache
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
                "CacheToken":getattr(response.usage_metadata,"cache_token_count",0)
            }
            return response.text,token_data,cache_hits
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
        prompt_token_cost=0.03 #$ per 1000 tokens
        output_token_cost=0.06 #$ per 1000 tokens
        total_cost=prompt_token_cost*token["PromptToken"]/1000 + output_token_cost*token["CandidateToken"]/1000
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