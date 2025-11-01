from google import genai
import os
from dotenv import load_dotenv
load_dotenv()
import re
import json
import time

def build_prompt(alert):
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

Is this suspicious?
Classify as :
 - TRUE_POSITIVE (real attack)
 - FALSE_POSITIVE (legitimate behaviour)
 - NEEDS_REVIEW (uncler)

 Think step by step and then provide:
 1. Classification
 2. Confidence Score (0-100%)
 3. Reasoning
 
 Format as Json:
 {{
    "classification":"TRUE_POSITIVE",
    "confidence":95,
    "reasoning": "8 failures at 2:00 AM indicate brute force"
 }}
"""
    return prompt

def classify_alert(alert,max_retries=3):
    """
    Alert -> AI -> classification
    """
    for attempts in range(max_retries):
        try:
            gemini_key=os.getenv('GEMINIKEY')
            client=genai.Client(api_key=gemini_key)
            response=client.models.generate_content(
                model='gemini-2.0-flash',contents=build_prompt(alert)
            )
            token_data={
                "PromptToken":getattr(response.usage_metadata,"prompt_token_count",0),
                "TotalToken":getattr(response.usage_metadata,"total_token_count",0),
                "CandidateToken":getattr(response.usage_metadata,"candidates_token_count",0),
                "ToolUsePromptToken":getattr(response.usage_metadata,"tool_use_prompt_token_count",0),
                "CacheToken":getattr(response.usage_metadata,"cache_token_count",0)
            }
            return response.text,token_data
        except Exception as e:
            if attempts < max_retries - 1:
                print(f"Attempt {attempts + 1} failed: {e}. Retrying...")
                time.sleep(2**attempts)
                continue
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
        print(e)
        return None

def calculate_cost(token):
    try:
        prompt_token_cost=0.03 #$ per 1000 tokens
        output_token_cost=0.06 #$ per 1000 tokens
        total_cost=prompt_token_cost*token["PromptToken"]/1000 + output_token_cost*token["CandidateToken"]/1000
        return total_cost
    except Exception as e:
        print(e)
        return None