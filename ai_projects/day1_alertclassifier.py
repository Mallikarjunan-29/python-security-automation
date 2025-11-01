from google import genai
import os
from dotenv import load_dotenv
load_dotenv()
import re
import json

#Result Dictionary
result ={}
#Sample alert
alert = {
    "user": "alice@company.com",
    "source_ip": "209.94.90.1",
    "failed_logins": 8,
    "success": True,
    "time": "02:00",
    "location": "San Francisco, CA"
    }
    

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

def classify_alert(alert):
    """
    Alert -> AI -> classification
    """
    gemini_key=os.getenv('GEMINIKEY')
    client=genai.Client(api_key=gemini_key)
    response=client.models.generate_content(
        model='gemini-2.5-flash',contents=build_prompt(alert)
    )
    return response.text

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

