import os
import sys
import time
sys.path.append(os.getcwd())
import re
import json
from json import JSONDecodeError
from google import genai
from src.rate_limiter import GeminiRateLimiter
from src.detection_patters import ATTACK_PATTERS,ATTACK_TO_SOURCE,DEFAULT_THRESHOLDS,MITRE_MAPPING,SOURCES
from src.logger_config import get_logger
logger=get_logger(__name__)
ai_rate_limiter=GeminiRateLimiter()


def build_planner_prompt(description):
    logger.debug(f"Building prompt for requirement: {description}")
    """Build a prompt for getting a structured output from gemini"""
    prompt = f"""
You are a Security Planner Agent.  
Your task: Convert a natural language description of an attack into the following structured dictionary.  

Rules:  
1. Do NOT provide any explanations or commentary. 
2. Convert the description directly into the structured dictionary. 
3. Fill semantic fields (source_type, destination_type, ports, log_sources, frequency, thresholds) wherever possible. 
4. If the attack_type can be inferred from behavior, fill it; otherwise, leave it null. Do not hedge or output text like "could be reconnaissance or C2"..  
2. If a field in missing_fields cannot be determined, mark requires_clarification = true and list the missing_fields.  
3. Provide reasoning for each filled value in the "reason" key.  
4. Use the "examples" fields to guide your classification but do NOT treat them as exhaustive.  
    4.a. "examples for attack type": ["brute_force", "password_spray", "lateral_movement", "data_exfiltration", "c2_connection", "privilege_escalation", "phishing"]  
    4.b. "examples for MITRE": ["T1110", "T1021", "T1041", "T1566"]  
    4.c. "examples for log sources": ["windows", "firewall"]  
    4.d. OS names may be used only under "log_sources".  
5. Do NOT invent attack types. If the type is unclear, mark as null and flag clarification.  
6. Always prefer semantic/generalized fields instead of raw IPs, hostnames, or domain names.  

Input: {description}  

Output JSON format:

{{
  "attack_type": {{
    "value": "",
    "reason": ""
  }},

  "entities": {{
    "source_type": "",
    "destination_type": "",
    "ports": [],
    "log_sources": [],
    "additional_context": {{}}
  }},

  "thresholds": {{
    "count": "",
    "frequency_window": {{
      "count": "",
      "minutes": ""
    }}
  }},

  "mitre": {{
    "value": "",
    "reason": ""
  }},

  "exclusions": [],
  "requires_clarification": true,
  "missing_fields": [
    "source_type",
    "destination_type",
    "ports",
    "log_sources"
  ]
}}
"""

    logger.debug(f"Prompt building completed")
    return prompt
    

def build_planner(description:str):
    logger.debug("Planner building started")
    for retries in range(3):
        try:
            ai_rate_limiter.wait_if_needed()
            gemini_key=os.getenv("GEMINIKEY")
            if not gemini_key:
                raise ValueError("No Gemini Key")
            client=genai.Client(api_key= gemini_key)
            response=client.models.generate_content(
                model="gemini-2.5-flash-lite",contents=build_planner_prompt(description))
            logger.debug("Planner generation complete")
            json_output=parse_json(response.text)
            if json_output:
                if json_output.get("requires_clarification"):
                    print(f"requires clarification {json_output.get("requires_clarification")}")
                    print(*json_output.get("missing_fields"),sep="\n")
                    return None
                else:
                    print("="*60)
                    print(f"AI output")
                    print("="*60)
                    print(json_output)
                    return json_output
            else:
                print("Json Decoder returned None")
                return None

        except ValueError as e:
            logger.error(str(e))
        except Exception as e:
            if e.code and e.code==429:
                print(f"Retrying time: {retries+1}")
                time.sleep(2**retries)
                continue
            logger.error(f"Error during AI content generation: {str(e)}")

def parse_json(input):
    logger.debug("Parsing AI output started")
    try:
        pattern=r"\{(.+)\}"
        output=re.search(pattern,input,re.DOTALL)
        json_output=output.group()
        json_output=json.loads(json_output)
        logger.debug("Parsing AI output ended")
        return json_output
    except JSONDecodeError as e:
        logger.error(f"Error decoding json {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error parsing input {str(e)}")
        return None

def extract_attack_type(description:str)->str:
    logger.debug(f"Extracting attack type from {description} ")
    try:
        for k, v in ATTACK_PATTERS.items():
            if re.search(v,description.lower()):
                logger.debug(f"return attack type {k}")
                return k
        logger.debug("No attack type in description")
        return None
    except Exception as e:
        logger.error(f"Error extracting attack type: {str(e)}")
        return None

def extract_data_source(description:str):
    logger.debug(f"Extracting data source from {description} ")
    try:
        for k,v in SOURCES.items():
            if any(kw in description.lower() for kw in v):
                logger.debug(f"Returning data source {k}")
                return k
            else:
                logger.debug("No data source to return")
                return None
    except Exception as e:
         logger.error(f"Exception during data source extraction {str(e)}")
         return None


def extract_thresholds(description:str):
        try:
            pass
        except Exception as e:
            logger.error(f"Exception during threshold extraction {str(e)}")
            return None
        
if __name__=="__main__":
    build_planner("Internal host communicating with unknown external domain once every 5 minutes over port 53. Use firewall logs for communication data")
