import sys
import os
import dotenv
dotenv.load_dotenv()
import requests
from src.logger_config import get_logger
logger=get_logger(__name__)
sys.path.append(os.getcwd())
def create_case(ai_response:dict):
    try:
        api_key=os.getenv("HIVE_KEY")
        url="http://localhost:9000/api/v1/case"
        header={
            "Content-Type":"application/json",
            "Authorization":f"Bearer {api_key}"
        }
        description=f"""
    Classification:{ai_response['classification']}
    Severity:{ai_response['severity']}
    Reasoning:{"\n".join(ai_response['reasoning'])}
    """
        payload={
            "title":ai_response["title"],
            "description":description,
            "severity":ai_response["priority"]
        }

        response=requests.post(url,headers=header,json=payload)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"{str(e)}")
        return None



