import json
import boto3
from datetime import datetime
import time
def lambda_handler(event, context):
    accesskeyid=event.get("AccessKeyId")
    
    stale=False
    try:
        client=boto3.client("iam")
        response = client.get_access_key_last_used(
    AccessKeyId=accesskeyid
)
        stale=True
        if response:
            if response.get("UserName"):
                username=response.get("UserName")
            if response.get("AccessKeyLastUsed") and response.get("AccessKeyLastUsed").get("LastUsedDate") :
                days_diff=(datetime.now()-response.get("AccessKeyLastUsed").get("LastUsedDate")).days
                if days_diff and days_diff<90:
                    stale=False
        return{
            "stale":stale,
            "UserName":username
        }
        
    except Exception as e:
        return{
            "stale":stale,
            "message":f"Error while determining stale account : {str(e)}"
        }

        

        