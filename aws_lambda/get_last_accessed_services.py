import json
import boto3
from datetime import datetime
import time
def lambda_handler(event, context):
    arn=event.get("Arn")
    username=event.get("UserName")
    stale=False
    try:
        client=boto3.client("iam")
        response = client.generate_service_last_accessed_details(
        Arn=arn
        )
        while True:
            service_response=client.get_service_last_accessed_details(
        JobId=response["JobId"])
            if service_response.get('JobStatus',"").lower()=="completed":
                break
        
        if service_response.get("ServicesLastAccessed"):
            for items in service_response.get("ServicesLastAccessed"):
                if items.get("LastAuthenticated"):
                    days=(datetime.now()-items.get("LastAuthenticated")).days
                    if days>90:
                        stale=True
                        break
                else:
                    stale=True
        else:   
            stale=True
        return{
            "stale":stale,
            "arn":arn,
            "username":username
        }
    except Exception as e:
        return{
            "stale":stale,
            "message":f"Error while determining stale account : {str(e)}"
        }

        

        