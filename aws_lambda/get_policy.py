import json
import boto3
import time
def lambda_handler(event, context):
    policyarn=event.get("PolicyArn")
    if policyarn is None:
        return {
            "status":"failed",
            "data": "Failed:  No Policy Arn provided"
        }
    client=boto3.client("iam")
    try:
        response = client.get_policy(
        PolicyArn=policyarn
        )
        if response and response.get("Policy").get("Arn"):
            return {"status":"success","data":response.get("Policy").get("Arn")}
        
    except Exception as e:
        return {
                "status":"failed",
                "data":"Policy Fetch Failed"}
                    
    
    
            
            