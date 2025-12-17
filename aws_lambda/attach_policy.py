import json
import boto3
import time
def lambda_handler(event, context):
    messages=[]
    policyarn=event.get("PolicyArn")
    username=event.get("UserName")
    if policyarn is None:
        messages.append("Failed:  No Policy Arn provided")
        return {
            "status":"failed",
            "message": messages
        }
    if username is None:
        messages.append("Failed:  No UserName provided")
        return {
            "status":"failed",
            "message": messages
        }
    client=boto3.client("iam")
    for retries in range(3):
        try:
                    
            client.attach_user_policy(
    UserName=username,
    PolicyArn=policyarn
)
            messages.append(f"Success: Policy {policyarn} attached to the user {username} successfully")
            break
        except Exception as e:
            if retries==2:
                messages.append(f"Failed: Attaching policy {policyarn} failed with error: {str(e)}")
            else:
                time.sleep(2**retries)
                    
    if not messages:
        status="failed"
    elif all("failed" in m.lower() for m in messages):
        status="failed"
    elif all("success" in m.lower() for m in messages):
        status="success"
    else:
        status="partial_failure"    
    return{
        "status":status,
        "message":messages
    }
    
    
            
            