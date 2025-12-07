import time
import json
import boto3
def lambda_handler(event, context):
    user_policies=event.get("UserPolicies")
    username=event.get("UserName")
    messages=[]
    if  not user_policies or not username :
        messages.append("No policies to remove")
        return{
            "status":"failed",
            "message":messages
        }
    client=boto3.client("iam")
    
    for items in user_policies:
        for retries in range(3):
            try:
                response = client.delete_user_policy(
UserName=username,
PolicyName=items
)
                messages.append(f"Success: Inline policy {items} removed successfully")
                break
            except Exception as e:
                if retries==2:
                    messages.append(f"Failed: Inline policy {items} could not be removed. Error: {str(e)}")
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
    return {
    'status': status,
    'message': messages
}

