import json
import boto3
import time
def lambda_handler(event, context):
    messages=[]
    try:
        attached_policies=event.get("attached_policies")
        user_name=event.get("UserName")
        if attached_policies is None:
            messages.append(f"attached policy is empty")
            return{
                "status":"failed",
                "message":messages
            }                
        client=boto3.client("iam")
        for items in attached_policies:
            if items.get("PolicyArn") is None or items.get("UserName") is None:
                messages.append("failed since username or policy arn is missing")
                continue
            policy_arn=items.get("PolicyArn")
            for retries in range(3):
                try:
                    response=client.detach_user_policy(
                        UserName=user_name,
                        PolicyArn=policy_arn
                        )
                    messages.append(f"detached arn {policy_arn} successfully")
                    break
                except Exception as e:
                    if retries==2:
                        messages.append(f"failed to detach policy {policy_arn} with error: {str(e)}")
                    else:
                        time.sleep(2**retries)  
        if not messages:
            status="failed"
        elif all("failed" in m.lower() for m in messages):
            status="failed"
        elif all("detached" in m.lower() for m in messages):
            status="success"
        else:
            status="partial_failure"
        return {
        'status': status,
        'message': messages
    }
    except Exception as e:
        messages.append(f"Failed to detach policies{str(e)}")
        return{
            "status":"failed",
            "message":messages
        }
    
    
