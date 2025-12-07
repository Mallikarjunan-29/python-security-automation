import time
import json
import boto3
def lambda_handler(event, context):
    groups=event.get("Groups")
    username=event.get("UserName")
    messages=[]
    if groups is None or username is None:
        messages.append("No Groups to remove")
        return{
            "status":"failed",
            "message":messages
        }
    client=boto3.client("iam")
    try:
        for items in groups:
            if items.get("GroupName") is None:
                messages.append("failed due to empty group name")
                continue
            group_name=items.get("GroupName")
            
            for retries in range(3):
                try:
                    response=client.remove_user_from_group(
                    GroupName=group_name,
                    UserName=username
                    )
                    messages.append(f"Group {group_name} removed successfully")
                    break
                except Exception as e:
                    if retries==2:
                        messages.append(f"failed to remove group with error {str(e)}")
                    else:
                        time.sleep(2**retries)
        
        if not messages:
            status="failed"
        elif all("failed" in m for m in messages):
            status="failed"
        elif all("removed" in m for m in messages):
            status="success"
        else:
            status="partial_failure"
        return {
        'status': status,
        'message': messages
    }
    except Exception as e:
        messages.append(f"failed to remove group with error: {str(e)}")
        return{
            "status":"failed",
            "message":messages
        }
