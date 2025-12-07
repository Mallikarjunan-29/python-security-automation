import json
import boto3
import time
def lambda_handler(event, context):
    messages=[]
    try:
        username=event.get("UserName")
        if username is None:
            messages.append("Failed: User name not provided")
            return {
                "status":"failed",
                "message": messages
            }
        client=boto3.client("iam")
        for retries in range(3):
            try:
                client.delete_user(
                UserName=username
            )
                messages.append(f"Success: User {username} successfully deleted")
                break
            except Exception as e:
                if retries==2:
                    messages.append(f"Failed: Deletion of user '{username}' failed with error: {str(e)}")
                    
                else:
                    time.sleep(2**retries)
                        
        if all("failed" in m.lower() for m in messages):
            status="failed"
        elif all("success" in m.lower() for m in messages):
            status="success"
        else:
            status="partial_failure"    
        return{
            "status":status,
            "message":messages
        }
    except Exception as e:
        messages.append(f"Failed: Deletion of user '{username}' failed with error: {str(e)}") 
        return{
            "status":"failed",
            "message":messages
        }
       
        
            
            