import json
import boto3
import time
def lambda_handler(event, context):
    messages=[]
    try:
        mfa_details=event.get("mfa_devices")
        if mfa_details is None:
            messages.append("failed since MFA is not enabled for this user")
            return {
                "status":"failed",
                "message": messages
            }
        client=boto3.client("iam")
        for items in mfa_details:
            
            for retries in range(3):
                try:
                    if not items.get("SerialNumber") or not items.get("UserName"):
                        messages.append("failed to deactivate MFA: missing SerialNumber or UserName")
                        break            
                    response = client.deactivate_mfa_device(
                        UserName=items.get("UserName"),
                        SerialNumber=items.get("SerialNumber")
                    )
                    if response.get("ResponseMetadata").get("HTTPStatusCode") == 200:
                        messages.append(f"mfa {items.get('SerialNumber')} is deactivated for {items.get('UserName')}")
                        break
                    else:
                        messages.append(f"failed to deactivate mfa for {items.get('SerialNumber')}")
                        continue
                except Exception as e:
                    if retries==2:
                        messages.append(f"failed to deactivate mfa for {items.get('SerialNumber')} with error: {str(e)}")
                    else:
                        time.sleep(2**retries)
                        
        if not messages:
            status="failed"
        elif all("failed" in m.lower() for m in messages):
            status="failed"
        elif all("deactivated" in m.lower() for m in messages):
            status="success"
        else:
            status="partial_failure"    
        return{
            "status":status,
            "message":messages
        }
    except Exception as e:
        messages.append(f"failed to deactivate MFA. error {str(e)}") 
        return{
            "status":"failed",
            "message":messages
        }
       
        
            
            