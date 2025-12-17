import time
import json
import boto3
def lambda_handler(event, context):
    serv_spec_creds=event.get("ServerSpecificCreds")
    
    messages=[]
    if  not serv_spec_creds :
        messages.append("No server specific credentials to remove")
        return{
            "status":"success",
            "message":messages
        }
    client=boto3.client("iam")
    
    for items in serv_spec_creds:
        username=items.get("UserName")
        if not username:
            messages.append("Failed: No username present in the request")
            continue
        for retries in range(3):
            try:
                ServiceSpecificCredentialId=items.get("ServiceSpecificCredentialId")
                response = client.delete_service_specific_credential(
    UserName=username,
    ServiceSpecificCredentialId=ServiceSpecificCredentialId
)
                messages.append(f"Success: Service Specific Credential  {ServiceSpecificCredentialId} removed successfully")
                break
            except Exception as e:
                if retries==2:
                    messages.append(f"Failed: Service Specific Credential {ServiceSpecificCredentialId} could not be removed. Error: {str(e)}")
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

