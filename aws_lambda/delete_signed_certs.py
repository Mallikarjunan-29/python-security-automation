import time
import json
import boto3
def lambda_handler(event, context):
    signed_certs=event.get("SignedCerts")
    
    messages=[]
    if  not signed_certs :
        messages.append("No signed certs  to remove")
        return{
            "status":"success",
            "message":messages
        }
    client=boto3.client("iam")
    
    for items in signed_certs:
        username=items.get("UserName")
        if not username:
            messages.append("Failed: No username present in the request")
            continue
        for retries in range(3):
            try:
                SignedCertId=items.get("CertificateId")
                client.delete_signing_certificate(
    UserName=username,
    CertificateId=SignedCertId
)
                messages.append(f"Success: Signing certificate  {SignedCertId} removed successfully")
                break
            except Exception as e:
                if retries==2:
                    messages.append(f"Failed: Signing certificate {SignedCertId} could not be removed. Error: {str(e)}")
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

