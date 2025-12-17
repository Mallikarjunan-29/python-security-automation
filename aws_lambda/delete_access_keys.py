import json
import boto3
import time
def lambda_handler(event, context):
    try:
        message=[]
        accesskeys=event.get('accesskeys')
        if accesskeys is None:
            return{
                "status":"failed",
                "message":"No access keys found"
            }
        iam_client=boto3.client('iam')

        for items in accesskeys:
            if items.get('AccessKeyId') is None or items.get('UserName') is None:
                    message.append(f"Failed to Delete since Access key id or UserName is missing")
                    continue
            for retries in range(3):
                try:
                    iam_client.delete_access_key(
                    AccessKeyId=items['AccessKeyId'],
                    UserName=items['UserName']
                    )
                    message.append(f"Access key {items['AccessKeyId']} for user {items['UserName']} deleted successfully")
                    break
                except Exception as e:
                    if retries==2:
                        message.append(f"Failed to delete access key {items['AccessKeyId']} for user {items['UserName']}: {str(e)}")
                    else:
                        time.sleep(2**retries)
                        
                    
        return {
            'status': "success" if all("Failed" not in m for m in message) else "Partial failure",
            'message': message
            
        }
    except Exception as e:
        return {
            'status': 'failed',
            'message': str(e)
        }
