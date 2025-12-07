import json
import boto3
def lambda_handler(event, context):
    
    try:
        username=event.get("UserName")
        password=event.get("Password")
        iam_client=boto3.client("iam")
        iam_client.update_login_profile(UserName=username,Password=password,PasswordResetRequired=True)
        return {
            'username': username,
            'password': password,
            'status': "Success",
            'statusCode': 200
        }
    
    except Exception as e:
        return {
            'statusCode': 400,
            'status':"failure",
            'error': json.dumps(str(e))
        }
