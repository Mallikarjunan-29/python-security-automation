import json
import boto3

def lambda_handler(event, context):
    try:
        username=event.get("UserName")
        if not username:
            return{
                "status":"failed",
                "message":"username is required"
            }
        iam=boto3.client("iam")
        response=iam.delete_login_profile(UserName=username)
        return {
            "status":"success",
            "message":"login profile deleted successfully"
        }
    except Exception as e:
        return{
            "status":"failed",
            "message":str(e)
        }
