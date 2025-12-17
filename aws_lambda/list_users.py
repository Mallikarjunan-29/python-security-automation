import json
import boto3
def lambda_handler(event, context):
    
    try:
        iam_client=boto3.client("iam")
        response= iam_client.list_users()
        usernames=[]
        if response and  response.get("Users"):
            users=response.get("Users")
            for user in users:
                if user.get("UserName"):
                    usernames.append(user.get("UserName"))
        return{
            "status":"Success",
            "UserNames":usernames
        }
    except Exception as e:
        return{
            "status":"Failure",
            "message":"Error fetching users"
        }

        