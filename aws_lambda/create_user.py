import json
import boto3
def lambda_handler(event, context):
    
    try:
        username=event.get("UserName")
        password=event.get("Password")
        email=event.get("email")
        iam_client=boto3.client("iam")
        response=iam_client.create_login_profile(UserName=username,Password=password,PasswordResetRequired=True)
        return {
            'username': username,
            'password': password,
            'email': email,
            'status': "Success",
            'statusCode': 200
        }
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        return {
            'statusCode': 200,
            'body': json.dumps(str(e))
        }
        return {
            'statusCode': 400,
            'body': json.dumps(str(e))
        }
    except Exception as e:
        return {
            'statusCode': 400,
            'body': json.dumps(str(e))
        }
