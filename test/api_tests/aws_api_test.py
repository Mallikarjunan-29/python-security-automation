import secrets
import string
import boto3
import requests
import time
from datetime import datetime
def iam_create():
    client=boto3.client("iam")
    response=client.create_user(
        UserName="test-user"
    )
    print(response)

def aws_create(username,email,path="",permission_boundary="",tags=""):
    url="http://localhost:5678/webhook/aws-create-user"
    data={
        "username":username,
        "email":email,
        "path":path,
        "permission_boundary":permission_boundary,
        "tags":tags
    }
    response=requests.post(url,json=data)
    response.raise_for_status()
def generate_password(length=12):
    char=string.ascii_letters+string.digits+"!@#$%^&*()-_+="
    password="".join((secrets.choice(char)) for _ in range(length))
    return password

def add_user_to_group(username,group_name):
    url="http://localhost:5678/webhook/addusergroup"
    data={
        "username":username,
        "groupname":group_name
    }
    response= requests.post(url,json=data)
    response.raise_for_status()


def aws_delete(username,email="",path="",permission_boundary="",tags=""):
    url="http://localhost:5678/webhook/aws_delete_user"
    data={
        "username":username
    }
    response=requests.post(url,json=data)
    response.raise_for_status()

def aws_attach_policy(username,policyarn):
    url="http://localhost:5678/webhook-test/attachpolicy"
    data={
        "username":username,
        "policyarn":policyarn
    }
    response=requests.post(url,json=data)
    response.raise_for_status()



def aws_get_policy_test(policyarn):
    client=boto3.client("iam")
    for retries in range(3):
        try:
                    
            response = client.get_policy(
        PolicyArn=policyarn
)
            if response and response.get("Policy").get("Arn"):
                return {"status":"success","data":response.get("Policy").get("Arn")}
            
        except Exception as e:
            if retries<2:
                time.sleep(2**retries)
            else:
                return {
                    "status":"failed",
                    "data":"Policy Fetch Failed"}
                    
    
def reset_password(username):
    
    url="http://localhost:5678/webhook-test/resetpassword"
    data={
        "username":username
    }
    response=requests.post(url,json=data)
    response.raise_for_status()

def get_last_accessed_service(arn):
    stale=False
    try:
        client=boto3.client("iam")
        response = client.generate_service_last_accessed_details(
        Arn=arn
        )
        while True:
            service_response=client.get_service_last_accessed_details(
        JobId=response["JobId"])
            if service_response.get('JobStatus',"").lower()=="completed":
                break
        
        if service_response.get("ServicesLastAccessed"):
            for items in service_response.get("ServicesLastAccessed"):
                if items.get("LastAuthenticated"):
                    days=(datetime.now()-items.get("LastAuthenticated")).days
                    if days>90:
                        stale=True
                else:
                    stale=True
        else:   
            stale=True
        return{
            "stale":stale,
            "arn":arn
        }
    except Exception as e:
        return{
            "stale":stale,
            "message":f"Error while determining stale account : {str(e)}"
        }


if __name__=="__main__":
    #aws_create("test-user-02","arjuneddy@gmail.com")
    #add_user_to_group("test-user-02","test_group")
    #aws_attach_policy("test-user-02","arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess")
    #aws_delete("test-user-02")
    #password=generate_password(12)
    #aws_get_policy_test("arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess")
    #reset_password("test-user-02")
    get_last_accessed_service("arn:aws:iam::002125562743:user/test-user-02")