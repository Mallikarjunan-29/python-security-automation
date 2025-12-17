import requests
import os
import sys
from urllib.parse import quote_plus

sys.path.append(os.getcwd())

def okta_test(method,id="",search=""):
    params={}
    if id!="":
        id = quote_plus(id)
        
    if search !="":
       params['filter']='status eq "PROVISIONED"'

    url=f"https://integrator-1776498.okta.com/{method}/{id}"
    api_key=os.getenv("OKTA")
    headers={
        "Authorization":f"SSWS {api_key}"
    }
    
    response=requests.get(url,headers=headers,params=params)
    response.raise_for_status()

def create_user():
    url="https:/integrator-1776498.okta.com/api/v1/users"
    
    payload = {
  "profile": {
    "firstName": "Ramyaa",
    "lastName": "Rajasekaran",
    "email": "ramyaa.rajasekaran@accenture.com",
    "login": "ramyaa.rajasekaran@accenture.com",
    "mobilePhone": "947-270-5070"
  }
}
    
    api_key=os.getenv("OKTA")
    headers={
        "Authorization":f"SSWS {api_key}"
    }
    
    response=requests.post(url,json=payload,headers=headers)
    response.raise_for_status()

def web_booktest(login,days=0):
    #url="https://long-water-5102.tines.com/webhook/OktaUserCreation/2be6ab310fc1156f8d25ebb174cc34cb"
    url2="http://localhost:5678/webhook/TempUsrCreate"
    data={
        "profile": {
    "firstName": "Arjun",
    "lastName": "Krishnna",
    "email": "arjuneddy@gmail.com",
    "login": login,
    "mobilePhone": "947-270-5070"
  },
  "groups":["Engineering","Medicine"],
  "days":days
    }
    header={
        "Content-Type":"application/json"
    }
    #response=requests.post(url,json=data,headers=header)
    #response.raise_for_status()
    response2=requests.post(url2,json=data,headers=header)
    response2.raise_for_status()

def get_groups():
    

    
    url="https://integrator-1776498.okta.com/api/v1/users/00uxtax0liL9CQ4gr697/groups"
    
    api_key=os.getenv("OKTA")
    header={
        "Authorization":f"SSWS {api_key}"
    }
    
    response=requests.get(url,headers=header)
    response.raise_for_status()

def delete_okta_user(userid,method):
    data={}
    if method =="delete":
        url="http://localhost:5678/webhook-test/deleteuser"
    else :
        url="http://localhost:5678/webhook/suspendoktauser"
    encoded_data=quote_plus(userid)
    data={
        "id":encoded_data
    }
    header={
        "Content-Type":"application/json"
    }
    response=requests.post(url,json=data,headers=header)
    response.raise_for_status()

def group_add():
    url="http://localhost:5678/webhook/createoktagroup"
    
    
    
    payload={
        "profile":{
            "name":"Medicine",
            "description":"Medicine group"
        }
    }

    response=requests.post(url=url,json=payload)
    response.raise_for_status()



if __name__=="__main__":
   # okta_test("api/v1/users")
    #create_user()
    """
    web_booktest("arjuneddy32@gmail.com",90)
    web_booktest("arjuneddy25@gmail.com",90)
    web_booktest("arjuneddy24@gmail.com",90)
    web_booktest("arjuneddy26@gmail.com",90)
    web_booktest("arjuneddy27@gmail.com",90)
    
    """
    delete_okta_user("arjuneddy24@gmail.com","suspend")
    delete_okta_user("arjuneddy32@gmail.com","suspend")
    delete_okta_user("arjuneddy25@gmail.com","suspend")
    delete_okta_user("arjuneddy26@gmail.com","suspend")
    delete_okta_user("arjuneddy27@gmail.com","suspend")
    #delete_okta_user("arjuneddy30@gmail.com","suspend")
    
    
    #group_add()
    
    
    
    
    
    
    
    #get_groups()