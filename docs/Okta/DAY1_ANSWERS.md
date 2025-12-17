## Q1: What are the 5 stages of identity lifecycle?

**Provisioning**
    Creating user
**Authentication**
    Authenticating created user with password/mfa
**Authorization/Access management**
    Providing appropriate roles for the user
**GRC**
    monitoring the access usage
**Deprovisioning**
    disabling the user upon offboarding


## Q2: What's the difference between user states in Okta?

STAGED vs PROVISIONED vs ACTIVE vs SUSPENDED vs DEPROVISIONED
When do you use each?
STAGED:
User has been imported from or created in the universal directly.
eg: User who has accepted joining formalities

Provisioned:
User account has been created in okta and may have been created in applications but the user can still not log in
user has been selected for project but is waiting project confirmation

Active:
User can log in into provided applications
active user who has joined a project

suspended:
All access for the user is live but the account is locked for some reason
eg:
user locked due to incorrect password

Deprovisioned:
The user is disabled in the system


Q3: What happens if you create a user with an existing email?

HTTP status code?
400
Error message?
'{"errorCode":"E0000001","errorSummary":"Api validation failed: login","errorLink":"E0000001","errorId":"oae5Xjl9pWiQVSAydouCQDcZA","errorCauses":[{"errorSummary":"login: An object with this field already exists in the current organization"}]}'
How do you handle this in automation?
absorb the error and send a proper response
{
    "status":"failed",
    "message":"errorSummary"
}

Q4: What's the difference between suspend vs deactivate?
    Suspend is when all the access is retained, the user is active however the account is suspended or locked out

    deactivate: Disable the user in  IAM

Can suspended user be reactivated?
    Yes
Can deactivated user login?
    No
Which is reversible?
    suspended and disabled
Q5: What user attributes are required vs optional?
    email, first name and last name, username

Minimum fields to create user?
What's profile.login vs profile.email?
both are email ids in okta
email is used for communications
login is used for authentication


SECTION B: API Questions (Test and document answers)
Q6: What's the endpoint to create a user?

HTTP method?
post

Required headers?
 headers={
        "Authorization":f"SSWS {api_key}"
    }
Request body structure?

    payload = {
  "profile": {
    "firstName": "R",
    "lastName": "R",
    "email": "r.r@accenture.com",
    "login": "r.r@accenture.com",
    "mobilePhone": "111-170-5070"
  }
}

Q7: How do you send activation email vs activate immediately?
one can activate by sending an activation email if the password is not provided
one can activate immediately by just creating the use

What parameter controls this?
password
if password is provided or if the user is part of federation then it gets activated immediately
if password isnt provided it is staged
Default behavior?
default behaviour is to set the user to stage and send activation email

Q8: What's the API response structure?

Status code for success?
200
What fields are returned?

{
"id": "00ub0oNGTSWTBKOLGLNR",
"status": "STAGED",
"created": "2013-07-02T21:36:25.344Z",
"activated": null,
"statusChanged": null,
"lastLogin": null,
"lastUpdated": "2013-07-02T21:36:25.344Z",
"passwordChanged": null,
"type": {
"id": "otyfnjfba4ye7pgjB0g4"
},
"profile": {
"firstName": "Isaac",
"lastName": "Brock",
"email": "isaac.brock@example.com",
"login": "isaac.brock@example.com",
"mobilePhone": "555-415-1337"
},
"credentials": {
"provider": {
"type": "OKTA",
"name": "OKTA"
}
},
"_links": {
"schema": {
"href": "https://{yourOktaDomain}/api/v1/meta/schemas/user/oscfnjfba4ye7pgjB0g4"
},
"activate": {
"href": "https://{yourOktaDomain}/api/v1/users/00ub0oNGTSWTBKOLGLNR/lifecycle/activate"
},
"self": {
"href": "https://{yourOktaDomain}/api/v1/users/00ub0oNGTSWTBKOLGLNR"
},
"type": {
"href": "https://{yourOktaDomain}/api/v1/meta/types/user/otyfnjfba4ye7pgjB0g4"
}
}
}

Where's the user ID?
profile.login


Q9: How do you handle API rate limits?
max retries on 429 and exponential backoffs
What's Okta's limit?
Action and Okta API endpoint	Integrator Free Plan	One App	Enterprise	Workforce identity
Authenticate different end users:
/api/v1/authn
This specific endpoint is eligible for dynamic scale and workforce multiplier
/api/v1/authn*
Not all endpoints under this base schema are eligible for dynamic scale and workforce multiplier. Check the APIs table on the rate limit dashboard and filter by Eligible or applied for Rate Limit Multiplier.	100	600	600	500
Verify a factor:
/api/v1/authn/factors/{factorIdOrFactorType}/verify only
Eligible for dynamic scale and workforce multiplier	100	600	600	500
Get session information:
/api/v1/sessions
Eligible for dynamic scale and workforce multiplier	100	600	600	750
OAuth2 requests for Custom Authorization Servers:
/oauth2/{authorizationServerId}/v1 except /oauth2/{authorizationServerId}/v1/authorize, /oauth2/{authorizationServerId}/v1/token, and public metadata endpoints (see Endpoints without rate limiting)
Eligible for dynamic scale and workforce multiplier	300	1,200	1,200	2,000
/oauth2/{authorizationServerId}/v1/authorize
Eligible for dynamic scale and workforce multiplier	300	1200	1200	2000
/oauth2/{authorizationServerId}/v1/token
Eligible for dynamic scale and workforce multiplier	300	1200	1200	2000
OAuth2 requests for the Org Authorization Server:
/oauth2/v1 except /oauth2/v1/clients, /oauth2/v1/authorize, /oauth2/v1/token, and public metadata endpoints (see Endpoints without rate limiting)
Eligible for dynamic scale and workforce multiplier	300	1,200	1,200	2,000
/oauth2/v1/authorize
Eligible for dynamic scale and workforce multiplier	300	1200	1200	2000
/oauth2/v1/token
Eligible for dynamic scale and workforce multiplier	300	1200	1200	2000
All other OAuth2 requests:
/oauth2	100	600	600	600
/app/{app}/{key}/sso/saml
Eligible for dynamic scale and workforce multiplier	100	600	600	750
/app/office365{appType}/{key}/sso/wsfed/active
Eligible for workforce multiplier	N/A	N/A	2,000	1,000
/app/office365{appType}/{key}/sso/wsfed/passive
Eligible for workforce multiplier	N/A	N/A	250	250
/app/template_saml_2_0/{key}/sso/saml
Eligible for dynamic scale and workforce multiplier	100	600	600	2,500
/login/login.htm
Eligible for dynamic scale and workforce multiplier	200	1200	1200	1200
/login/sso_iwa_auth
Eligible for workforce multiplier	100	600	600	500
/api/{apiVersion}/radius
Eligible for workforce multiplier	100	600	600	600
/login/token/redirect
Eligible for dynamic scale and workforce multiplier	100	600	600	600
Identity Engine Identity Engine APIs:
Identity Engine rate limits are configured to support 1000 Identity Engine authentication flows per minute. Depending on the authentication flow, some endpoint limits may differ.				
/idp/idx	100	1000	1000	1000
/idp/idx/identify
Eligible for dynamic scale and workforce multiplier	100	1000	1000	1000
/idp/idx/introspect
Eligible for dynamic scale and workforce multiplier	200	2000	2000	2000
Identity Engine App intent
Eligible for dynamic scale and workforce multiplier	200	2000	2000	2000



Which header tells you remaining quota?

How to implement retry logic?
try:
for retries in max_retries:
    code logic
catch exception and on e.code==429
time.sleep(2**retries)

Q10: How do you search for users?
https://{yourOktaDomain}/api/v1/users/{id}
id here mentions the userid
it can be okta uid
or email or login 

in gui go to people tab and perform string search
Search by email endpoint?
in gui use advanced search and search by email

Search by last login date?

Filter syntax?

 status, lastUpdated, id, profile.login, profile.email, profile.firstName, and profile.lastName.

 def okta_test(method,id=str,search=str):
    if id!="":
        id = quote_plus(id)
    url=f"https://integrator-1776498.okta.com/{method}/{id}"
    api_key=os.getenv("OKTA")
    headers={
        "Authorization":f"SSWS {api_key}"
    }
    params={}
    if str !="":
       params['filter']='status eq "ACTIVE" and lastLogin gt "2025-11-25"'

    response=requests.get(url,headers=headers,params=params)
    response.raise_for_status()

def create_user():
    url="https://integrator-1776498.okta.com/api/v1/users"
    
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


BUILD CHALLENGE 1: User Onboarding (90 min)
Create N8N workflow answering these:
Q11: How do you receive new hire data?

Webhook structure?
json
{
    firstname:"",
    lastname:"",
    username:"",
    email:""
}
Required fields validation?

Q12: How do you create user in Okta?

N8N HTTP Request setup?
webhook->http post request with body
Where do you store API token?
env variable or n8n credential manager

Q13: How do you handle errors?

User already exists?
{
    status:failed
    "message":errorSummart
}
Invalid email format?
validation with regex
[a-z](?:(?:[a-zA-Z0-9-]{1,61})?([a-z])?\.)+[a-z]{2,}

API timeout?
retry and max retries

Q14: How do you assign to group after creation?

What's the endpoint?

https://{yourOktaDomain}/api/v1/groups/{groupId}/users/{userId}
Do you need group ID? How to get it?
https://{yourOktaDomain}/api/v1/groups and search by name

Q15: How do you log success/failure?
{
    status:success/failure,
    message:assignment successful/errorSummary
}

Where to send logs?
email notification? - not sure
What data to capture?
    username and group nam e


Deliverable: Working flow that creates user + assigns group + sends notification

BUILD CHALLENGE 2: User Offboarding (60 min)
Q16: What's the secure offboarding sequence?

Suspend first or deactivate first? Why?
deactivate first
When to remove group memberships?

Q17: How do you get all groups for a user?

API endpoint?
Pagination if >200 groups?

Q18: How do you remove from all groups?

Loop through groups in N8N?
What if removal fails for one group?

Q19: How do you revoke active sessions?

API endpoint?
Does suspend auto-revoke sessions?

Q20: How do you schedule delayed deactivation?

Suspend now, deactivate in 30 days?
How to implement in N8N?

Deliverable: Flow that suspends → removes groups → schedules deactivation