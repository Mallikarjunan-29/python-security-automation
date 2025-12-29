import os
import sys
sys.path.append(os.getcwd())
from test.flask_test import app
import pytest
import requests
import requests
import json
import hashlib
from src.extensions.redis_client import redis_client

@pytest.fixture(scope="module")
def client():
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="module")
def jwt_token():
    client_id=os.getenv("OKTA_API_CLIENT")
    secret=os.getenv("OKTA_API_SECRET")
    token_url=f"{os.getenv('OKTA_ISSUER')}/v1/token"
    data = {
            "grant_type": "client_credentials",
            "scope": "alert.read alert.write"
        }
    resp = requests.post(
            token_url,
            data=data,
            auth=(client_id, secret)            
        )
    token_json = resp.json()
    yield token_json.get("access_token")
    
        

def test_submitalert_success(client,jwt_token):
    headers={
        "Authorization":f"Bearer {jwt_token}"
    }
    response=client.post("/submit_alert",headers=headers,json={"alert":"test"})
    assert response.status_code==200
    data=response.get_json(force=True)
    assert "jobid" in data
    assert "status" in data

def test_submitalert_failure_emptydata(client,jwt_token):
    headers={
        "Authorization":f"Bearer {jwt_token}"
    }
    response=client.post("/submit_alert",headers=headers)
    assert response.status_code==400
    
def test_submitalert_failure_malformeddata(client,jwt_token):
    headers={
        "Authorization":f"Bearer {jwt_token}"
    }
    response=client.post("/submit_alert",headers=headers,data="alert")
    assert response.status_code==400

def test_submitalert_duplicatekey(client,jwt_token):
    headers={
        "Authorization":f"Bearer {jwt_token}"
    }
    alert_data={
        "test1":"test1"
    }
    response=client.post("/submit_alert",headers=headers,json=alert_data)
    assert response.status_code ==200
    data=response.get_json()
    assert 'jobid' in data
    assert 'status' in data
    test_data=redis_client.get_job(data['jobid'])
    assert test_data is not None
    assert 'status' in test_data
    test_data['status']="completed"
    redis_client.set_job(data['jobid'],test_data)
    test_data=redis_client.get_job(data['jobid'])
    assert test_data['status']=='completed'
    response=client.post("/submit_alert",headers=headers,json=alert_data)
    assert response.status_code==200
    data=response.get_json()
    assert "jobid" in data
    assert "status" in data
    assert data['status']=="completed"

    
def test_submitnewalert_responsetime(client,jwt_token):    
    headers={
        "Authorization":f"Bearer {jwt_token}"
    }
    alert_data={
        "test2":"test2"
    }
    response=client.post("/submit_alert",headers=headers,json=alert_data)
    assert response.status_code ==200
    data=response.get_json()
    assert 'jobid' in data
    assert 'status' in data
    assert 'responsetime' in data
    assert data['responsetime'] <5000


def test_submitduplicatealert_responsetime(client,jwt_token):    
    headers={
        "Authorization":f"Bearer {jwt_token}"
    }
    alert_data={
        "test2":"test2"
    }
    response=client.post("/submit_alert",headers=headers,json=alert_data)
    assert response.status_code ==200
    data=response.get_json()
    assert 'jobid' in data
    assert 'status' in data
    assert 'responsetime' in data
    assert data['responsetime'] <5000


