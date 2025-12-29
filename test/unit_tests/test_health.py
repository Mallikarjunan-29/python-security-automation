import os
import requests
def test_health():
    url= f"{os.getenv('BASE_URL')}/health"
    response=requests.get(url)
    assert response.status_code==200
    body=response.json()
    assert body["status"]=="healthy"
    assert body["redis_status"]=="healthy"