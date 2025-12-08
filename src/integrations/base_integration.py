from datetime import datetime
import uuid
import time
from typing import Dict
import requests
class BaseIntegration:
    def __init__(self,name):
        self.name=name
    
    def execute(self,action:str,params:dict):
        """Exexcute any action with standardized response"""
        time.sleep(.3)
        return{
            "status":"Success",
            "platform":self.name,
            "action":action,
            "params":params,
            "execution_id":str(uuid.uuid4()),
            "timestamp":datetime.now().isoformat()
        }
    
    def send_alert_notification(self, alert_data, ai_result, playbook_result):
        header={
            "Content-Type":"application/json"
        }
        data={
            alert_data
        }
        response=requests.post(self.url,headers=header,json=data)
        response.raise_for_status()