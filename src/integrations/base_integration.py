from datetime import datetime
import uuid
import time
from typing import Dict

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