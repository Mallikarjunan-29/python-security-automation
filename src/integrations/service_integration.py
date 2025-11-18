import os
import sys
sys.path.append(os.getcwd())
from src.integrations.base_integration import BaseIntegration
class ServiceIntegration(BaseIntegration):
    def __init__(self):
        super().__init__("Service Now")
    
    def create_ticket(self,input:dict):
        return(super().execute("create_ticket",{"alert_id":input['alert_id'],"title":input['title'],"description":input['description']}))
    
    def update_ticket(self,ticket_id,status):
        return(super().execute("update_ticket",{"ticket_id":ticket_id,"status":status}))
