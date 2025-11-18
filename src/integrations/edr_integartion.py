import os
import sys
sys.path.append(os.getcwd())
from src.integrations.base_integration import BaseIntegration

class EdrIntegration(BaseIntegration):
    def __init__(self):
        super().__init__("Crowdstrike EDR")
    
    def isolate_host(self,hostname:dict):
        return(super().execute("isolate_host",{"host":hostname}))
    
    def kill_process(self,process_id:dict):
        return(super().execute("kill_process",{"process_id":process_id}))
