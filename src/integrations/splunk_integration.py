import os
import sys
sys.path.append(os.getcwd())
from src.integrations.base_integration import BaseIntegration
class SplunkIntegration(BaseIntegration):
    def __init__(self):
        super().__init__("Splunk")
    
    def search(self,input:dict):
        return(super().execute("search",{"query":input['query']} ))

    def get_results(self,job_id:str):
        return(super().execute("get_results",{"job_id":job_id}))