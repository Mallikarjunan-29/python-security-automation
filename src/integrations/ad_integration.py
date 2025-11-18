import os
import sys
sys.path.append(os.getcwd())
from src.integrations.base_integration import BaseIntegration

class ActiveDirectoryIntegration(BaseIntegration):
    def __init__(self):
        super().__init__("Active Directory")
    
    def disable_user(self,user:dict):
        return(super().execute("disable_user",{"user":user['user']}))
    
    def reset_password(self,user:dict):
        return(super().execute("reset_password",{"user":user['user']}))