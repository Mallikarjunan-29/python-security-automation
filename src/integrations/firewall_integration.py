import os
import sys
sys.path.append(os.getcwd())
from src.integrations.base_integration import BaseIntegration
class FirewallIntegration(BaseIntegration):
    def __init__(self):
        super().__init__("Palo Alto Firewall")
    
    def block_ip(self,ip:dict):
        return(super().execute("block_ip",{"ip":ip['ip']}))