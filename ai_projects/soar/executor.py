import os
import sys
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)
from ai_projects.soar.resolver import resolve_playbook
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from src.integrations import base_integration,firewall_integration,edr_integartion,ad_integration,splunk_integration,service_integration
from src.integrations.ad_integration import ActiveDirectoryIntegration
playbook=os.path.join(os.getcwd(),"data/playbooks/brute_force_mitigation.yaml")
def execute_playbook(playbook,alert):
    resolved_playbook=resolve_playbook(playbook,alert)
    print(resolved_playbook)
    fw= firewall_integration.FirewallIntegration()
    ad=ad_integration.ActiveDirectoryIntegration()
    edr=edr_integartion.EdrIntegration()
    sn=service_integration.ServiceIntegration()
    sp=splunk_integration.SplunkIntegration()
    function_map={
        "block_ip":fw.block_ip,
        "disable_user":ad.disable_user,
        "create_ticket":sn.create_ticket,
        "update_ticket":sn.update_ticket,
        "reset_user_password":ad.reset_password,
        "isolate_host":edr.isolate_host,
        "kill_process":edr.kill_process,
        "splunk_search":sp.search
    }
    if resolved_playbook and resolved_playbook.get("steps"):
        for steps in resolved_playbook.get("steps"):
            if steps['action']=="create_ticket":
                steps['input'].update({"title":resolved_playbook.get('ticket').get("title","None"),"description":resolved_playbook.get('ticket').get("description","None")})
        with ThreadPoolExecutor(max_workers=5) as exe:
            futures=[]
            for steps in resolved_playbook['steps']:
                future=exe.submit(function_map[steps['action']],steps['input'])
                futures.append(future)
                
            
        result_set=[]
        for future in as_completed(futures):
            result=future.result()
            result_set.append(result)
        
        return result_set
            
    else:
        raise ValueError("Invalid playbook format")
    

if __name__=="__main__":
    playbook=os.path.join(os.getcwd(),"data/playbooks/brute_force_mitigation.yaml")
    alert={
    "alert": {
        "id": "bf-20251117-001",
        "source": {
        "ip": "192.168.1.45"
        },
        "user": "john.doe"
    }
    }
    execute_playbook(playbook,alert)

