import re
import json
import os
import sys
from ai_projects.soar.playbook_parser import load_playbook,validate_playbook
from src.logger_config import get_logger
logger=get_logger(__name__)
playbook=os.path.join(os.getcwd(),"data/playbooks/brute_force_mitigation.yaml")
def resolve_playbook(playbook,alert):
    try:
        parsed_playbook=load_playbook(playbook)
        validated_playbook=validate_playbook(parsed_playbook)

        keys_in_playbook=re.findall(r"(?:\$\{)((?:[a-zA-Z_]+\.?)+)\}",json.dumps(validated_playbook))
        key_value={}
        for keys in keys_in_playbook:
            key_parts=keys.split(".")
            value=alert[key_parts[0]]
            for index in range(1,len(key_parts)):
                value=value[key_parts[index]]
            
            key="${"+keys+"}"
            key_value[key]=value


        validated_playbook_str=json.dumps(validated_playbook)
        for key,value in key_value.items():
            validated_playbook_str= validated_playbook_str.replace(key,value)
        return json.loads(validated_playbook_str)
    except Exception as e:
        logger.error(str(e))
        return None

if __name__=="__main__":

    alert={
    "alert": {
        "id": "bf-20251117-001",
        "source": {
        "ip": "192.168.1.45"
        },
        "user": "john.doe"
    }
    }
    resolve_playbook(playbook,alert)


