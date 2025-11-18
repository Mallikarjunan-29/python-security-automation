import os
import sys
import errno
import yaml
from yaml.error import YAMLError

sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)
def load_playbook(playbook_path:str):
    """
    Load and parse YAML playbook
    
    Args:
        playbook_path: Path to .yaml file
        
    Returns:
        dict: Parsed playbook structure
    """
    try:
        file_data=""
        if os.path.exists(playbook_path):
            if os.path.getsize(playbook_path)>0:
                with open(playbook_path,"r") as f:
                    playbook= yaml.safe_load(f.read())
            else:
                raise Exception("File Size is 0KB")        
        else:
            raise FileNotFoundError(errno.ENOENT,os.strerror(errno.ENOENT),playbook_path)
        
        return validate_playbook(playbook)
    except FileNotFoundError as e:
        logger.error(str(e))
        print(str(e))
    except YAMLError as e:
        logger.error(f"Error in line {e.problem_mark.line}")
        error_message={
            "error":"Yaml parsing failed",
            "status":"failed",
            "error_message":f"Error in line {e.problem_mark.line}. Error message: {e.problem}. Error content:{e.problem_mark.get_snippet()}"
        }
        print (error_message)
        return error_message
    except Exception as e:
        logger.error(str(e))
        return str(e)
        


def validate_playbook(playbook:dict):
    try:
        warnings=[]
        if not "name" in playbook.keys():
            raise ValueError("{'status':'invalid','error':'playbook missing name'}")
        elif not "trigger" in playbook.keys():
            raise ValueError("{'status':'invalid','error':'playbook missing trigger'}")
        elif not "steps" in playbook.keys():
            raise ValueError("{'status':'invalid','error':'playbook missing steps'}")
        elif not "roles_and_responsibilities" in playbook.keys():
            raise ValueError("{'status':'invalid','error':'playbook missing roles_and_responsibilities'}")
        elif not "output" in playbook.keys():
            raise ValueError("{'status':'invalid','error':'playbook missing output'}")
        if not "metadata" in playbook.keys():
            warnings.append("missing metadata")
        if not "description" in playbook.keys():
            warnings.append("missing description")
        if not "integration_tools" in playbook.keys():
            warnings.append("missing integration_tools")
        if not "success_criteria" in playbook.keys():
            warnings.append("missing success_criteria")
        if len(warnings)==0:
            validated={**playbook}
            validated["status"]="clean"
            validated["warnings"]=None
        else:
            validated={**playbook}
            validated["status"]="warning"
            validated["warnings"]=warnings
            
        return validated
    except Exception as e:
        logger.error(str(e))
        return {
            "status": "invalid",
            "error": str(e)
        }

if __name__ == "__main__":
    playbook_path=os.path.join(os.getcwd(),"data/playbooks/brute_force_mitigation_copy.yaml")
    #playbook_path=os.path.join(os.getcwd(),"data/playbooks/emptyfile.txt")
    load_playbook(playbook_path)

