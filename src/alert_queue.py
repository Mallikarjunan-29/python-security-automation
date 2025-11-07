import sys
import os
import json
sys.path.append(os.getcwd())
from src.logger_config import get_logger
from src.cache_handler import CacheHandler
logger=get_logger(__name__)
def queue_alert(alerts):
    try:
        logger.debug("Alert Queue sorting start")
        priority_map={"Critical":1,"High":2,"Medium":3,"Low":4}
        for alert in alerts:
            alert['alert'].update({'prioritylevel':priority_map.get(alert.get("alert",10).get("severity",10),10)})
        alerts.sort(key= lambda x: x['alert']['prioritylevel'])   
        logger.debug("Alert Queue Sorting ended")
        return alerts
    except Exception as e:
        logger.error(e)
        return None
    
def get_topalerts(alerts,number=10):
    try:
        
        alerts.sort(key=lambda x:x['PriorityLevel'])
        number = number if len(alerts)>=number else len(alerts)
        for count in range(number):
            print(f"Alert Number {count+1}")
            print("="*50)
            print(f"Alert Name: {alerts[count]['alert_name']}")
            print(f"AISeverity:{alerts[count]['AISeverity']}")
            print(f"AlertSeverity:{alerts[count]['AlertSeverity']}")
            print(f"AI Classification:{alerts[count]['Classification']}")
            print(f"AI Confidence Score:{alerts[count]['Confidence']}")
            print(f"AI Reasoning:{alerts[count]['Reasoning']}")
            print(f"AI Priority:{alerts[count]['PriorityLevel']}")            
            print("="*50)
    except IndexError as e:
        logger.error(e)
    except Exception as e:
        logger.error(e)


    
