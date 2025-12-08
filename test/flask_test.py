from flask import Flask,jsonify,request
import sys
import os
import time
import json
from datetime import datetime
sys.path.append(os.getcwd())
from ai_projects.batch_processor import test_function
from src.ioc_extractor import extract_behavior
from src.logger_config import get_logger
from ai_projects.soar.executor import execute_playbook
logger=get_logger(__name__)
app=Flask(__name__)

def format_datetime(date_time):
    try:
        date_time=date_time.strftime("%Y-%m-%d %H:%M:%S")
        return date_time
    except Exception as e:
        logger.error(e)
        return None
server_up_time=time.time()
server_start=format_datetime(datetime.now())



def get_cache():
    base_path=os.getcwd()
    cache_path=os.path.join(base_path,"cache")
    ai_cache_path=os.path.join(cache_path,"ai_cache.json")
    ti_cache_path=os.path.join(cache_path,"cache.json")
    ti_file_size=0
    ai_file_size=0
    ti_entries=0
    ai_entries=0
    if os.path.exists(ti_cache_path):
        ti_file_size=(os.path.getsize(ti_cache_path))/(1024*1024)
        with open(ti_cache_path) as f:
            ti_cache=json.load(f)
        ti_entries=len(ti_cache)
    
    if os.path.exists(ai_cache_path):
        ai_file_size=(os.path.getsize(ai_cache_path))/(1024*1024)
        with open(ai_cache_path) as f:
            ai_cache=json.load(f)
        ai_entries=len(ai_cache)
    
    
    cache_data={
        "threat_intel":{
            "exists":os.path.exists(ti_cache_path),
            "cache_size":f"{ti_file_size} MB",
            "entries":ti_entries        
        },
        "ai_response":{
            "exists":os.path.exists(ai_cache_path),
            "cache_size":f"{ai_file_size} MB",
            "entries":ai_entries
        }
    }

    return cache_data

def chec_api_config():
    gemini_status="online" if os.getenv("GEMINIKEY") else "offline"
    Abuse_Ip_status="online" if os.getenv("ABUSEIPDB") else "offline"
    VT_status="online" if os.getenv("VTKEY") else "offline"
    api_data={
        "gemini_status":gemini_status,
        "abuse_ip_db_status":Abuse_Ip_status,
        "vt_Status":VT_status
    }
    return api_data

last_request_info = {
    "endpoint": None,
    "timestamp": None,
    "alerts_processed": 0,
    "processing_time": 0.0
}

@app.route("/")
def helloworld():
    return "<p>Hello World </p>"

@app.route("/home")
def home():
    return jsonify({
        "message":"Alert Triage API",
        "response":"success"
    })

@app.route("/analyze",methods=['POST'])
def analyze():
    try:
        global last_request_info
        data=request.get_json(force=True)
        if not data:
            message={
                "status":"error",
                "message":"Invalid or missing json"
            }
            return  jsonify(message),400
        resultlist,total_time = test_function(data)
        resultset=[]
        if resultlist:
            for results in resultlist:
                ti_values=[]
                if results.get('TI_Cache',0)!=0:
                    for values in results['TI_Cache'].values():
                        ti_values.append(values)
                ai_values=[]
                if results.get('AI_Cache',0)!=0:
                    for values in results['AI_Cache'].values():
                        ai_values.append(values)
                
                data_to_add={
                    "classification":results["Classification"],
                    "confidence":results["Confidence"],
                    "severity":results["AISeverity"],
                    "reasoning":results["Reasoning"],
                    "priority":results["Priority"],
                    "title":results["Title"],
                    "performance":{
                        "processing_time":total_time,
                        "total_cost":f"${results['TimingBreakDown']['CalculateCost']}"
                    },
                    "runbook":results['runbooks']
                }
                resultset.append(data_to_add)
                
            last_request_info={
                "endpoint": "/analyze",
                "timestamp": format_datetime(datetime.now()),
                "alerts_processed": len(resultset),
                "processing_time": total_time
            }

            #behaviour=extract_behavior(title)
            behaviour=resultset[0]['title']
            if resultset[0]['classification']=="TRUE_POSITIVE":
                
                if behaviour=="brute_force_auth":
                    playbook_execution= execute_playbook(os.path.join(os.getcwd(),"data/playbooks/brute_force_mitigation.yaml"),data)
                elif "exfil" in behaviour:
                    playbook_execution=execute_playbook(os.path.join(os.getcwd(),"data/playbooks/data_exfiltration_response.yaml"),data)
                elif "lateral" in behaviour:
                    playbook_execution=execute_playbook(os.path.join(os.getcwd(),"data/playbooks/lateral_movement_containment.yaml"),data)
                elif "powershell" in behaviour:
                    playbook_execution=execute_playbook(os.path.join(os.getcwd(),"data/playbooks/malicious_powershell.yaml"),data)
                elif "phishing" in behaviour:
                    playbook_execution=execute_playbook(os.path.join(os.getcwd(),"data/playbooks/phishing_response.yaml"),data)
                else:
                    playbook_execution={"status":"no_matching_playbook"}
            else:
                playbook_execution=None
            
            resultset[0]['playbook_execution']=playbook_execution

            return jsonify(resultset)
        else:
            return jsonify({"message":"No data"})
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/batch",methods=['POST'])
def batch_process():
    try:
        data=request.get_json(silent=True)
        if not data:
            message={
                "status":"error",
                "message":"Invalid or missing json"
            }
            return  jsonify(message),400
        alerts=[]
        for values in data.values():
            alerts.append(values)
        
        for items in alerts:
            resultlist,total_time = test_function(items)
            resultset=[]
            true_positive=0
            false_positive=0
            needs_review=0
            total_cost=0.0
            ai_cache_hit=0
            ti_cache_hit=0
            global last_request_info
            if resultlist:
                for results in resultlist:
                    logger.debug(f"documenting alert {alerts}")
                    true_positive+=1 if results["Classification"] =="TRUE_POSITIVE" else 0
                    false_positive+=1 if results["Classification"] =="FALSE_POSITIVE" else 0
                    needs_review+=1 if results["Classification"] =="NEEDS_REVIEW" else 0
                    total_cost+=float(results['TimingBreakDown']['CalculateCost'])
                    ti_values=[]
                    if results.get('TI_Cache',0)!=0:
                        for values in results['TI_Cache'].values():
                            ti_values.append(values)
                    ai_values=[]
                    if results.get('AI_Cache',0)!=0:
                        for values in results['AI_Cache'].values():
                            ai_values.append(values)
                    
                    data_to_add={
                        "classification":results["Classification"],
                        "confidence":results["Confidence"],
                        "severity":results["AISeverity"],
                        "reasoning":results["Reasoning"],
                        "threat_intel":ti_values if ti_values else "",
                        "ai_cache_hit":ai_values if ai_values else "",
                        "performance":{
                            "processing_time":total_time,
                            "total_cost":f"${results['TimingBreakDown']['CalculateCost']}"
                        },
                        "runbook":results['runbooks']
                    }
                    resultset.append(data_to_add)
                final_result={
                    "summary":{
                        "total":len(resultset),
                        "true_positive":true_positive,
                        "false_positive":false_positive,
                        "needs_review":needs_review,
                        "processing_time":total_time,
                        "total_cost":f"${total_cost}",
                        "ai_cache_hit":f"{(ai_cache_hit*100)/len(resultset)}%",
                        "ti_cache_hit":f"{(ti_cache_hit*100)/len(resultset)}%"                        
                    },"results":resultset
                }
                last_request_info={
                "endpoint": "/batch",
                "timestamp": format_datetime(datetime.now()),
                "alerts_processed": len(resultset),
                "processing_time": total_time
            }
                return jsonify(final_result)
            else:
                return jsonify({"message":"No data"})
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/health",methods=['GET'])
def healthcheck():
    try:
        api_data=chec_api_config()
        offline_count=0
        for values in api_data.values():
            offline_count+=1 if values == "offline" else 0
        status="healthy"
        if offline_count==3:
            status="unhealthy"
        elif offline_count>0:
            status="degraded"

        health={
            "status":status,
            "server_up_time":time.time()-server_up_time,
            "server_info":{
                "started_at":server_start,
                "current_time":format_datetime(datetime.now()),
            },
            "cache":get_cache(),
            "api_data":chec_api_config(),
            "last_api_call":last_request_info
        }
        return jsonify(health)
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

    
if __name__=="__main__":
    app.run(debug=True,port=5000,host="0.0.0.0")
