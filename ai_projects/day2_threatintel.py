import requests
import os
import dotenv
import time
import logging
from logging.handlers import RotatingFileHandler
from ipaddress import ip_address
from ipaddress import ip_network
dotenv.load_dotenv()
import sys
sys.path.append(os.getcwd())
from src.logger_config import  get_logger

logger=get_logger(__name__)

def abuseip_lookup(ip,maxretries=3):
    #AbuseDB IP LookUP functionality
    if ip_address(ip) in ip_network("10.0.0.0/8") or ip_address(ip) in ip_network("172.16.0.0/12") or ip_address(ip) in ip_network("192.168.0.0/16"):
        logger.debug("ABUSEIPDB RESPONSE: IP is a private IP")
        return "IP is a private IP"
    for retries in range(maxretries):
        try:
            abuse_dict={}
            abuse_key=os.getenv("ABUSEIPDB") #AbuseIPDB API key
            if not abuse_key:
                raise ValueError("API Key Not found for AbuseIPDB")
            
            #AbuseIPDB API Call parameters
            abuse_url="https://api.abuseipdb.com/api/v2/check"
            querystring={
                'ipAddress':ip,
                'maxAgeInDays':90
            }
            header={
                'Accept':'application/json',
                'KEY':abuse_key
            }
            abuse_response=requests.get(abuse_url,headers=header,params=querystring,timeout=10) #AbuseIPDB API call
            abuse_response.raise_for_status() # Throws error for all codes >400
            if abuse_response.status_code==200:
                abuse_json=abuse_response.json()
                abuse_data=abuse_json.get("data","")
                abuse_dict={
                    "IP":abuse_data.get("ipAddress",""),
                    "UsageType":abuse_data.get("usageType",""),
                    "ISP":abuse_data.get("isp",""),
                    "ISTor":abuse_data.get("isTor",""),
                    "TotalReports":abuse_data.get("totalReports",0),
                    "AbuseConfidenceScore":abuse_data.get("abuseConfidenceScore",0),
                    "IsWhiteListed":abuse_data.get("isWhitelisted",True)
                }
            return abuse_dict
        except ValueError as e:
            logger.error(e)
            print(f"API Key not found:{e}")
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the ip: {ip}")
                continue
            logger.error(e)
            return None
        
#VT Lookup
def vtip_lookup(ip,maxretries=3):
    if ip_address(ip) in ip_network("10.0.0.0/8") or ip_address(ip) in ip_network("172.16.0.0/12") or ip_address(ip) in ip_network("192.168.0.0/16"):
        logger.debug("VT RESPONSE: IP is a private IP")
        return "IP is a private IP"
    vt_dict={}
    #VT LookUP functionality
    for retries in range(maxretries):
        try:
            vt_key=os.getenv("VTKEY") #AbuseIPDB API key
            if not vt_key:
                raise ValueError("API Key Not found for VirusTotal")
            
            #VT API Call parameters
            abuse_url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"accept": "application/json",
                       "x-apikey":vt_key}

            vt_response=requests.get(abuse_url,headers=headers,timeout=10) #VT API call
            vt_response.raise_for_status() # Throws error for all codes >400
            if vt_response.status_code==200:
                vt_json=vt_response.json()
                vt_data=vt_json.get("data",{})
                vt_attributes=vt_data.get("attributes",{})
                vt_rdap=vt_attributes.get("rdap",{})
                vt_dict={
                    "IPAddress":vt_data.get("id",0),
                    "Owner":vt_attributes.get("as_owner",""),
                    "Stats":vt_attributes.get("last_analysis_stats",{}),
                    "Reputation":vt_attributes.get("reputation",0),  
                    "UsageType":vt_rdap.get("name","")                  
                }
            #logger.info(vt_response.text)
            return vt_dict
        except ValueError as e:
            logger.error(e)
            print(f"API Key not found:{e}")
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the ip: {ip}")
                continue
            logger.error(e)
            return None
        
def ip_lookup(ip):
    abuse_response=abuseip_lookup(ip)
    vt_response=vtip_lookup(ip)
    return abuse_response,vt_response
#ip_lookup('203.0.113.50')

