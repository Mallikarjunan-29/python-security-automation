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
from flask import g
from src.logger_config import  get_logger

logger=get_logger(__name__)

def abuseip_lookup(ip,maxretries=3):
    #AbuseDB IP LookUP functionality
    if ip_address(ip) in ip_network("10.0.0.0/8") or ip_address(ip) in ip_network("172.16.0.0/12") or ip_address(ip) in ip_network("192.168.0.0/16"):
        logger.debug(f"ABUSEIPDB RESPONSE: {ip} is a private IP",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
        return {"ip":f"{ip} is a private IP","AbuseConfidenceScore":0}
    for retries in range(maxretries):
        try:
            logger.debug("Abuse Lookup started",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
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
            logger.debug("Abuse Lookup ended",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return abuse_dict
        except ValueError as e:
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            print(f"API Key not found:{e}")
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the ip: {ip}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                continue
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None
        
#VT Lookup
def vtip_lookup(ip,maxretries=3):
    logger.debug("VT Lookup Started",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
    if ip_address(ip) in ip_network("10.0.0.0/8") or ip_address(ip) in ip_network("172.16.0.0/12") or ip_address(ip) in ip_network("192.168.0.0/16"):
        logger.debug("VT RESPONSE: IP is a private IP",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
        return {"ip":f"{ip} is a private IP","Reputation":100}
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
            logger.debug("VT Lookup ended",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return vt_dict
        except ValueError as e:
            logger.error(e)
            print(f"API Key not found:{e}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the ip: {ip}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                continue
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None

def ip_lookup(ip):
    abuse_response=abuseip_lookup(ip)
    vt_response=vtip_lookup(ip)
    return abuse_response,vt_response
#ip_lookup('203.0.113.50')

def url_lookup(url):
    logger.debug("Url Lookup started",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
    vt_response=vt_url_response(url)
    haus_response=url_haus_response(url)
    logger.debug("Url Lookup ended",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
    return vt_response,haus_response

def vt_url_response(url,maxretries=3):
    logger.debug("VT URL lookup start ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
    for retries in range(maxretries):
        try:
            vt_key=os.getenv("VTKEY")
            if not vt_key:
                raise ValueError("API Key Not found for VirusTotal")
            
            #VT API Call parameters
            url_scan_url=f"https://www.virustotal.com/api/v3/urls"
            headers = {
                "accept": "application/json",
                "x-apikey":vt_key ,
                "content-type": "application/x-www-form-urlencoded"
            }
            
            payload={
                    "url":url,
            }
            url_scan_response=requests.post(url_scan_url,headers=headers,data=payload,timeout=10) #VT API call
            url_scan_response.raise_for_status() # Throws error for all codes >400
            scan_results={}
            if url_scan_response.status_code==200:
                if url_scan_response.ok:
                    logger.debug("VT URL polling start ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                    results=poll_results(url_scan_response.json()['data']['links']['self'],{ "accept": "application/json","x-apikey": vt_key})
                    logger.debug("VT URL polling end ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            scan_results={
                "url":url,
                "stats":results['data']['attributes']['stats'],
            }
            #logger.info(vt_response.text)
            logger.debug("VT URL lookup ended ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return scan_results
        except ValueError as e:
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the url: {url}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                continue
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None



def url_scan_response(url,maxretries=3):
    logger.debug("URL scan response start",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
    for retries in range(maxretries):
        try:
            url_scan_key=os.getenv("URLSCANKEY")
            if not url_scan_key:
                raise ValueError("API Key Not found for VirusTotal")
            
            #VT API Call parameters
            url_scan_url=f"https://urlscan.io/api/v1/scan"
            headers = {"Content-Type": "application/json",
                       "api-key":url_scan_key}
            payload={
                    "url":url,
                    "visibility": "public",
                    "tags":["Testing","API"]
            }
            url_scan_response=requests.post(url_scan_url,headers=headers,json=payload,timeout=10) #VT API call
            url_scan_response.raise_for_status() # Throws error for all codes >400
            scan_results={}
            if url_scan_response.status_code==200:
                logger.debug("URL scan polling start ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                results=poll_results(url_scan_response.json()['api'],{"api-key":url_scan_key})
                logger.debug("URL scan polling end ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            scan_results={
                "url":url,
                "malicious":results['stats']['malicious'],
                "verdicts":results['verdicts']['overall']
            }
            #logger.info(vt_response.text)
            logger.debug("URL scan response start ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return scan_results
        except ValueError as e:
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            print(f"API Key not found:{e}")
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the url: {url}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                continue
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None



def url_haus_response(url,maxretries=3):
     logger.debug("URL haus lookup start ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
     for retries in range(maxretries):
        try:
            url_scan_key=os.getenv("URLHAUS")
            if not url_scan_key:
                raise ValueError("API Key Not found for VirusTotal")
            
            #VT API Call parameters
            url_scan_url=f"https://urlhaus-api.abuse.ch/v1/url/"
            headers = {"Auth-Key":url_scan_key}
            data={
                    "url":url}
            
            url_haus_response=requests.post(url_scan_url,data,headers=headers,timeout=10) #VT API call
            url_haus_response.raise_for_status() # Throws error for all codes >400
            
            haus_response={}
            if url_haus_response.status_code==200:
                url_haus_response=url_haus_response.json()
                if url_haus_response.get("query_status",0)=='ok':
                    haus_response={
                        "verdict":"malicious",
                        "url_status":url_haus_response.get("url_status",0),
                        "threat":url_haus_response.get("threat",0),
                        "blacklists":url_haus_response.get("blacklists",0)
                    }

                logger.debug("URL haus lookup ended ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                return haus_response    
            #logger.info(vt_response.text)
            
            
        except ValueError as e:
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the url: {url}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                continue
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None

def poll_results(url,headers,max_wait=60,interval=3):
    logger.debug("polling started",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
    waited=0
    attempts=0
    while waited<max_wait:
        attempts+=1
        response=requests.get(url=url,headers=headers,timeout=10)
        if response.status_code==200:
            logger.debug("polling ended",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return response.json()
        sleep_time=interval*(attempts+1)
        time.sleep(sleep_time)
        waited+=sleep_time



def vt_domain_response(domain,maxretries=3):
    logger.debug("URL scan response start ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
    for retries in range(maxretries):
        try:
            vt_key=os.getenv("VTKEY")
            if not vt_key:
                raise ValueError("API Key Not found for VirusTotal")
            
            #VT API Call parameters
            url_scan_url=f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {
                "accept": "application/json",
                "x-apikey":vt_key 
            }
            url_scan_response=requests.get(url_scan_url,headers=headers,timeout=10) #VT API call
            url_scan_response.raise_for_status() # Throws error for all codes >400
            scan_results={}
            if url_scan_response.status_code==200:
                
                vt_json=url_scan_response.json()
                vt_data=vt_json.get("data",{})
                vt_attributes=vt_data.get("attributes",{})
                
                vt_dict={
                    "Domain":vt_data.get("id",0),
                    "Owner":vt_attributes.get("registrar",""),
                    "Stats":vt_attributes.get("last_analysis_stats",{}),
                    "Reputation":vt_attributes.get("reputation",0)
                }
            #logger.info(vt_response.text)
            logger.debug("URL scan response start ",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return vt_dict
        except ValueError as e:
            logger.error(e)
            print(f"API Key not found:{e}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None
        except Exception as e:
            if e.response.status_code==429:
                waittime=2**retries
                time.sleep(waittime)
                if retries==maxretries-1:
                    logger.error(f"Max retries reached for the url: {domain}",extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
                continue
            logger.error(e,extra={
                        'request_id':g.request_id,
                        'user_id':g.user_id
                    })    
            return None

if __name__=="__main__":
   #vt_url_response("http://8.148.5.67/02.08.2022.exe")
   vt_domain_response("bach.walnutsteg.ru")
   """ scan_response=url_scan_response("http://8.148.5.67/02.08.2022.exe") 
   haus_response= url_haus_response("http://8.148.5.67/02.08.2022.exe")
   print(scan_response)
   print(haus_response)"""