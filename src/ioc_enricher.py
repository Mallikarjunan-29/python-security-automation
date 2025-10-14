import os
import requests
import pandas
import logging
import ipaddress
import time
from dotenv import load_dotenv
log_timestamp= time.strftime("%Y-%m-%d")
base_path=os.getcwd()
log_path=os.path.join(base_path,"logs")
os.makedirs(log_path,exist_ok=True)
file_name=f"log_{log_timestamp}"
file_path=os.path.join(log_path,file_name)
logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(file_path),
                logging.StreamHandler()
            ]
        )
logger=logging.getLogger(__name__)
class IOCEnricher:    
    def __init__(self):
        load_dotenv()        
        logger.info("Initializing enrichment")
        self.abuse_url="https://api.abuseipdb.com/api/v2/check"
        self.abuse_api_key=os.getenv("ABUSEIPDB")
        #self.abuse_api_key="test"
        if not self.abuse_api_key:
            raise ValueError("API key not found. Add AbuseIP API key to environment file")
        self.abuse_headers={
            "Accept":"application/json",
            "Key":self.abuse_api_key
        }
        self.abuse_params={           
        }
        
    def calculate_threat_score(self,abuse_score:int):
        if abuse_score >=75 :
            return ("CRITICAL","BLOCK")
        elif abuse_score>=50:
            return("HIGH","INVESTIGATE")
        elif abuse_score>=25:
            return("MEDIUM","MONITOR")
        else:
            return("LOW","ALLOW")
    
    def check_ip(self,ipAddress:str,max_retries:int =3) -> dict:
        logger.info(f"Checking the IP reputation for {ipAddress}")
        for retries in range(max_retries):
            try:
                self.abuse_params={
                    "ipAddress":ipAddress,
                    "maxAgeInDays":90
                }
                logger.info(f"Making API call for the ip {ipAddress}")
                response=requests.get(self.abuse_url,headers=self.abuse_headers,params=self.abuse_params,timeout=10)
                response.raise_for_status()
                if response.status_code==200:
                    response_json=  response.json()
                    abuse_score=response_json['data']['abuseConfidenceScore']
                    threat_category=self.calculate_threat_score(abuse_score)
                    abuse_response={
                        "ip_address":response_json['data']['ipAddress'],
                        "threat_score":response_json['data']['abuseConfidenceScore'],
                        "threat_level":threat_category[0],
                        "recommendation":threat_category[1],
                        "country":response_json['data']['countryCode'],
                        "total_reports":response_json['data']['totalReports']
                    }
                    return abuse_response
                else:
                    return None
            except requests.exceptions.HTTPError as e:
                status=e.response.status_code
                if status == 429:
                     wait_time=2**retries
                     time.sleep(wait_time)
                     if retries==max_retries-1:
                         logger.info(f"Max retries reach for the ip {ipAddress}")
                     continue
                else:
                    if len(e.response.json())>0:
                        try:
                            error_detail=e.response.json()['errors'][0]['detail']
                            logger.error(error_detail)
                        except Exception as e:
                            logger.error(str(e))
                    else:
                        logger.error(e)
                    return None
            except requests.exceptions.Timeout as e:
                logger.error(e)
                return None            
            except Exception as e:
                logger.error(e)
                return None
        return None


    def enrich_csv(self,filepath:str):
        logger.info("Enriching IOCs from CSV")
        try:                
            data=pandas.read_csv(filepath,skip_blank_lines=True)
            ioc_results=[]
            if len(data)>0 and 'ip' in data.columns:
                for ips in data['ip']:
                    try:
                        ipaddress.ip_address(ips)
                        result={}
                        result = self.check_ip(ips)
                        if result:
                            ioc_results.append(result)
                            time.sleep(1)
                            logger.info(f"{len(ioc_results)}/{len(data)} IPs processed successfully")
                        else:
                            print(f"InvalidIP {ips}")
                            logger.info(f"{len(ioc_results)+1}/{len(data)} IPs processed successfully")
                    except ValueError as e:
                        logger.error(e)
                        continue
                print(ioc_results)
            if len(ioc_results)>0:
                df= pandas.DataFrame(ioc_results)
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                output_path=os.path.join(base_path,"output")
                os.makedirs(output_path,exist_ok=True)
                file_name=f"IOC_Enriched_{timestamp}"
                df.to_csv(os.path.join(output_path,file_name),index=False)
            else:
                print("No data")
        except FileNotFoundError as e:
            logger.error(e)
        except Exception as e:
            logger.error(e)
            




        
            
        


    
    

