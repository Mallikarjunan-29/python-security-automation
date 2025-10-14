import os
import requests
import pandas
import logging
import ipaddress
import time
from datetime import datetime
from dotenv import load_dotenv
from src import constants as c
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
logging.getLogger().setLevel(logging.DEBUG)
logger=logging.getLogger(__name__)
class IOCEnricher:    
    def __init__(self):
        load_dotenv()        
        logger.debug("Initializing enrichment")

        ##AbuseIPDB parameters
        self.abuse_url="https://api.abuseipdb.com/api/v2/check"
        self.abuse_api_key=os.getenv("ABUSEIPDB")
        #self.abuse_api_key="test"
        if not self.abuse_api_key:
            raise ValueError("AbuseDB API key not found. Add AbuseIP API key to environment file")
        self.abuse_headers={
            "Accept":"application/json",
            "Key":self.abuse_api_key
        }
        self.abuse_params={}

        #Virus total definitions
        self.vt_api_key=os.getenv("VTKEY")
        if not self.vt_api_key:
            raise ValueError("Virustotal key is not found. Add the key in environment file")
        self.vt_headers={
            "accept":"application/json",
            "x-apikey":self.vt_api_key
        }
        self.vt_params={}      
        ## VT parameters
        self.vt_url="https://www.virustotal.com/api/v3/ip_addresses/{}"

    def calculate_threat_score(self,abuse_score:int):
        if abuse_score >=c.THREAT_CRITICAL_SCORE :
            return ("CRITICAL","BLOCK")
        elif abuse_score>=c.THREAT_HIGH_SCORE:
            return("HIGH","INVESTIGATE")
        elif abuse_score>=c.THREAT_MEDIUM_SCORE:
            return("MEDIUM","MONITOR")
        else:
            return("LOW","ALLOW")
    #Function for Checking AbuseIP DB
    def check_ip_in_AbuseDB(self,ipAddress:str,max_retries:int =3) -> dict:
        logger.debug(f"Checking the AbuseIPDB reputation for {ipAddress}")
        for retries in range(max_retries):
            try:
                # AbuseIPDB API call
                self.abuse_params={
                    "ipAddress":ipAddress,
                    "maxAgeInDays":90
                }
                logger.debug(f"Making AbuseIPDB API call for the ip {ipAddress}")
                abuse_response=requests.get(self.abuse_url,headers=self.abuse_headers,params=self.abuse_params,timeout=10)
                abuse_response.raise_for_status()
                if abuse_response.status_code==200:
                    abuse_response_json=  abuse_response.json()
                    abuse_score=abuse_response_json['data']['abuseConfidenceScore']
                    threat_category=self.calculate_threat_score(abuse_score)
                    abuse_response_dct={
                        "abuse_ip_address":abuse_response_json['data']['ipAddress'],
                        "abuse_threat_score":abuse_response_json['data']['abuseConfidenceScore'],
                        "abuse_threat_level":threat_category[0],
                        "abuse_recommendation":threat_category[1],
                        "abuse_country":abuse_response_json['data']['countryCode'],
                        "abuse_total_reports":abuse_response_json['data']['totalReports'],
                        "source":"AbuseIPDB"
                    }
                    return abuse_response_dct
                else:
                    return None
            except requests.exceptions.HTTPError as e:
                status=e.response.status_code
                if status == 429:
                     wait_time=2**retries
                     time.sleep(wait_time)
                     if retries==max_retries-1:
                         logger.debug(f"Max retries reach for the ip {ipAddress} in AbuseIPDB")
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
        logger.debug("Enriching IOCs from CSV")
        try:                
            data=pandas.read_csv(filepath,skip_blank_lines=True)
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"File not found {filepath}")
            if 'ip' not in data.columns:
                raise ValueError(f"File must contain IP address column")
            ioc_results=[]
            total_ips=len(data['ip'])
            successful=0
            failed=0
            invalid=0   
            print(f"\n{'='*80}")
            print("MULTI SOURCE ENRICHMENT")
            print(f"\n{'='*80}")
            print(f"Total IPs = {total_ips}\n")
            for idx,ips in enumerate(data['ip'],1):
                print(f"[{idx}/{total_ips}] Processing {ips} ....")
                combined_result=self.enrich_multi_source_ip(ips)
                #print(combined_result)
                if combined_result:
                    ioc_results.append(combined_result)
                    successful+=1
                    print(f"Score:{combined_result['combined_score']}, Confidence:{combined_result['confidence']}")
                else:
                    print(f"InvalidIP {ips}")
                    failed+=1
                time.sleep(1)
                #print(ioc_results)
            print(f"\n{'='*80}")
            print("SUMMARY")
            print(f"Total IPs: {total_ips}")
            print(f"Successful IPs: {successful}")
            print(f"Failed IPs: {failed}")
            print(f"\n{'='*80}")
            if len(ioc_results)>0:
                df= pandas.DataFrame(ioc_results)
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                output_path=os.path.join(base_path,"output")
                os.makedirs(output_path,exist_ok=True)
                file_name=f"IOC_Enriched_{timestamp}"
                df.to_csv(os.path.join(output_path,file_name),index=False)
                print(f"Saved to path {output_path}/{file_name}")
            else:
                print("No data")
        except FileNotFoundError as e:
            logger.error(e)
        except Exception as e:
            logger.error(e)
            
    def check_ip_in_VT(self,ipAddress:str, max_retries:int =3):
        logger.debug(f"Checking reputation for {ipAddress} in VirusTotal")
        for retries in range(max_retries):
            try:
                live_vt_url=self.vt_url.format(ipAddress)   
                logger.debug(f"Making Virus Total API call for {ipAddress}")
                vt_response=requests.get(live_vt_url,headers=self.vt_headers,timeout=10)
                vt_response.raise_for_status()
                if vt_response.status_code==200:
                    response_json=vt_response.json()
                    if response_json:
                        data=response_json.get('data',{})
                        attributes=data.get('attributes',{})
                        ip=data.get('id',{})
                        stats=attributes.get('last_analysis_stats',{})
                        malicious=stats.get('malicious',0)
                        suspicious=stats.get('suspicious',0)
                        harmless=stats.get('harmless',0)
                        undetected=stats.get('undetected',0)
                        last_analysis_date=datetime.fromtimestamp(data.get('last_analysis_date',0)).strftime("%Y-%m-%d %H:%M:%S")
                        total_score=malicious+suspicious+harmless+undetected
                        if total_score>0:
                            threat_score=round(((malicious+suspicious)/total_score)*100)
                        else:
                            threat_score=0
                        threat_category=self.calculate_threat_score(threat_score)
                        if len(threat_category)>0:
                            threat_level=threat_category[0]
                            recommendation=threat_category[1]
                        vt_result_dct={
                            "vt_ip":ip,
                            "vt_malicious_votes":malicious,
                            "vt_suspicious_votes":suspicious,
                            "vt_harmless_votes":harmless,
                            "vt_undetected_votes":undetected,
                            "vt_total_votes":total_score,
                            "vt_threat_score":threat_score,
                            "vt_threat_level":threat_level,
                            "vt_recommendation":recommendation,
                            "vt_last_analysis_date":last_analysis_date,
                            "vt_source":"VirusTotal"
                        }
                        return vt_result_dct
                    else:
                        return None
                else:
                    return None
            except requests.exceptions.HTTPError as e:
                status_code=e.response.status_code
                if status_code ==429:
                    time.sleep(2*retries)
                    if retries==max_retries-1:
                        print(f"Max retries reached for the ip {ip}")
                        logger.error(str(e))
                        return None
            except requests.exceptions.Timeout as e:
                logger.error(str(e))
            except Exception as e:
                logger.error(str(e)) 
        return None

    def multi_source_weightage(self,abuse_score,vt_score):
        logger.debug("Calcualting the multi source score")
        absolute_score = round((0.6*abuse_score+0.4*vt_score))
        score_diff=abs(vt_score-abuse_score)
        result={}
        if absolute_score<=20:
            if score_diff<=20:
                result={
                    "confidence":"HIGH",
                    "threat_level":"LOW",
                    "recommendation":"MONITOR"
                }
                return result
            elif score_diff<=50:
                result={
                    "confidence":"MEDIUM",
                    "threat_level":"LOW",
                    "recommendation":"INVESTIGATE"
                }
                return result
            elif score_diff >50:
                result={
                    "confidence":"LOW",
                    "threat_level":"LOW",
                    "recommendation":"INVESTIGATE"
                }
                return result 
        elif absolute_score<=50:
            if score_diff<=20:
                result={
                    "confidence":"HIGH",
                    "threat_level":"MEDIUM",
                    "recommendation":"INVESTIGATE"
                }
                return result
            elif score_diff<=50:
                result={
                    "confidence":"MEDIUM",
                    "threat_level":"MEDIUM",
                    "recommendation":"INVESTIGATE"
                }
                return result
            elif score_diff >50:
                result={
                    "confidence":"LOW",
                    "threat_level":"MEDIUM",
                    "recommendation":"INVESTIGATE"
                }
                return result 
        elif absolute_score<=80:
            if score_diff<=20:
                result={
                    "confidence":"HIGH",
                    "threat_level":"HIGH",
                    "recommendation":"BLOCK"
                }
                return result
            elif score_diff<=50:
                result={
                    "confidence":"MEDIUM",
                    "threat_level":"HIGH",
                    "recommendation":"INVESTIGATE"
                }
                return result
            elif score_diff >50:
                result={
                    "confidence":"LOW",
                    "threat_level":"HIGH",
                    "recommendation":"INVESTIGATE"
                }
                return result 
        elif absolute_score>80:
            if score_diff<=20:
                result={
                    "confidence":"HIGH",
                    "threat_level":"CRITICAL",
                    "recommendation":"BLOCK"
                }
                return result
            elif score_diff<=50:
                result={
                    "confidence":"MEDIUM",
                    "threat_level":"CRITICAL",
                    "recommendation":"INVESTIGATE"
                }
                return result
            elif score_diff >50:
                result={
                    "confidence":"LOW",
                    "threat_level":"CRITICAL",
                    "recommendation":"INVESTIGATE"
                }
                return result 
    def enrich_multi_source_ip(self,ipAddress:str):
        try:
            try:
                ipaddress.ip_address(ipAddress)
            except ValueError as e:
                logger.error(str(e))
                return None
            abuse_result = self.check_ip_in_AbuseDB(ipAddress)
            vt_result=self.check_ip_in_VT(ipAddress)
            if not abuse_result and not vt_result:
                logger.warning(f"Both APIs failed for the IP {ipAddress}")
            abuse_score=abuse_result.get('abuse_threat_score',0) if abuse_result else 0
            vt_score=vt_result.get('vt_threat_score',0) if vt_result else 0
            weighted_result=self.multi_source_weightage(abuse_score,vt_score)
            combined_result=abuse_result|vt_result|weighted_result
            combined_result['ip']=ipAddress
            combined_result['timestamp']= time.strftime("%Y-%m-%d %H:%M:%S")
            combined_result['combined_score']=round(0.6*abuse_score+0.4*vt_score)
            return combined_result
            #print(combined_result)
        except Exception as e:
            logger.error(str(e))

            






                 
            
        


    
    

