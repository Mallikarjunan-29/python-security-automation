import re
import sys
import os
import hashlib
import json
from datetime import datetime
sys.path.append(os.getcwd())
from src.logger_config import get_logger
from src.ioc_extractor import extract_behavior
from ai_projects.week2_rag import day3_document_loader
import chromadb
from chromadb.config import Settings,DEFAULT_DATABASE,DEFAULT_TENANT
logger=get_logger(__name__)
db_path=os.path.join(os.getcwd(),"data/db")

class AI_response_handler:
    def __init__(self,collection_name):
        self.client=chromadb.PersistentClient(
            settings=Settings(),
            database=DEFAULT_DATABASE,
            tenant=DEFAULT_TENANT,
            path=db_path
        )
        self.collection=self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description":"Cached AI Alert classification"})


    def store_cache1(self,ioc,ip_response,url_response,domain_response,ai_response,token_usage,alert):
        

        malicious_ip=[
                        data.get('IP_Abuse_intel',0).get('IP',0) for data in ip_response.values()
                        if data.get('IP_Abuse_intel') and data.get('IP_Abuse_intel',0).get('AbuseConfidenceScore',0) > 50
            ]
        
        malicious_url=[
                        data.get('vt_URL_response',0).get('url',0) for data in url_response.values()
                        if data.get('vt_URL_response') and data.get('vt_URL_response',0).get('stats',0).get('malicious',0)>0
            ]
        malicious_domain=[
                        data.get('VT_domain_response',0).get('Domain',0) for data in domain_response.values()
                        if data.get('VT_domain_response') and data.get('VT_domain_response',0).get('Stats',0).get('malicious',0)>0
            ]
            
        malicious_ioc={
            "ips":malicious_ip,
            "urls":malicious_url,
            "domain":malicious_domain
        }
        if len(malicious_ip)==0 and len(malicious_url)==0 and len(malicious_domain)==0:
            all_iocs=ioc.get("ips",[])+ioc.get('urls',[])+ioc.get('domains',[])
            all_iocs=sorted(set(all_iocs))
            ioc_fp=hashlib.sha256(",".join(all_iocs).encode()).hexdigest()[:12]
            normalized_alert={
                "ioc":ioc_fp,
                "behaviour":extract_behavior(alert)
            }
        else:
            normalized_alert={
                "ioc":malicious_ioc,
                "behaviour":extract_behavior(alert)
            }
        cache_key=hashlib.md5(json.dumps(normalized_alert,sort_keys=True).encode()).hexdigest()
        cache_document={
            "classification":ai_response.get('classification','None'),
            "confidence":ai_response.get('confidence',0),
            "severity":ai_response.get('severity','Low'),
            "reasoning":ai_response.get('reasoning','None'),
            "semantic":ai_response.get('semantic','None'),
            "cache_key":cache_key,
            "token_usage":token_usage,
            "iocs":ioc,
            "threat_summary":{
                "malicious_ip_count":sum(
                    1 for data in ip_response.values()
                    if data.get('IP_Abuse_intel') and data.get('IP_Abuse_intel',0).get('AbuseConfidenceScore',0) > 50
                ),
                "malicious_url_count":sum(
                    1 for data in url_response.values()
                    if data.get('vt_URL_response') and data.get('vt_URL_response',0).get('stats',0).get('malicious',0)>0
                ),
                "malicious_domain_count":sum(
                    1 for data in domain_response.values()
                    if data.get('VT_domain_response') and data.get('VT_domain_response',0).get('Stats',0).get('malicious',0)>0
                )
            }
        }
        query_text=self.create_query_text(ioc,ip_response,url_response,domain_response,alert)
        doc_id=hashlib.md5(f"{query_text}_{datetime.now().isoformat()}".encode()).hexdigest()
        self.collection.add(
            documents=[json.dumps(cache_document)],
            ids=[doc_id],
            metadatas=[{
                "timestamp":datetime.now().isoformat(),
                "classification":ai_response['classification'],
                "confidence":ai_response['confidence']
            }]
        )
        #print(f"Stored AI response in cache (ID: {doc_id[:8]}).....")

    def create_query_text(self,ioc,ip_response,url_response,domain_response,alert):
        try:
            parts=[]
            """
            if ioc.get('ips'):
                parts.append(f"IPs:{','.join(ioc['ips'])}")
            if ioc.get('urls'):
                parts.append(f"URLs:{','.join(ioc['urls'])}")
            if ioc.get('domains'):
                parts.append(f"domains:{','.join(ioc['domains'])}")
            """
            
            malicious_ip=[
                        data.get('IP_Abuse_intel',0).get('IP',0) for data in ip_response.values()
                        if data.get('IP_Abuse_intel') and data.get('IP_Abuse_intel',0).get('AbuseConfidenceScore',0) > 50
            ]
            if malicious_ip:
                parts.append(f"malicious_ip:{','.join(malicious_ip)}")
            malicious_url=[
                        data.get('vt_URL_response',0).get('url',0) for data in url_response.values()
                        if data.get('vt_URL_response') and data.get('vt_URL_response',0).get('stats',0).get('malicious',0)>0
            ] 
            if malicious_url:
                parts.append(f"malicious_url:{','.join(malicious_url)}")
            malicious_domain=[
                        data.get('VT_domain_response',0).get('Domain',0) for data in domain_response.values()
                        if data.get('VT_domain_response') and data.get('VT_domain_response',0).get('Stats',0).get('malicious',0)>0
            ]
            if malicious_domain:
                parts.append(f"malicious_domain:{','.join(malicious_domain)}")
            #parts.append(alert)
            parts.append(f"behaviour:{extract_behavior(alert)}")
            all_iocs=ioc.get("ips",[])+ioc.get('urls',[])+ioc.get('domains',[])
            all_iocs=sorted(set(all_iocs))
            ioc_fp=hashlib.sha256(",".join(all_iocs).encode()).hexdigest()[:12]
            parts.append(f"ioc_fp:{ioc_fp}")
            return "|".join(parts)
        except Exception as e:
            logger.error(str(e))
            return None

    def search(self, query_text, number_of_results=3):
        try:
            result = self.collection.query(
            query_texts=[query_text],
            n_results=number_of_results,
            include=["metadatas", "documents", "distances"]
            )
        
        # Return full runbooks from metadata
            if result['documents']:
                for i in range(len(result['metadatas'][0])):
                # Replace summary with full runbook
                    result['documents'][0][i] = result['metadatas'][0][i]['full_runbook']
        
            return result
                
        except Exception as e:
            logger.error(f"Metadata filtering error: {e}")
                # Continue to semantic fallback
        
       

    def _log_results(self, query_text, result):
        """
        Debug logging for search results
        """
        if not result['documents'] or len(result['documents'][0]) == 0:
            logger.warning(f"❌ No results for: {query_text}")
            return
        
        print(f"\n{'='*60}")
        print(f"Query: {query_text}")
        print(f"Results: {len(result['documents'][0])}")
        print(f"{'='*60}")
        
        for i, (doc, distance, meta) in enumerate(zip(
            result['documents'][0],
            result['distances'][0],
            result['metadatas'][0]
        )):
            print(f"\n[{i+1}] Distance: {distance:.4f}")
            print(f"    Title: {meta.get('title', 'N/A')}")
            print(f"    MITRE: {meta.get('mitre_all', 'N/A')}")
            print(f"    Type: {meta.get('attack_type', 'N/A')}")
            print(f"    Severity: {meta.get('severity', 'N/A')}")
            
            # Show first 150 chars of content
            preview = doc[:150].replace('\n', ' ')
            print(f"    Preview: {preview}...")

    def search1(self,ioc,ip_response,url_response,domain_response,alert,similarity_threshold=0.8):
        logger.debug("Searching cache")
        try:

            query_text=self.create_query_text(ioc,ip_response,url_response,domain_response,alert)
            result=self.collection.query(
                query_texts=query_text,
                n_results=1,
                include=["metadatas",'documents','distances']
                
            )
            malicious_ip=[
                        data.get('IP_Abuse_intel',0).get('IP',0) for data in ip_response.values()
                        if data.get('IP_Abuse_intel') and data.get('IP_Abuse_intel',0).get('AbuseConfidenceScore',0) > 50
            ]
        
            malicious_url=[
                        data.get('vt_URL_response',0).get('url',0) for data in url_response.values()
                        if data.get('vt_URL_response') and data.get('vt_URL_response',0).get('stats',0).get('malicious',0)>0
            ]
            malicious_domain=[
                        data.get('VT_domain_response',0).get('Domain',0) for data in domain_response.values()
                        if data.get('VT_domain_response') and data.get('VT_domain_response',0).get('Stats',0).get('malicious',0)>0
            ]
            
            malicious_ioc={
            "ips":malicious_ip,
            "urls":malicious_url,
            "domain":malicious_domain
            }
            if len(malicious_ip)==0 and len(malicious_url)==0 and len(malicious_domain)==0:
                all_iocs=ioc.get("ips",[])+ioc.get('urls',[])+ioc.get('domains',[])
                all_iocs=sorted(set(all_iocs))
                ioc_fp=hashlib.sha256(",".join(all_iocs).encode()).hexdigest()[:12]
                normalized_alert={
                    "ioc":ioc_fp,
                    "behaviour":extract_behavior(alert)
                }
            else:
                normalized_alert={
                    "ioc":malicious_ioc,
                    "behaviour":extract_behavior(alert)
                }
            cache_key=hashlib.md5(json.dumps(normalized_alert,sort_keys=True).encode()).hexdigest()
            
            if result['documents'][0] :
                cached_data=json.loads(result['documents'][0][0])
                if cache_key==cached_data['cache_key']:
                    print("cache hit")
                    return{
                        "classification":cached_data['classification'],
                        "severity":cached_data['severity'],
                        "confidence":cached_data['confidence'],
                        "reasoning":cached_data['reasoning'],
                        "semantic":cached_data['semantic'],
                        "cache_key":cache_key,
                        "from_cache":True,
                        "cache_similairty":1-result['distances'][0][0]
                    },cached_data['token_usage']
            
            print("Cache miss")
            logger.debug("leaving search cache")
            return None,None
        except Exception as e:
            logger.error(str(e))

    def store_cache(self,chromadata):
        try:       
            logger.debug("Storing runbooks in chromadb")
            self.collection.add(
                documents=chromadata['documents'],
                ids=chromadata['ids'],
                metadatas=chromadata['metadatas']
            )
            logger.debug("Runbooks stored in chromadb")
        except Exception as e:
            logger.error("Error saving data to chromadb")
            
        
        
if __name__=="__main__":
    chromadata= day3_document_loader.load_all_documents(os.path.join(os.getcwd(),"data/security_docs"))
    
    