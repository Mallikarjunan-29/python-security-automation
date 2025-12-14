from datetime import datetime,timedelta
from flask import g
import json
import os
import sys
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)

class CacheHandler:
    def __init__(self):
        self.TTL=14400


    def write_cache(self,data,path,context):
        logger.debug(f"Caching intel",extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })    
        try:
            with open (path,"w") as f:
                json.dump(data,f,indent=4)  
                logger.debug(f"cached to {path}",extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })    
        except Exception as e:
            logger.error(str(e),extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })       

    def load_cache(self,path,context):
        try:
            with open(path,"r") as f:
             data= json.load(f)
            return data
        except Exception as e:
            logger.error(str(e),extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })    

    def prune_old_cache(self,cache_dump,context):
        logger.debug("Pruning old cache",extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })    
        try:
            listofkeys=list(cache_dump.keys())
            prunecount=0
            for keys in listofkeys:
                logger.debug(f"Checking {keys} for pruning ",extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })    
                timestamp=cache_dump[keys].get("Timestamp","")
                timediff=datetime.now()-datetime.strptime(timestamp,"%Y-%m-%d %H:%M:%S")
                if timediff>timedelta(seconds=self.TTL):
                    cache_dump.pop(keys)
                    prunecount+=1
            logger.debug(f"Pruned item count: {prunecount}",extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })    
            return cache_dump
        except Exception as e:
            logger.error(str(e),extra={
                        'request_id':context.get('request_id'),
                        'user_id':context.get('user_id')
                    })    
            return None
        
