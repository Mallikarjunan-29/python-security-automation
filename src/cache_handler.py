from datetime import datetime,timedelta
import json
import os
import sys
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)

class CacheHandler:
    def __init__(self):
        self.TTL=14400
        self.file_path=""

    def cache_ip(self,data):
        logger.debug(f"Caching ip {data.keys()}")
        try:
            with open (self.file_path,"w") as f:
                json.dump(data,f,indent=4)           
        except Exception as e:
            logger.error(e)

    def load_cache(self):
        try:
            with open(self.file_path,"r") as f:
             data= json.load(f)
            return data
        except Exception as e:
            logger.error(e)

    def prune_old_cache(self,cache_dump):
        logger.debug("Pruning old cache")
        try:
            listofkeys=list(cache_dump.keys())
            prunecount=0
            for keys in listofkeys:
                logger.debug(f"Checking {keys} for pruning ")
                timestamp=cache_dump[keys].get("Timestamp","")
                timediff=datetime.now()-datetime.strptime(timestamp,"%Y-%m-%d %H:%M:%S")
                if timediff>timedelta(seconds=self.TTL):
                    cache_dump.pop(keys)
                    prunecount+=1
            logger.debug(f"Pruned item count: {prunecount}")
            return cache_dump
        except Exception as e:
            logger.error(e)
            return None
        
