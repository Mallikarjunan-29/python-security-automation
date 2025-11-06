from threading import Lock
from collections import deque
import sys
import os
sys.path.append(os.getcwd())
from src.logger_config import get_logger
import time
logger= get_logger(__name__)

class GeminiRateLimiter:
    def __init__(self):
        self.max_calls=14
        self.time_window=60
        self.calls=deque()
        self.lock=Lock()
    
    def wait_if_needed(self):
        with self.lock:
            now=time.time()
        
            #Remove old calls
            if self.calls and self.calls[0]<now-self.time_window: #Remove any calls older than 60 seconds
                self.calls.popleft()
            
            #if number of calls greater than or equal to limit, in this case 14
            if len(self.calls)>=self.max_calls:
                oldest_call=self.calls[0]
                wait_time=self.time_window-(now-oldest_call)+1 #remaining time from the first call to set up time wait

                logger.debug(f"Wait time triggerd. Waiting {wait_time:.1f}s")
                time.sleep(wait_time)
                now=time.time()
                while self.calls and self.calls[0]<now-self.time_window:
                    self.calls.popleft()
            
            #Record current call
            self.calls.append(time.time())
            
            




