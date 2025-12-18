import os
import sys
sys.path.append(os.getcwd())
from src.middleware.redis_cache import RedisCache

if __name__=="__main__":
    cache=RedisCache()
    #cache.set_ti("A123","TEst TI")
    #cache.set_ai("A123","TEst TI")
    print(cache.get_ai("193.32.162.157"))
    #print(cache.get_ti("A123"))