About Caching:

Where is the cache loaded? (which file, which function?)
    - Files:
        - ai_cache.json : AI Cache
        - cache.json : TI Cache
    - Functions:
        - load_cache function in CacheHandler class
How does cache checking work? (exact line of code)
    - TI Cache:
        -   ip_to_check=alert['source_ip']
            itemtocheck=ti_cache_data.get(ip_to_check,0)
            if not ti_cache_data:
                Load API
            elif itemtocheck==0:
                Load API
            else:
                Load from Cache
    - AI Cache:
        -   response_data= json.dumps({"alert":alert,"AbuseTI":alert_ti_cache[ip_to_check]          ['AbuseIntel'],"VTTI":alert_ti_cache[ip_to_check]['VTIntel']},sort_keys=True)
            response_key=hashlib.md5(response_data.encode()).hexdigest()
            response_to_check=ai_cache_data.get(response_key,"") if ai_cache_data else ""
            if response_to_check != "":
                if alert_ai_cache[response_key]['AI_Response']['classification']!=alert_ai_cache[response_key]['Humanoverride']:
                    Load AI API
                else:
                    Load from cache
            else:
                LoadAI API        
        
When is cache updated? (after what operation?)
    - Cache is updated after all alerts are processed and the result is summarized
What's the cache key? (how is it generated?)
    - Cache Key is the key generated as a key value for AI cache
    - It is the combination of Alert name, ti data, ai data
Why did you use JSON files instead of Redis?
    - the number of test cases is very limited and the max alerts processed is 50.
    - since it is a small cache operation, JSON files have been used instead of Redis
About Threading:

Where do you create the ThreadPoolExecutor?
    ThreadPoolExecutor is executed  in batchprocessor file in test function
How many workers did you set? Why that number?
    workers =3, to make sure rate is limited for gemini api
What happens if one thread crashes?
    if one thread crashes , exception is caught and the remaining is processed.
How do you maintain result order?
    Submit method is used in ThreatPoolExecutor which gives control over the batch
Is there a race condition? Where?
    Race condition happens while cache updation. Update TI cache. It is handled by creating a local copy of the cache and modifying data in local cache.

About API Integration:

Which API calls happen synchronously?

Where do you handle rate limits?
    Rate limits are handled in GeminiRate limiter class, and it is initiated during the gemini call
What happens if Gemini returns malformed JSON?
    Exception is caught and logged and No data message is sent back
Why did you choose Flask over FastAPI?
    Easier to deploy and light weight
What's missing from your error handling?