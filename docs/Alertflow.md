New Alert -> HTTP Post -> Analyze/batch  -> TI Cache Load-> AI Cache Load - >TI Cache Prune -> Alert Queue -> TI Cache Check - > TI Lookup/ API Request ->AI Cache Check-> AI Lookup/Ai Generate-> write TI Cache-> Write AI cache ->Consolidate and summarize

1. flask_test.py receives POST /analyze
   └─> What happens first?
        - Flask Analyze api receives the data as an input
   └─> Where does it call next?
        - It passes it on to test_function in batch processor class

2. batch_processor.py → test_function()
   └─> What does this do?
        - Loads TI and AI cache
        - Prunes TI and AI cache
        - Calls Alert queue to sort alerts based on priority
        - Processes the alerts via batch using ThreatPoolExecutor
   └─> Why ThreadPoolExecutor?
        - Processes alert batch in batches of 3 (max workers=3)
        - Calls the Process single alert function
   └─> What's happening in parallel?
        - All alerts are processed in batch of 3. these alerts are executed in parallel. 
        - Process single alert class is called
        - creates a local copy of the cache.
        - calls the classifyalert function

3. day1_alertclassifier.py → classify_alert()
   └─> Cache check happens when?
        - first thing that is checked is whether the alert is present in cache
   └─> Where does TI enrichment happen?
        - if there is no cache present for the alert Ip lookup function is called and TI enrichment happens
   └─> Where does AI call happen?
        - IF there is no cache present for the alert in ai cache the content generate function is called and an API call to Gemini is made with alert detials

4. day2_threatintel.py → ip_lookup()
   └─> Which API is called first?
        - AbuseIPDB is called first
   └─> What if one fails?
        - Exception is noted for the failed API call and the other API call is processed
   └─> How is data returned?
        - Data is returned in the form of a dictionary

5. Back to flask_test.py → jsonify(response)
   └─> What format is returned?
        - dictionraies are returned in the form of a dictionary
   └─> What happened to the datetime objects?
        - Date time objects are formatted using dt.strftime("%Y-%m-%d %H:%M:%S")