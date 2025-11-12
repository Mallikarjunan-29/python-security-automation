"""
1. How does semantic search differ from keyword search?
 - Semantic search is more of a meaning based search and not exact keyword match. In semantic search results are those which are closely related to the meaning of the query
2. Can I search for text that doesn't appear in any document?
 - yes. As long as the context is available in the document it will still be returned. For instance I save a document as brute force, when i search for multiple login failures it will return the value based on context
3. How does ChromaDB find "similar" documents?
 - Query is converted to embeddings and similarity measures are used to arrive at the result
4. What does `n_results=5` do?
 - outputs 5 results
5. What happens if I ask for 10 results but only have 5 docs?
 - still outputs 5 results
6. Can I get ALL documents with `.query()`?
 - by default the results returned is 10
7. What does `distance=0.5` mean?
 - 0.5 is the L2 distance from the search term. Lower the number higher the similarity
8. Is distance=0.1 more similar than distance=0.9?
 - 0.1 is more similar than 0.9
9. What's the range? (0 to what?)
 - 0 to infinity
10. Can I filter without searching? (get all high severity)
 - get method instead of query
11. How do I combine conditions? (AND, OR)
 - by using where clause in the query method
12. Can I filter on fields that don't exist in some docs?
 - chromadb doesnt allow such search.

Mini-Challenge 2.3: Semantic Search

Goals:
1. Search by meaning (not exact keywords)
2. Filter by metadata
3. Understand similarity scores
4. Compare search vs get
"""
import chromadb
import os
import sys
from chromadb.config import Settings,DEFAULT_DATABASE,DEFAULT_TENANT
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)
try:
    base_path=os.getcwd()
    db_path=os.path.join("db")
    os.makedirs(db_path,exist_ok=True)
    logger.debug("Creating Persistent Client")
    persistent_client=chromadb.PersistentClient(
        path=db_path,
        settings=Settings(),
        tenant=DEFAULT_TENANT,
        database=DEFAULT_DATABASE,
    )
    
    documents=[
        "Phishing email with suspicious attachment",
        "Failed login attempts from an IP",
        "Malware detected in file download",
        "Unusual network traffic to malicious domain",
        "Privilege escalation attempt on server"
    ]
    ids=[
        "doc1",
        "doc2",
        "doc3",
        "doc4",
        "doc5",
    ]
    metadatas=[
        {
            "type":"alert",
            "severity":"high",
            "category":"phishing"
        },
        {
            "type":"alert",
            "severity":"high",
            "category":"brute force"
        },
        {
            "type":"alert",
            "severity":"medium",
            "category":"malware"
        },
        {
            "type":"alert",
            "severity":"medium",
            "category":"c2c"
        },
        {
            "type":"alert",
            "severity":"medium",
            "category":"privilege escalation"
        }
    ]

   
    test_queries = [
    "email attack",           # Should find phishing doc
    "password attack",        # Should find brute force doc
    "virus download",         # Should find malware doc
    "network traffic",        # Should find C2C doc
    "elevation of privileges" # Should find priv esc doc
    ]

    persistent_collection= persistent_client.get_or_create_collection("security_docs")
    persistent_collection.add(ids=ids,
        documents=documents,
        metadatas=metadatas)
    #=========================================================
    #TESTING THE QUERY METHOD WITH JUST TEXT
    #=========================================================
    print("="*60)
    print("#TESTING THE QUERY METHOD WITH JUST TEXT")
    print("="*60)
    for queries in test_queries:
        results=persistent_collection.query(
            query_texts=[queries],
            n_results=2
        )
        print(f"Results for the query: {queries}")
        print("-"*60)
        print(results)
        print("-"*60)
    #=========================================================
    #TESTING THE QUERY METHOD WITH TEXT AND METADATA
    #=========================================================
    print("="*60)
    print("TESTING THE QUERY METHOD WITH TEXT AND METADATA")
    print("="*60)
    for queries in test_queries:
        results=persistent_collection.query(
            query_texts=[queries],
            n_results=2,
            where={"severity":"high"}
        )
        print(f"Results for the query with meta filter: {queries}")
        print("-"*60)
        print(results)
        print("-"*60)
    
    #=========================================================
    #TESTING THE QUERY METHOD WITH TEXT AND METADATA WITH TWO CONDITIONS
    #=========================================================
    print("="*60)
    print("TESTING THE QUERY METHOD WITH TEXT AND METADATA WITH TWO CONDITIONS")
    print("="*60)
    for queries in test_queries:
        results=persistent_collection.query(
            query_texts=[queries],
            n_results=2,
            where={
                "$and": [
                    {"severity":"high"},
                    {"category":"phishing"}
                ]
                }
        )
        print(f"Results for the query with meta and condition filter: {queries}")
        print("-"*60)
        print(results)
        print("-"*60)
    #=========================================================
    #TESTING THE QUERY METHOD WITH TEXT AND METADATA WITH OR CONDITION
    #=========================================================
    print("="*60)
    print("TESTING THE QUERY METHOD WITH TEXT AND METADATA WITH OR CONDITION")
    print("="*60)
    results=persistent_collection.query(
        query_texts=['security'],
        n_results=2,
        where={
            "$or": [
                {"severity":"high"},
                {"category":"malware"}
            ]
            }
    )
    print(f"Results for the query for or condition")
    print("-"*60)
    print(results)
    print("-"*60)
    
    #=========================================================
    #TESTING THE QUERY METHOD WITH CLOSER DISTANCE OUTPUT
    #=========================================================
    print("="*60)
    print("TESTING THE QUERY METHOD WITH CLOSER DISTANCE OUTPUT")
    print("="*60)
    results=persistent_collection.query(
        query_texts=['phishing'],
        n_results=2,
    )
    print(f"Results for the query for closer distance output")
    print("-"*60)
    result=[]
    for distances, documents in zip(results['distances'][0],results['documents'][0]):
        if distances<1.0:
            result.append(documents)
    print(result)
    #=========================================================
    #TESTING THE QUERY AND GET DIFFERENCE
    #=========================================================
    print("="*60)
    print("#TESTING THE QUERY AND GET DIFFERENCE")
    print("="*60)
    print("\n")
    
    query_result=persistent_collection.query(
        query_texts="phishing"
    )
    get_result=persistent_collection.get(ids=['doc1'])

    print("Querying result")
    print("-"*60)
    print(query_result)
    print("-"*60)
    print("Get result")
    print("-"*60)
    print(get_result)
    print("-"*60)    
    
    logger.debug("Query end")
except Exception as e:
    logger.error(e)




