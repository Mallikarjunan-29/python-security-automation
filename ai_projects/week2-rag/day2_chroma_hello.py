"""
Mini-Challenge 2.2: ChromaDB Hello World

PRE-CODING QUESTIONS (Answer these first):
What command installs ChromaDB?
 - pip install chromadb

What's the import statement for ChromaDB?
import chromadb

What's the difference between Client() and PersistentClient()?
- PersistentClient()
    - The client stores data clocally at the path specified by the user
    - path - parameter must be a local path on the machine where Chroma is running. If the path does 
    not exist, it will be created. The path can be relative or absolute. If the path is not specified, the default is ./chroma in the current working directory.
    - settings - Chroma settings object.
    - tenant - the tenant to use. Default is default_tenant.
    - database - the database to use. Default is default_database.
    - can be implement in this format chromadb.PersistentClient(
        path="test",
        settings=Settings(),
        tenent=DEFAULT_TENENT,
        database=DEFAULT_DATABASE
    )
- Client()
    - The client stores data in RAM - in memory
    - I suppose it is now called EphemeralClient
    - Useful for fast prototuping and testing
    - can be used in this format chromadb.EphemeralClient(
        settings=Settings(),
        tenent=DEFAULT_TENENT,
        database=DEFAULT_DATABASE
    )

Which one should I use for testing? Why?
 - For testing EphemeralClient will do as it is fast and support prototyping.

Architecture Questions:
5. What's the relationship: Client → Collection → Documents?
 - Client - > Takes the query to the query engine
 - Collection - > Combination of documents , embeddings and meta. Crux of VectorDB which holds actual data
6. Can one client have multiple collections?
 - Yes
7. Can one collection have multiple document types?
 - yes
8. Where does ChromaDB store data with PersistentClient?
 - IT stores data in the path specified during initialization. path parameter
THEN write the code below:
"""

import chromadb
from chromadb.config import Settings, DEFAULT_DATABASE,DEFAULT_TENANT
import time
import os
import sys
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)
try:
        
    """Q9: How do I create a ChromaDB client?"""
    client=chromadb.EphemeralClient(
        settings=Settings(),
        tenant=DEFAULT_TENANT,
        database=DEFAULT_DATABASE
    )

    """Q10: How do I verify the client is working?"""
    if client.heartbeat(): # To check if the server is alive. Returns int
        """Q11: What does client.heartbeat() do?"""
        print(f"Client is alive since {client.heartbeat()}")

    #Create a collection named security_docs
    """Q12: How do I create a collection called "security_docs"?"""
    collection=client.get_or_create_collection("security_docs") # creates the collection with the specified name or gets it if it is available
    print(f"Verifying collection name: {collection.name}") # Verify the collection name by printing it

    """Q13: What happens if I create the same collection twice?
    the get_or_create_collection method handles it accordingly
    Q14: How do I get an existing collection vs create new?
    the get_or_Create_collection method handles both.
    """

    collection=client.get_collection('security_docs')
    print(f"Verifying get collection name: {collection.name}") # Verify the collection name by printing it

    """Q15: What 3 things are required to add a document?"""

    """Adding document strings to a collection
    - The method to add document strings to collection is .add()
    - The parameters to add are as follows
        - documents=["Phishing email","Suspicious outbound conection","malware download"]
        - ids=["doc1","doc2","doc3"]
        - metadatas=[
        {'type':'alert,
        'serverity':'medium',
        'category':'phishing'},
        {
        'type':'alert,
        'serverity':'medium',
        'category':'c2c'
        },
        {
        'type':'alert,
        'serverity':'critical',
        'category':'malware'
        }]
    """
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
            "severity":"medium",
            "category":"phishing"
        },
        {
            "type":"alert",
            "severity":"medium",
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

    batch_Start=time.time()
    collection.add(ids=ids,documents=documents,metadatas=metadatas)
    batch_end=time.time()-batch_Start
    print(f"Count in the collection: {collection.count()}")
    """Q16: What data types does documents parameter accept?
    -list of string
    Q17: What data types does ids parameter accept?
    - lsit of string
    Q18: What happens if I use duplicate IDs?
    -  Expected IDs to be unique, found duplicates of: doc4 in add """

    doc_collection= collection.get()
    print(doc_collection.keys())
    """Q19: How do I check how many documents are in a collection?"""
    print(f"Number of documents in the collection: {len(doc_collection["documents"])}")

    """Q20: How do I retrieve all documents?"""
    print("Documents in the list:")
    print("="*50)
    print("\n".join(doc_collection['documents']))

    """Q21: How do I get a specific document by ID?"""
    print(collection.get(ids="doc1"))
    """
    Q22: Can I add 5 documents in one .add() call?
    - Yes it can be done
    Q23: Can I add documents one at a time in a loop? 
    - yes it can be done
    Q24: Which approach is faster? Why?
    batch time is faster as can be seen from the below print statement, as all data is added in one initialization and the method is called once.
    loop calls the method as many number of times as there are items in the list
    Q25. Where are my documents stored on disk?
    for EphemeralClient it is stored in RAM
    for PersistentClient it is stored in path variable
    """
    collection_loop=client.get_or_create_collection('security_docs_loop')
    list_range=len(documents)
    loop_start=time.time()
    for items in range(list_range):
        collection_loop.add(
            ids=ids[items],
            documents=documents[items],
            metadatas=metadatas[items]
        )
    loop_end=time.time()-loop_start
    print(f"Single Batch time: {batch_end}")
    print(f"Loop time: {loop_end}")

    """Questions to answer in comments:

    Q28: What happens if I add an empty string as document?
    - it still considers it as string and gets added
    Q29: What happens if I use the same ID twice?
    - internal error
    Q30: What happens if I forget to provide IDs
    - positional arguement ids missing error
    """
    collection.add(
        documents=[""],
        ids=['empty-test'],
        metadatas=[{
            "type":"alert",
            "severity":"medium",
            "category":"c2c"
        }]
    )
    print("\n" + "="*60)
    print("EDGE CASE TESTING - SYSTEMATIC APPROACH")
    print("="*60)

    # Create a fresh collection for edge case testing
    edge_collection = client.get_or_create_collection("edge_case_tests")

    # ============================================
    # TEST 1: Empty String Document
    # ============================================
    print("\n[TEST 1] Adding empty string as document:")
    try:
        edge_collection.add(
            documents=[""],
            ids=["empty_test"],
            metadatas=[{"type": "empty_test"}]
        )
        print("✓ Empty string ACCEPTED")
        
        # Verify it was actually added
        result = edge_collection.get(ids=["empty_test"])
        print(f"  Retrieved: '{result['documents'][0]}'")
        print(f"  Length: {len(result['documents'][0])} characters")
        
    except Exception as e:
        print(f"✗ Empty string REJECTED")
        print(f"  Error: {e}")

    # ============================================
    # TEST 2: Duplicate IDs (Upsert Behavior)
    # ============================================
    print("\n[TEST 2] Using same ID twice:")
    try:
        # First add
        edge_collection.add(
            documents=["First version of document"],
            ids=["duplicate_test"],
            metadatas=[{"version": "1"}]
        )
        print("✓ First add successful")
        
        # Check what's stored
        result1 = edge_collection.get(ids=["duplicate_test"])
        print(f"  After 1st add: '{result1['documents'][0][:30]}...'")
        print(f"  Metadata: {result1['metadatas'][0]}")
        
        # Second add with SAME ID
        edge_collection.add(
            documents=["Second version - completely different text"],
            ids=["duplicate_test"],
            metadatas=[{"version": "2"}]
        )
        print("✓ Second add successful (no error thrown)")
        
        # Check what's stored NOW
        result2 = edge_collection.get(ids=["duplicate_test"])
        print(f"  After 2nd add: '{result2['documents'][0][:30]}...'")
        print(f"  Metadata: {result2['metadatas'][0]}")
        
        # Analysis
        if result2['documents'][0] == "Second version - completely different text":
            print("  ⚠️  BEHAVIOR: Duplicate ID OVERWRITES (upsert)")
        else:
            print("  ⚠️  BEHAVIOR: Duplicate ID IGNORED")
            
    except Exception as e:
        print(f"✗ Duplicate ID caused error")
        print(f"  Error: {e}")

    # ============================================
    # TEST 3: Missing IDs Parameter
    # ============================================
    print("\n[TEST 3] Adding document without IDs:")
    try:
        edge_collection.add(
            documents=["Document without ID provided"]
            # No ids parameter at all
        )
        print("✓ Add succeeded without IDs")
        
        # Try to get all docs to see if it was added
        all_docs = edge_collection.get()
        print(f"  Total docs in collection: {len(all_docs['ids'])}")
        print(f"  Last ID: {all_docs['ids'][-1]}")
        
    except TypeError as e:
        print(f"✗ TypeError (expected - missing required parameter)")
        print(f"  Error: {e}")
    except Exception as e:
        print(f"✗ Other error")
        print(f"  Error: {e}")

    # ============================================
    # TEST 4: Wrong Data Types
    # ============================================
    print("\n[TEST 4] Passing wrong data types:")

    # Test 4a: String instead of list for documents
    print("  4a. documents as string (not list):")
    try:
        edge_collection.add(
            documents="This is a string not a list",
            ids=["string_test"]
        )
        print("    ✓ Accepted string")
    except Exception as e:
        print(f"    ✗ Rejected: {type(e).__name__}")

    # Test 4b: Dict instead of list for metadata
    print("  4b. metadatas as dict (not list):")
    try:
        edge_collection.add(
            documents=["Test doc"],
            ids=["dict_test"],
            metadatas={"type": "test"}  # Wrong: should be [{"type": "test"}]
        )
        print("    ✓ Accepted dict")
    except Exception as e:
        print(f"    ✗ Rejected: {type(e).__name__}")

    print("\n" + "="*60)
    print("EDGE CASE TESTING COMPLETE")
    print("="*60)
    print("\n" + "="*60)
    print("DEEP DIVE: Understanding Duplicate ID Behavior")
    print("="*60)

    # Create fresh collection
    test_dup = client.get_or_create_collection("duplicate_investigation")

    # Add first document
    test_dup.add(
        ids=["test_id"],
        documents=["Version 1: Original document"],
        metadatas=[{"version": 1, "timestamp": "2024-01-01"}]
    )

    print("After 1st add:")
    result1 = test_dup.get(ids=["test_id"])
    print(f"  Document: {result1['documents'][0]}")
    print(f"  Metadata: {result1['metadatas'][0]}")
    print(f"  Total count: {test_dup.count()}")

    # Try to add with SAME ID but DIFFERENT content
    test_dup.add(
        ids=["test_id"],
        documents=["Version 2: Completely new text here"],
        metadatas=[{"version": 2, "timestamp": "2024-01-02"}]
    )

    print("\nAfter 2nd add (same ID, different content):")
    result2 = test_dup.get(ids=["test_id"])
    print(f"  Document: {result2['documents'][0]}")
    print(f"  Metadata: {result2['metadatas'][0]}")
    print(f"  Total count: {test_dup.count()}")

    # Analysis
    if result2['documents'][0] == "Version 2: Completely new text here":
        print("\n✓ Behavior: UPSERT (overwrites)")
    elif result2['documents'][0] == "Version 1: Original document":
        print("\n✓ Behavior: IGNORE DUPLICATES (keeps first)")
    else:
        print("\n⚠️  Unexpected behavior!")
    # ================================================================
    # TESTING PERSISNTENT CLIENT
    # ================================================================
    base_path=os.getcwd()
    db_path=os.path.join(base_path,"db")
    os.makedirs(db_path,exist_ok=True)
    persistent_client=chromadb.PersistentClient(
        path=db_path,
        settings=Settings(),
        tenant=DEFAULT_TENANT,
        database=DEFAULT_DATABASE
    )
    persistent_collection=persistent_client.get_or_create_collection("security_docs")
    persistent_collection.add(
        documents=documents,
        ids=ids,
        metadatas=metadatas
    )
    print(persistent_collection.name)
except Exception as e:
    logger.error(e)
