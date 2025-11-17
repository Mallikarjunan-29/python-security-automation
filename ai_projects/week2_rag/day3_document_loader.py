"""
Day 3 Document Loader

DESIGN DECISIONS:

Q1: How will you read files?
A: [os.listdir? glob? Path.glob? Why?]

Q2: How will you extract metadata from filename?
Pattern: runbook_phishing.txt
A: [Regex? String split? Why?]
    - Regex since file names can have multiple underscores
    - in Split i will have to split twice 
        - first to remove the "."
        - second to split the contents before and after the first "_"
    
Q3: What if file doesn't match pattern?
A: [Skip? Default metadata? Error? Why?]
 
Q4: Where will you store in ChromaDB?
A: [One collection? Multiple? Why?]
    All runbooks will be one collection, so when a user queries for runbooks this collection can be loaded
Q5: What will be the document ID?
A: [Filename? Hash? UUID? Why?]
    hash

Q6: What metadata will you store?
A: [List 5-7 fields based on Q4 answer]
    type : IP
    value : 185.23.23.23
    action : blocked
    duration_in_days:90
    ckc_stage:recon
    related_runbook:run book name

Q7: How will you handle errors?
A: [Try-except where? Log errors? Continue or fail?]
    try except after every logic
    log exceptions
    continue for graceful exit

Q8: How will you verify it worked?
A: [Check count? Test query? Both?]
    check count
    test query 
"""
import re
import os
import sys
import hashlib
import chromadb
from src.ioc_extractor import extract_behavior
from chromadb.config import Settings,DEFAULT_DATABASE,DEFAULT_TENANT
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)
def parse_filename(filename: str) -> dict:
    """
    Extract metadata from filename
    
    Examples:
    - runbook_phishing.txt → {"type": "runbook", "topic": "phishing"}
    - runbook_network_scanning.txt → {"type": "runbook", "topic": "network_scanning"}
    """
    metadata={}
    
    if "_" in filename:
        if "." in filename:
            metadata={
                "type":filename[:filename.index("_")],
                "topic":filename[filename.index("_")+1:filename.index(".")]
            }
        else:
            metadata={
                "type":filename[:filename.index("_")],
                "topic":filename[filename.index("_")+1:]
            }
    return metadata


def load_single_document(file_path: str) -> dict:
    """
    Load one document file
    
    Your tasks:
    1. Read file content (handle UTF-8)
    2. Extract metadata from filename
    3. Extract MITRE techniques from content (look for T1XXX pattern)
    4. Return dict with: content, metadata, mitre_techniques
    
    """
    with open(file_path,"r") as f:
        file_content=f.read() 
    return file_content



def load_all_documents1(docs_folder:str):
    try:
        """
        Load documents with enhanced metadata extraction
        """
        documents = []
        ids = []
        metadatas = []
        
        for file in os.listdir(docs_folder):
            if not file.endswith('.txt'):
                continue
            
            file_path = os.path.join(docs_folder, file)
            
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            # Extract metadata from content
            content_metadata = extract_metadata_from_content(file_content)
            
            # Add filename-based metadata
            filename_metadata = parse_filename(file)
            
            # Merge metadata
            final_metadata = {
                **content_metadata,
                'filename': file,
                'topic_from_filename': filename_metadata.get('topic', '')
            }
            
            # Generate document ID
            doc_id = hashlib.md5(file_content.encode()).hexdigest()
            
            documents.append(file_content)
            ids.append(doc_id)
            metadatas.append(final_metadata)
        
        return {
            'documents': documents,
            'ids': ids,
            'metadatas': metadatas
        }
    except Exception as e:
        return None

def index_to_chrome(document_data:dict,collection_name:str):
    try:
        inmemory_client=chromadb.EphemeralClient(
            settings=Settings(),
            database=DEFAULT_DATABASE,
            tenant=DEFAULT_TENANT
        )
        #print(inmemory_client.heartbeat())
        collection=inmemory_client.get_or_create_collection(collection_name)
        collection.add(
            ids=document_data['ids'],
            documents=document_data['documents'],
            metadatas=document_data['metadatas']
        )
        print(collection.count())
        
        queries = [
        "How to respond to phishing email?",
        "Steps for investigating brute force attack",
        "What to do when malware detected?",
        "MITRE technique for data exfiltration",
        "Past incidents related to PowerShell execution"
        ]
        final_result=[]
        
        try:
            for query in queries:
                data_mapping={}
                result_set=[]
                results=collection.query(query_texts=query)
                for distance,document,metadata,ids in zip(results['distances'][0],results['documents'][0],results['metadatas'][0],results['ids'][0]):
                    if distance<1.0:
                        result_set.append(
                            {
                                "ids":ids,
                                "documents":document,
                                "distances":distance,
                                "metadatas":metadata
                            }
                        )
                data_mapping={
                    query:result_set
                }
                final_result.append(data_mapping)
                result1={}
            for result in final_result:
                count=1
                for keys,values in result.items():
                    print("="*60)
                    print(keys)
                    print("="*60)
                    for value in values:
                        print("-"*60)
                        print(f"Document {count} of {len(values)}")
                        print("-"*60)
                        print(value['documents'])
                        print("-"*60)
                        count+=1
        except Exception as e:
            logger.error(e)
            print(f"Exception with query: {query}")
            
    except Exception as e:
        logger.error(e)
        
def load_all_documents(docs_folder: str):
    documents = []  # Summaries for embedding
    ids = []
    metadatas = []  # Includes full_runbook
    
    for file in os.listdir(docs_folder):
        if not file.endswith('.txt'):
            continue
        
        with open(os.path.join(docs_folder, file), 'r') as f:
            file_content = f.read()
        
        summary, full_content, meta = create_searchable_summary(file_content)
        
        documents.append(summary)  # Summary gets embedded
        metadatas.append(meta)     # Full runbook in metadata
        ids.append(hashlib.md5(file_content.encode()).hexdigest())
    
    return {
        'documents': documents,
        'ids': ids,
        'metadatas': metadatas
    }

def create_searchable_summary(file_content: str) -> tuple:
    """
    Returns: (summary_for_embedding, full_content, metadata)
    """
    # Extract metadata
    meta = extract_metadata_from_content(file_content)
    
    # Create concise summary (300 chars max)
    mitre_str = meta['mitre_techniques'] if meta['mitre_techniques'] else 'None'
    
    summary = f"""
Runbook: {meta['title']}
MITRE ATT&CK Techniques: {mitre_str}
Severity: {meta['severity']}
Type: {meta['attack_type']}

This runbook covers incident response procedures for {meta['attack_type']} attacks.
Primary MITRE techniques: {mitre_str}
    """.strip()
    
    # Store full content in metadata
    meta['full_runbook'] = file_content
    
    return summary, file_content, meta


def extract_metadata_from_content(file_content: str) -> dict:
    """
    Parse runbook text to extract structured metadata
    
    INPUT:
        file_content = "Title: Brute Force...\nSeverity: High\n..."
    
    OUTPUT:
        {
            'title': 'Brute Force Credential Attack',
            'severity': 'High',
            'mitre_techniques': ['T1110'],
            'attack_type': 'brute_force',
            'doc_type': 'runbook'
        }
    """
    metadata = {
        'title': '',
        'mitre_techniques': [],
        'attack_type': '',
        'severity': '',
        'doc_type': 'runbook'
    }
    
    lines = file_content.split('\n')
    
    for line in lines:
        # 1. EXTRACT TITLE
        if line.startswith('Title:'):
            # "Title: Brute Force Credential Attack" → "Brute Force Credential Attack"
            metadata['title'] = line.replace('Title:', '').strip()
        
        # 2. EXTRACT SEVERITY
        if line.startswith('Severity:'):
            # "Severity: High" → "High"
            metadata['severity'] = line.replace('Severity:', '').strip()
        
        # 3. EXTRACT MITRE TECHNIQUES
        if 'MITRE ATT&CK:' in line:
            # "MITRE ATT&CK: T1110" → ["T1110"]
            # "MITRE ATT&CK: T1078, T1021" → ["T1078", "T1021"]
            # "MITRE ATT&CK: T1110.003" → ["T1110.003", "T1110"]
            
            techniques = re.findall(r'T\d{4}(?:\.\d{3})?', line)
            
            all_techniques = []
            for tech in techniques:
                all_techniques.append(tech)
                
                # If sub-technique, also add parent
                if '.' in tech:
                    parent = tech.split('.')[0]  # T1110.003 → T1110
                    if parent not in all_techniques:
                        all_techniques.append(parent)
            mitre_techniques=",".join(all_techniques)
            metadata['mitre_techniques'] = mitre_techniques
    
    # 4. DERIVE ATTACK TYPE FROM TITLE
    title_lower = metadata['title'].lower()
    
    metadata['attack_type']=extract_behavior(title_lower)
    
    
    return metadata

            
if __name__=="__main__":
        
    """
    # ====================================================#
    # TESTING PARSING WITH ACTUAL FILE NAME
    # ====================================================#
    print("-"*60)
    print("TESTING PARSING WITH ACTUAL FILE NAME")
    print("-"*60)
    meta = parse_filename("run_est1.txt")
    print(meta)

    # ====================================================#
    # TESTING PARSING WITH ACTUAL FILE NAME WITH TWO "_"
    # ====================================================#
    print("-"*60)
    print("TESTING PARSING WITH ACTUAL FILE NAME WITH TWO '_'")
    print("-"*60)
    meta = parse_filename("run_EST_est1.txt")
    print(meta)

    # ====================================================#
    # TESTING PARSING WITH ACTUAL FILE NAME WITH NO "_"
    # ====================================================#
    print("-"*60)
    print("TESTING PARSING WITH ACTUAL FILE NAME WITH NO '_'")
    print("-"*60)
    meta = parse_filename("run.txt")
    if len(meta.keys())>0:
        print(meta)
    else:
        print("Invalid file name")

    # ====================================================#
    # TESTING PARSING WITH ACTUAL FILE NAME WITH NO EXTENSION
    # ====================================================#
    print("-"*60)
    print("TESTING PARSING WITH ACTUAL FILE NAME WITH NO EXTENSION")
    print("-"*60)
    meta = parse_filename("run_run")
    if len(meta.keys())>0:
        print(meta)
    else:
        print("Invalid file name")

    filename="runbook_bruteforce.txt"
    folder_path=os.path.join(os.getcwd(),"data/security_docs")
    file_path=os.path.join(folder_path,filename)
    metadata=parse_filename(filename)
    file_content =load_single_document(file_path)
    MITRE=re.findall(r"T\d{4}",file_content)
    print("-"*60)
    print("Document Load testing")
    print("-"*60)
    print(f"Content length : {len(file_content)}")
    print(f"MITRE: {MITRE}")
    print(f"Metadata: {metadata}")"""
    folder_path=os.path.join(os.getcwd(),"data/security_docs")
    chroma_data=load_all_documents(folder_path)
    #print(chroma_data)
    print("="*60)
    print("TESTING CHROMA DB")
    print("="*60)
    index_to_chrome(chroma_data,"security_docs")
    print("-"*60)
