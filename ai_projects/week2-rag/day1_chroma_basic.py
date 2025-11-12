import chromadb
from transformers import SentenceTransformer

class SecurityKnowledgeBase:
    """
    Your first vector database
    
    Stores security documents and retrieves them by semantic similarity
    """
    
    def __init__(self, collection_name="security_docs"):
        """
        Initialize Chroma
        
        Your decisions:
        1. Persistent or in-memory?
        2. Where to store the database?
        3. Which embedding function?
        """
        
        # Your code here
        # Hint: chromadb.PersistentClient() or chromadb.Client()?
        pass
    
    def add_document(self, document_text: str, document_id: str, metadata: dict = None):
        """
        Add a document to the knowledge base
        
        Args:
            document_text: The actual document content
            document_id: Unique ID (e.g., "runbook_phishing_001")
            metadata: Optional info (e.g., {"type": "runbook", "date": "2025-01-01"})
        
        Your tasks:
        1. Generate embedding for document_text
        2. Store in Chroma collection
        3. Include metadata for filtering
        """
        pass
    
    def search(self, query: str, top_k: int = 3):
        """
        Search for relevant documents
        
        Args:
            query: User's question
            top_k: Number of results to return
        
        Returns:
            List of relevant documents with scores
        
        Your tasks:
        1. Generate embedding for query
        2. Search Chroma for similar documents
        3. Return results with similarity scores
        """
        pass
    
    def get_all_documents(self):
        """
        List all documents in collection
        
        Useful for debugging
        """
        pass


def test_knowledge_base():
    """
    Test your vector database
    
    Your tasks:
    1. Create knowledge base
    2. Add 5 security documents
    3. Test different queries
    4. Print results
    """
    
    kb = SecurityKnowledgeBase()
    
    # Sample security documents (you create better ones)
    documents = [
        {
            "id": "doc_001",
            "text": "Phishing Response: Immediately report suspicious emails to security team. Do not click links or download attachments.",
            "metadata": {"type": "runbook", "topic": "phishing"}
        },
        {
            "id": "doc_002", 
            "text": "Ransomware Incident: Isolate affected systems immediately. Do not pay ransom. Contact incident response team.",
            "metadata": {"type": "runbook", "topic": "ransomware"}
        },
        # Add 3 more documents about:
        # - Brute force attacks
        # - Data exfiltration
        # - Lateral movement
    ]
    
    # Your code: Add documents to knowledge base
    
    # Your code: Test queries
    queries = [
        "How to handle suspicious email?",
        "What to do if ransomware detected?",
        "Steps for brute force attack?"
    ]
    
    # Your code: Search and print results
    
    pass


if __name__ == "__main__":
    test_knowledge_base()