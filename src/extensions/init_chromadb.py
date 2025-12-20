from ai_projects.batch_processor import AI_response_handler

def init_db():
    """
    Initialize ChromaDB only once before Gunicorn starts
    """
    print("Initializing ChromaDB...")
    AI_response_handler("security_docs")
    print("ChromaDB initialized successfully.")