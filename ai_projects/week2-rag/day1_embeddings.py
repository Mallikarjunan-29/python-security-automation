from sentence_transformers import SentenceTransformer
import time
import numpy as np
from numpy.linalg import norm

mpnet_model=SentenceTransformer('all-mpnet-base-v2')
minilm_model=SentenceTransformer('all-MiniLM-L6-v2')
    
def get_embeddings(text=[]):
    """
    Convert text to embedding
    
    Args:
        text: Any string
        
    Returns:
        List of numbers (embedding vector)
        
    Your tasks:
    1. Load the embedding model
    2. Generate embedding for input text
    3. Return the vector
    """

    mpnet_start_time=time.time()
    mpnet_embeddings=mpnet_model.encode(text)
    mpnet_end_time=time.time()-mpnet_start_time
    print(f"Model 1 time taken {mpnet_end_time}")
    minilm_start_time=time.time()
    minilm_embeddings=minilm_model.encode(text)
    minilm_end_time=time.time()-minilm_start_time
    print(f"Model 2 time taken {minilm_end_time}")
    return mpnet_embeddings,minilm_embeddings

def test_embeddings():
    """
    Test embeddings with security text
    
    Your tasks:
    1. Create 3 security-related sentences
    2. Generate embeddings for each
    3. Print shape and first 5 values
    4. Calculate similarity between them
    """
    
    # Test sentences (you create better ones)
    sentence1 = "Phishing attack detected in email"
    sentence2 = "Suspicious email with malicious link"
    sentence3 = "Server disk space is low"
    text=[sentence1,sentence2,sentence3]
    mpnet,minilm=get_embeddings(text)
    print(f"Mpnet Shape: {mpnet.shape}\n MiniLM shape:{minilm.shape}")
    print("\nFirst 5 items in Mpnet:")
    print("="*50)
    for items in mpnet:
        print(f"\n{items[:5]}")
    print("="*50)
    print("\nFirst 5 items in Minilm:")
    print("="*50)
    for items in minilm:
        print(f"\n{items[:5]}")
    print("="*50)

    mpnet_overall=cosine_sim_matrix(mpnet)
    print("MPNET MODEL SIMILARITIES")
    print("="*50)
    print(f"Similarity between sentence 1 and sentence 2 is {mpnet_overall[0][1]}")
    print(f"Similarity between sentence 1 and sentence 3 is {mpnet_overall[0][2]}")
    print(f"Similarity between sentence 2 and sentence 3 is {mpnet_overall[1][2]}")
    print("="*50)
    
    minilm_overall=cosine_sim_matrix(minilm)
    print("Minilm MODEL SIMILARITIES")
    print("="*50)
    print(f"Similarity between sentence 1 and sentence 2 is {minilm_overall[0][1]}")
    print(f"Similarity between sentence 1 and sentence 3 is {minilm_overall[0][2]}")
    print(f"Similarity between sentence 2 and sentence 3 is {minilm_overall[1][2]}")
    print("="*50)

def cosine_sim_matrix(embeddings):
    normed=embeddings/norm(embeddings,axis=1,keepdims=True)
    return np.dot(normed,normed.T)

if __name__=='__main__':
    test_embeddings()