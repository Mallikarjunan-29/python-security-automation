```markdown
# Day 2: Vector Database Concepts

## What I Learned

### 1. Vector Databases vs Traditional Databases

**Traditional (SQL):**
- [How it works] - Stores scalar values such as numbers, strings and can be queried to find the exact match
- [Example query] - select * from alerts where alert_name='phishing'
- [Limitations] - can only work on exact match and not semantic similarity

**Vector Databases:**
- [How it works] - stores vetcors in multidimensional space , with similar meanings close to one another
- [Example query] - Find phishing alerts
                    - email spoofing attempt
                    - phishing email received from xyz
                    - suspicious email with attachment
- [Advantages]  - able to bring about results which are semantically similar


### 2. How Similarity Search Works

**Step-by-step:**
1. User posts a query to the query engine using client
2. the query engine compares the embeddings
3. embeddings with values closer to the query are returned as top results

**Diagram:** [Draw on paper or describe in words]

### 3. ChromaDB Architecture

**Key components:**
- Client: [What it does]
    - Interface to talk to the chroma db
- Collection: combination of below
    - documents - actual chunks of data
    - embeddings - vectoral representation of data
    - meta data- additional info to make it easy for querying data
- Documents: [How stored]
    - As chunks of texts
- Metadata: [Purpose]
    - to aid in additional filtering

### 4. Use Cases for Security

**How vector DBs help SOC analysts:**
1. Finding runbooks,playbooks, incidents, alerts for a particular idea
2. finding alerts based on mitre TTP, IOCs
3. same alert different analysts different words can still be queried

### 5. Questions I Still Have
- are there other such options than vector db, or am i covering the only or best option
- what other use cases can be there, how does this help with hallucination
- where do these fit in overall scheme of things. The broader architecture

## Key Insights

**"Aha!" moments:**
- [What clicked for you?] - understanding chroma db when i asked AI to dumb it down to 6th grader level with relational examples
- [What surprised you?] - varying uses of Semantic Similrity search
- [What's still fuzzy?] - dot product - getting there

## Pre-Coding Questions (Answer BEFORE writing code)
**Setup Questions:**

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