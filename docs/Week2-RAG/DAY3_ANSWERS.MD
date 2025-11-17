## 📋 PART 1: Pre-Implementation Questions (30 min)

### **Answer BEFORE creating any documents**

### **Section A: Document Quality**

**Q1: What makes a security runbook effective?**
- What sections should it have?
   - Title & Purpose
      - What this runbook is for?
   - Scope
      - what is covers ( and doesn't)
   - Detection
      - How to confirm that the incident has happened
   - Investigation Steps
      - How to find out what is going on
   - Containment and Remediation
      - What should be done once the incident is confirmed
   - Post Incident & Lessons
      - what to learn after fixing it
- How much detail is right amount?
   - Written so that an intern can follow it
      - Include tools that should be used
      - What to check for
      - what is the expected outcome
- What makes it searchable?
   - Clean Title/Header
   - Important and matching keywords
   - Bulleted
   - Add tags if possible

**Q2: What information should ALWAYS be in an incident response runbook?**
- Initial response steps?
    - How to identify the alert
    - who to inform
    - Immediate safety actions
    - log time + ticket
- Investigation procedures?
    - Gather evidence
    - check the source of the attack
    - correlate alerts
    - use tools
- Containment actions?
    - isolate devices
    - block indicators
    - suspend accounts
    - preserve evidence
- Post-incident tasks?
    - Eradication
    - Recovery
    - Documentation
    - Lessons Learned

**Q3: How should IOCs be documented?**
- Inline in text?
- Separate section?
- Structured format?
- Why your choice?
    - Structured format: json
    - Easy for chroma db to search
    - example:
        {
         "IOCs": [
                    {
                    "type": "domain",
                    "value": "hacker-login.net",
                    "source": "email_header",
                    "action_taken": "blocked_in_gateway"
                    },
                    {
                    "type": "ip",
                    "value": "185.123.45.22",
                    "source": "firewall_log",
                    "action_taken": "added_to_blocklist"
                    }
                ]
        } 

**Q4: What metadata makes documents RAG-friendly?**
- Document type?
- Topic/category?
- Date/version?
- Severity?
- What else?
    - Author/Owner - "author":"mallikarjunan.k"
    - Framework/ mapping - "framework":"MITRE T1080"
    - Environment/Platform - "environment":"aws"
    - Tools Used - "tools":["email","crowdstrike","splunk"]
    - tags/keywords - "tags":["email","phishing","user_report","containment"]
    - Stage - "CKC_stage":"containment"

**Q5: How do you structure for semantic search?**
- One big document or sections?
- Headers important?
- Keywords needed?
- Natural language vs technical?
    - Sections
    - Yes. Makes it easier to read the document
    - absolutely. Helps with co-relating docs with one another
    - natural language, with reference to tools
---

### **Section B: Content Strategy**

**Q6: What's the difference between runbook, procedure, and incident report?**
- Runbook: A prescriptive playbook — defines exact steps to respond to a known incident type (phishing, malware, DDoS, etc.)
- Procedure: A technical operational guide — defines how to perform a specific action or task, not necessarily tied to an incident
- Incident report: A post-incident documentation — describes what happened, what actions were taken, who did what, and the outcome

**Q7: What security topics should your 10 documents cover?**
- List 10 topics
- Why these topics?
- How do they relate?
    Phishing
    Network Scanning - host and port
    BruteForce
    password spray
    One user accessing multiple hosts outside norm
    Malware Infection
    Suspicious powershell execution
    Outbound C2c Connections over port 53
    Data exfiltration
    low and slow data exfiltration


    these topics cover from one end of cyber kill chain to the other

**Q8: Should documents reference each other?**
- Yes or no?
    - yes
- How to implement references?
    - inline mentioned + Related documents + meta data
- Benefits/drawbacks?
    - Benifits
        - Saves duplication
        - Easier RAG search
        - shows relationship between incidents
    - Drawbacks
        - too many can create clutter
        - circular referencing
        - unmaintained links
        - Noise for embedding

**Q9: How do you handle document versions?**
- Include date in content?
- Version number?
- Change log?

    - Include all three above

**Q10: What makes a past incident report valuable?**
- Timeline?
- IOCs?
- Lessons learned?
- What else?
    - the technical details in the report such as tools or queries used
    - steps taken to investigate and other measures of incident response process
    - to understand if it is a repeat incident and then plug holes

---

### **Section C: MITRE Integration**

**Q11: What is MITRE ATT&CK?**
- In your own words
    - MITRE is a frame which helps analysts undrestand which phase in a cyber kill chain an attack is in. What are the techniques and tactics used and what can be the branches of next attack
- Why does it matter for security docs?
    - It provides clear reference to TTPs used by adversaries and also tells analysts where the use cases need to be built
    - TTP Awareness
    - structured mapping
    - consistency across docs
    - planning detection and response
**Q12: Which MITRE techniques should your docs cover?**
- List 5 techniques
- Map to your 10 document topics
T1566 — Phishing
T1046 — Network Service Discovery
T1110 — Brute Force.
T1110.003 — Password Spraying
T1078 — Valid Accounts
T1021 — Remote Services
T1204 — User Execution
T1547 — Boot or Logon Autostart Execution
T1059 — Command and Scripting Interpreter
T1059.001 — Command and Scripting Interpreter: PowerShell
T1071.004 — Application Layer Protocol: DNS
T1041 — Exfiltration Over C2 Channel
T1020 — Automated Exfiltration,
T1030 — Data Transfer Size Limits

**Q13: How do you document MITRE techniques?**
- Just technique ID (T1110)?
- Full name + description?
- Link to MITRE website?
    - Technique ID and name

**Q14: Should every document have MITRE mapping?**
- Yes/no?
    - No
- Which document types need it?
    - All security documents which handle alerts need it
- Which don't?
    - Procedural documents and policies don't need it
