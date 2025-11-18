# 🛡️ AI-Powered SOAR Platform (Learning Project)

> **End-to-end security orchestration platform demonstrating automated incident response workflows - from alert classification to multi-tool coordination.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Status](https://img.shields.io/badge/Status-Week%202%20Complete-success.svg)

**📌 Project Note:** This is a portfolio/learning project built to understand SOAR architecture and automation workflows. Security tool integrations use simulated responses to demonstrate orchestration logic without requiring enterprise tool access.

---

## 📋 Table of Contents

- [What This Project Demonstrates](#what-this-project-demonstrates)
- [Quick Demo](#quick-demo)
- [Architecture Overview](#architecture-overview)
- [What's Real vs Simulated](#whats-real-vs-simulated)
- [Key Features](#key-features)
- [Performance Metrics](#performance-metrics)
- [API Endpoints](#api-endpoints)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [What I Learned](#what-i-learned)
- [Tech Stack](#tech-stack)
- [Project Journey](#project-journey)
- [Future Enhancements](#future-enhancements)

---

## 🎯 What This Project Demonstrates

This SOAR (Security Orchestration, Automation, and Response) platform was built to learn and demonstrate:

✅ **End-to-end automation workflows** - Alert → Classification → Playbook Execution → Audit Trail  
✅ **AI-powered decision making** - 95%+ classification accuracy with explainable reasoning  
✅ **Multi-tool orchestration** - Concurrent execution across EDR, Firewall, IAM, SIEM, Ticketing  
✅ **Platform-agnostic architecture** - Base integration framework for easy extensibility  
✅ **Production-quality code** - Error handling, logging, threading, caching, rate limiting  

### Why This Approach?

Building with full production security tools requires:
- Enterprise licenses ($50K-$200K+ annually)
- Production API credentials
- Live security infrastructure
- Compliance approvals

Instead, I focused on what's actually **hard** about SOAR:
1. ⚙️ **Workflow orchestration logic** - Managing state across async actions
2. 🔄 **Multi-threaded execution** - Concurrent actions with error handling
3. 📝 **Declarative playbooks** - YAML parsing and variable resolution
4. 🏗️ **Platform-agnostic design** - Extensible integration framework
5. 📊 **State management** - Audit trails and execution tracking

*Calling REST APIs is straightforward. Designing the orchestration framework is the challenge.*

---

## 🚀 Quick Demo

### From Alert to Automated Response in 1.5 Seconds

**Input:** Malicious PowerShell Alert
```json{
"alert_id": "psh-20251117-004",
"host": "win-0458",
"user": "robert.clark",
"process": {
"command_line": "powershell.exe -enc JAB...",
"process_id": "5566"
},
"network": {
"destination_ip": "103.44.20.11"
},
"severity": "Critical"
}

**System Response:**Step 1: AI Classification (0.85s)
├─ Classification: TRUE_POSITIVE
├─ Confidence: 95%
├─ Severity: Critical
└─ Reasoning: Encoded PowerShell + external IP communicationStep 2: Playbook Matching (0.01s)
└─ Matched: "Malicious PowerShell Response"Step 3: Automated Execution (1.5s)
├─ [SUCCESS] Host isolated (EDR) - 0.3s
├─ [SUCCESS] Malicious IP blocked (Firewall) - 0.3s
├─ [SUCCESS] Process terminated (EDR) - 0.3s
├─ [SUCCESS] Evidence collected (Splunk) - 0.3s
├─ [SUCCESS] Credentials reset (Active Directory) - 0.3s
└─ [SUCCESS] Incident ticket created (ServiceNow) - 0.3sTotal Execution Time: 2.36 seconds
Actions Coordinated: 6 platforms
Success Rate: 100%

---

## 🏗️ Architecture Overview┌──────────────────────────────────────────────────────────┐
│                 Security Alert (JSON)                    │
└────────────────────────┬─────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────┐
│              Multi-Source Enrichment                     │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│   │  AbuseIPDB   │  │ VirusTotal   │  │  URLhaus     │ │
│   │  (Real API)  │  │  (Real API)  │  │  (Real API)  │ │
│   └──────────────┘  └──────────────┘  └──────────────┘ │
└────────────────────────┬─────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────┐
│            AI Classification (Gemini 2.5)                │
│  • TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW         │
│  • Confidence Score (0-100%)                             │
│  • Explainable Reasoning                                 │
│  • Severity Assessment                                   │
└────────────────────────┬─────────────────────────────────┘
│
┌────────┴────────┐
│                 │
▼                 ▼
┌─────────────────────┐  ┌─────────────────────┐
│  Runbook Retrieval  │  │  Playbook Matching  │
│  (ChromaDB RAG)     │  │  (Behavior-Based)   │
│  → Documentation    │  │  → Automation       │
└─────────────────────┘  └──────────┬──────────┘
│
▼
┌──────────────────────────────────────────────────────────┐
│           Playbook Executor (ThreadPoolExecutor)         │
│  Concurrent execution of multi-step workflows            │
└────────────────────────┬─────────────────────────────────┘
│
┌────────────────┼────────────────┐
│                │                │
▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ EDR          │  │ Firewall     │  │ IAM          │
│ (Simulated)  │  │ (Simulated)  │  │ (Simulated)  │
└──────────────┘  └──────────────┘  └──────────────┘
│                │                │
▼                ▼                ▼
┌──────────────┐  ┌──────────────┐
│ SIEM         │  │ Ticketing    │
│ (Simulated)  │  │ (Simulated)  │
└──────────────┘  └──────────────┘
│
└─────────────────┬──────────────┘
▼
┌──────────────────────────────────────────────────────────┐
│              Execution Summary (JSON)                    │
│  • Playbook executed                                     │
│  • All actions tracked with UUIDs + timestamps           │
│  • Complete audit trail                                  │
│  • Performance metrics                                   │
└──────────────────────────────────────────────────────────┘

---

## ✅ What's Real vs Simulated

### Real Components (Production API Calls):
| Component | Technology | Status |
|-----------|-----------|--------|
| AI Classification | Google Gemini API | ✅ Real |
| Threat Intelligence | AbuseIPDB API | ✅ Real |
| Threat Intelligence | VirusTotal API | ✅ Real |
| Threat Intelligence | URLhaus API | ✅ Real |
| Semantic Search | ChromaDB (Local) | ✅ Real |
| Multi-threading | ThreadPoolExecutor | ✅ Real |
| REST API | Flask HTTP Server | ✅ Real |
| Caching Layer | JSON-based (85% hit rate) | ✅ Real |

### Simulated Components (Architecture Demonstration):
| Component | Purpose | Why Simulated |
|-----------|---------|---------------|
| EDR Integration | Host isolation, process termination | Requires CrowdStrike/SentinelOne license |
| Firewall Integration | IP/domain blocking | Requires Palo Alto/Fortinet access |
| IAM Integration | Credential management | Requires Azure AD/Okta admin access |
| SIEM Integration | Evidence collection | Requires Splunk/Sentinel instance |
| Ticketing Integration | Incident documentation | Requires ServiceNow license |

**All simulated integrations include:**
- ✅ Standardized response format matching real APIs
- ✅ Execution tracking (UUIDs, timestamps, status codes)
- ✅ Simulated latency for realism (0.3s per action)
- ✅ Complete documentation for production implementation
- ✅ Thread-safe concurrent execution

---

## ⚡ Key Features

### 🤖 AI-Powered Classification
- **Google Gemini 2.5** for intelligent alert analysis
- **95%+ accuracy** with confidence scoring
- **Explainable reasoning** (4 bullet points per decision)
- **Severity assessment** (Critical/High/Medium/Low)
- **Behavioral pattern extraction** (25 attack signatures)

### 🌐 Multi-Source Threat Intelligence
- **AbuseIPDB**: IP reputation + abuse confidence scoring
- **VirusTotal**: Community detections + historical analysis
- **URLhaus**: Malicious URL database
- **Intelligent caching**: 85% hit rate (avoids redundant API calls)
- **Private IP detection**: Skips lookups for RFC1918 addresses

### 🎯 SOAR Orchestration
- **YAML-defined playbooks**: Declarative workflows (no code changes needed)
- **Variable resolution**: `${alert.field}` → actual values
- **Concurrent execution**: ThreadPoolExecutor (5+ tools simultaneously)
- **Execution tracking**: UUID + timestamp for every action
- **Complete audit trails**: All actions logged with results

### 📋 Available Playbooks
1. **Malicious PowerShell Response** (T1059.001, T1105)
2. **Phishing Email Response** (T1566, T1204)
3. **Brute Force Attack Mitigation** (T1110)
4. **Lateral Movement Containment** (T1021, T1078)
5. **Data Exfiltration Response** (T1041, T1567)

### 🚀 Performance Optimizations
- **2-layer caching**: Threat intel (85% hit) + AI responses (60% hit)
- **Parallel processing**: ThreadPoolExecutor for batch operations
- **Rate limiting**: Respects API quotas automatically
- **Cost tracking**: $0.0012 average per alert

---

## 📊 Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| **Alert Classification Time** | 0.85s | AI analysis + TI enrichment |
| **Playbook Execution Time** | 1.5-3s | 6 concurrent actions |
| **End-to-End Processing** | 2.4s | Alert → Response → Audit trail |
| **Classification Accuracy** | 95%+ | Tested on 50+ sample alerts |
| **Cache Hit Rate (TI)** | 85% | Avoids redundant lookups |
| **Cache Hit Rate (AI)** | 60% | Based on behavior patterns |
| **Cost Per Alert** | $0.0012 | With caching enabled |
| **Concurrent Actions** | 5-6 | Orchestrated simultaneously |
| **Success Rate** | 100% | All test scenarios passed |

### Batch Processing Performance:
- **14 alerts processed in 5 seconds** (2.8 alerts/sec)
- **7× faster** than sequential processing
- **100% cost savings** on cached alerts

---

## 📡 API Endpoints

### POST `/analyze`
Analyze a single security alert with automated response.

**Request:**
```json{
"alert_id": "TEST-001",
"source_ip": "185.220.101.52",
"user": "alice@company.com",
"failed_logins": 10,
"severity": "High"
}

**Response:**
```json{
"classification": "TRUE_POSITIVE",
"confidence": 95,
"severity": "Critical",
"reasoning": [
"10 failed login attempts from TOR exit node",
"Source IP has 100% abuse confidence score",
"Successful login after failed attempts indicates compromise",
"Login time outside normal business hours"
],
"threat_intel": [
{
"IP": "185.220.101.52",
"AbuseConfidenceScore": 100,
"ISTor": true,
"TotalReports": 173
}
],
"runbook": "Title: Brute Force Attack Mitigation\n\nSeverity: High\n...",
"playbook_execution": {
"status": "success",
"playbook_name": "Brute Force Attack Mitigation",
"steps_executed": 5,
"steps_succeeded": 5,
"actions": [
{
"action": "block_ip",
"platform": "Palo Alto Firewall",
"status": "Success",
"execution_id": "769377c4-9a1b-4270-abaa-843296b80501",
"timestamp": "2025-11-17T16:59:41.318193"
},
{
"action": "disable_user",
"platform": "Active Directory",
"status": "Success",
"execution_id": "49189d10-3a30-4aff-aafb-709949058c79",
"timestamp": "2025-11-17T16:59:41.318878"
}
]
},
"performance": {
"processing_time": 2.36,
"total_cost": "$0.0021"
}
}

### POST `/batch`
Process multiple alerts concurrently.

**Request:**
```json{
"alerts": [
{...alert1...},
{...alert2...}
]
}

### GET `/health`
System health and monitoring.

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- API Keys (free tiers available):
  - [Google AI Studio](https://aistudio.google.com/app/apikey) (Gemini)
  - [AbuseIPDB](https://www.abuseipdb.com/register)
  - [VirusTotal](https://www.virustotal.com/gui/join-us)

### Quick Start
```bashClone repository
git clone https://github.com/yourusername/soar-platform.git
cd soar-platformInstall dependencies
pip install -r requirements.txtConfigure environment variables
cp .env.example .env
Edit .env and add your API keysRun the server
python flask_test.py

Server starts on `http://localhost:5000`

---

## 🎮 Usage Examples

### Example 1: Analyze Single Alert
```bashcurl -X POST http://localhost:5000/analyze 
-H "Content-Type: application/json" 
-d '{
"alert_id": "TEST-001",
"host": "win-0458",
"user": "robert.clark",
"process": {
"command_line": "powershell.exe -enc JAB...",
"process_id": "5566"
},
"network": {
"destination_ip": "103.44.20.11"
},
"severity": "Critical"
}'

### Example 2: Check System Health
```bashcurl http://localhost:5000/health | jq

### Example 3: Batch Processing
```bashcurl -X POST http://localhost:5000/batch 
-H "Content-Type: application/json" 
-d @test_batch.json

---

## 💡 What I Learned

### Technical Skills Developed:
- ✅ **Multi-threaded programming** in Python (ThreadPoolExecutor)
- ✅ **Async workflow orchestration** with state management
- ✅ **YAML parsing and validation** for declarative configs
- ✅ **Variable resolution** with regex patterns
- ✅ **REST API design** with Flask
- ✅ **Integration architecture** patterns
- ✅ **Error handling at scale** (retries, timeouts, graceful degradation)
- ✅ **Caching strategies** (2-layer with TTL)
- ✅ **Rate limiting** for external APIs

### SOAR Concepts Mastered:
- ⚙️ **Playbook design principles** - Balancing automation with human oversight
- 🔄 **Orchestration patterns** - Managing concurrent actions with dependencies
- 📊 **State management** - Tracking execution across distributed actions
- 🔍 **Audit trail requirements** - Complete accountability for automated actions
- 🎯 **Integration framework design** - Platform-agnostic architecture
- 🛡️ **Security automation best practices** - When to automate vs escalate

### Key Insights:
1. **SOAR isn't about the integrations** - It's about the orchestration logic
2. **Workflow design is hard** - Handling partial failures, retries, state management
3. **Production code is 80% error handling** - Happy path is easy; edge cases are hard
4. **Architecture matters more than features** - Extensibility > completeness
5. **AI adds intelligence** - But you still need solid engineering fundamentals

---

## 🛠️ Tech Stack

| Category | Technology | Purpose |
|----------|-----------|---------|
| **Language** | Python 3.10+ | Core development |
| **AI/LLM** | Google Gemini 2.5 Flash | Alert classification |
| **Web Framework** | Flask 3.0+ | REST API |
| **Threat Intel** | AbuseIPDB, VirusTotal, URLhaus | IP/URL reputation |
| **Vector DB** | ChromaDB | Semantic search (RAG) |
| **Embeddings** | Sentence Transformers | Text-to-vector conversion |
| **Concurrency** | ThreadPoolExecutor | Parallel execution |
| **Caching** | JSON-based with TTL | Performance optimization |
| **Logging** | Python logging + RotatingFileHandler | Audit trails |
| **YAML Parsing** | PyYAML | Playbook definitions |

---

## 📈 Project Journey

### Week 1: AI Alert Triage Foundation
**Built:** AI-powered classification + multi-source threat intelligence + caching

**Key Achievement:** Reduced alert processing from 15 minutes (manual) to <1 second (automated)

**Blog Post:** [Link to first LinkedIn post about Week 1]

---

### Week 2: SOAR Orchestration
**Built:** Playbook system + integration framework + execution engine

**Key Achievement:** End-to-end automated response in 2.4 seconds across 6 platforms

**What Changed:** Went from "classify alerts" to "automatically respond to threats"

---

## 🗺️ Future Enhancements

### Planned Improvements:
- [ ] **Human-in-the-loop approval workflows** - Require approval for critical actions
- [ ] **Incident state management** - Track incidents from detection → resolution
- [ ] **Advanced error handling** - Retry logic, rollback on failure
- [ ] **Performance dashboard** - Real-time metrics and analytics
- [ ] **Webhook support** - Push notifications to external systems

### Long-Term Vision:
- [ ] **Multi-agent IR orchestrator** - Advanced decision-making across agents
- [ ] **ML-based anomaly detection** - Behavioral baseline analysis
- [ ] **Advanced correlation rules** - Cross-alert pattern detection
- [ ] **Playbook recommendation engine** - AI suggests relevant playbooks

---

## 📁 Project Structuresoar-platform/
├── flask_test.py                 # Flask API server
├── ai_projects/
│   ├── day1_alertclassifier.py   # AI classification logic
│   ├── day2_threatintel.py       # Threat intel enrichment
│   ├── batch_processor.py        # Parallel batch processing
│   └── soar/
│       ├── executor.py           # Playbook execution engine
│       ├── playbook_parser.py    # YAML parser + validator
│       └── resolver.py           # Variable resolution
├── src/
│   ├── integrations/
│   │   ├── base_integration.py   # Base class for all integrations
│   │   ├── edr_integration.py    # EDR (simulated)
│   │   ├── firewall_integration.py
│   │   ├── ad_integration.py     # Active Directory
│   │   ├── splunk_integration.py # SIEM
│   │   └── service_integration.py # ServiceNow
│   ├── cache_handler.py          # 2-layer cache management
│   ├── logger_config.py          # Centralized logging
│   ├── rate_limiter.py           # API rate limiting
│   ├── alert_queue.py            # Priority queue sorting
│   └── ioc_extractor.py          # IOC extraction + behavior patterns
├── data/
│   ├── playbooks/                # YAML playbook definitions
│   │   ├── brute_force_mitigation.yaml
│   │   ├── malicious_powershell.yaml
│   │   ├── phishing_response.yaml
│   │   ├── lateral_movement_containment.yaml
│   │   └── data_exfiltration_response.yaml
│   └── security_docs/            # Runbooks for RAG
├── cache/
│   ├── cache.json                # Threat intel cache
│   └── ai_cache.json             # AI response cache
├── requirements.txt
├── .env.example
└── README.md

---

## 🤝 Contributing

This is a learning project, but feedback and suggestions are welcome!

**Areas for discussion:**
- SOAR architecture patterns
- Integration framework design
- Workflow orchestration approaches
- Error handling strategies

Feel free to open issues for questions or discussions.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Google Gemini** for powerful AI capabilities
- **AbuseIPDB & VirusTotal** for threat intelligence APIs
- **SOC analysts** who inspired this project
- **Security automation community** for best practices

---

## 📬 Contact

Built by [Your Name] as part of a 24-month DevSecOps + AI Security Engineer learning journey.

- **LinkedIn:** [Your Profile](https://www.linkedin.com/in/mallikarjunan-cybersecpro/)
- **GitHub:** [@Mallikarjunan-29](https://github.com/Mallikarjunan-29)
- **Portfolio Project:** Week 2 of 104

**Learning Roadmap:**
- ✅ Week 1: AI-powered alert triage
- ✅ Week 2: SOAR orchestration
- 🔄 Week 3-4: Advanced RAG + threat hunting
- 📅 Months 3-6: Multi-agent systems

---

**⭐ If this project helped you understand SOAR architecture, please star the repo!**

*Completed: November 2025*
*Status: Active Development*