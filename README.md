# 🛡️ AI-Powered Security Alert Triage System

> **Intelligent SOC automation that classifies security alerts, enriches them with threat intelligence, and provides actionable insights — eliminating 70% of manual triage work.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Solution Architecture](#solution-architecture)
- [Key Features](#key-features)
- [Performance Benchmarks](#performance-benchmarks)
- [API Endpoints](#api-endpoints)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Roadmap](#roadmap)

---

## 🎯 Overview

This project is a **production-ready AI security automation system** that transforms how Security Operations Centers (SOCs) handle alert triage.

**What it does:**
- Automatically classifies security alerts as `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_REVIEW`
- Enriches alerts with multi-source threat intelligence (AbuseIPDB, VirusTotal)
- Provides confidence scoring and explainable AI reasoning
- Optimizes performance with intelligent caching and parallel processing
- Exposes REST API for SIEM/SOAR integration

**Built as part of a 24-month DevSecOps learning journey.**

---

## 🔥 Problem Statement

**The Challenge:**
- SOC analysts spend **70% of their time** on repetitive alert triage
- Manual threat intel lookups take **5-10 minutes per alert**
- 500+ overnight alerts = **40+ hours of analyst time** wasted
- Fatigue leads to missed real threats (alert fatigue)

**The Impact:**
- Critical alerts buried in noise
- Slow incident response times
- Analyst burnout and turnover

---

## 💡 Solution Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SIEM (Azure Sentinel)                   │
│                    Firewall, EDR, etc.                      │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP POST
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Flask REST API Layer                       │
│            /analyze (single) | /batch (bulk)                │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
┌──────────────────┐        ┌──────────────────┐
│  Threat Intel    │        │   AI Classifier  │
│  Enrichment      │───────▶│   (Gemini 2.5)   │
│  (AbuseIPDB/VT)  │        │                  │
└──────────────────┘        └──────────────────┘
        │                             │
        └──────────────┬──────────────┘
                       ▼
            ┌─────────────────────┐
            │  Intelligent Cache  │
            │  (2-Layer: TI + AI) │
            └─────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Classification Response (JSON)                 │
│  • TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW           │
│  • Confidence Score (0-100%)                               │
│  • Explainable Reasoning (3 bullet points)                 │
│  • Threat Intel Context                                    │
│  • Processing Cost & Performance Metrics                   │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼
            ┌─────────────────────┐
            │  SOAR Platform      │
            │  (Automated Actions)│
            └─────────────────────┘
```

---

## ⚡ Key Features

### 🧠 AI-Powered Classification
- **Google Gemini 2.5 Flash** for intelligent alert analysis
- Explainable AI reasoning (not a black box)
- Confidence scoring for human-in-the-loop decisions
- MITRE ATT&CK technique identification (coming soon)

### 🌐 Multi-Source Threat Intelligence
- **AbuseIPDB**: IP reputation, abuse confidence scoring
- **VirusTotal**: Community detections, historical analysis
- Private IP detection (skip lookups for RFC1918)
- Automatic retry with exponential backoff

### 🚀 Performance Optimization
- **2-Layer Caching**: Threat intel + AI responses
- **Parallel Processing**: ThreadPoolExecutor for batch operations
- **Smart Rate Limiting**: Respects API quotas
- **Cost Tracking**: Per-alert token usage and cost analysis

### 🔌 Production-Ready API
- RESTful endpoints for integration
- Health monitoring (`/health`)
- Batch processing support (`/batch`)
- Comprehensive error handling

---

## 📊 Performance Benchmarks

| Scenario                | Alerts | Time   | Cost    | Cache Hit Rate |
|-------------------------|--------|--------|---------|----------------|
| Sequential, no cache    | 15     | ~84s   | $0.058  | 0%            |
| Parallel, no cache      | 15     | ~12s   | $0.058  | 0%            |
| Sequential, cached      | 15     | ~0.03s | $0     | 100%          |
| **Parallel, cached**    | **15** | **~0.016s** | **$0** | **100%**      |

### Real-World Impact:
- **7× faster** than sequential processing
- **100% cost savings** on cached alerts
- **14 alerts processed in 5 seconds** (production test)
- Average cost: **$0.0012 per alert** (with caching)

---

## 🔌 API Endpoints

### POST `/analyze`
Analyze a single security alert.

**Request:**
```json
{
  "name": "Suspicious Login",
  "alert": {
    "user": "alice@company.com",
    "source_ip": "185.220.101.52",
    "failed_logins": 8,
    "success": true,
    "time": "02:00",
    "location": "Moscow, RU",
    "severity": "Critical"
  }
}
```

**Response:**
```json
{
  "classification": "TRUE_POSITIVE",
  "confidence": 95,
  "severity": "Critical",
  "reasoning": [
    "8 failed login attempts followed by success from TOR exit node",
    "Source IP has 100% abuse confidence score on AbuseIPDB",
    "Login time (02:00) outside normal business hours"
  ],
  "threat_intel": {
    "abuse_score": 100,
    "is_tor": true,
    "total_reports": 173
  },
  "performance": {
    "processing_time": 0.85,
    "from_cache": false,
    "cost": "$0.0016"
  }
}
```

### POST `/batch`
Process multiple alerts in parallel.

**Request:**
```json
{
  "alerts": [
    {...alert1...},
    {...alert2...}
  ]
}
```

**Response:**
```json
{
  "summary": {
    "total": 14,
    "true_positive": 5,
    "false_positive": 8,
    "needs_review": 1,
    "processing_time": 5.07,
    "total_cost": "$0.017",
    "ai_cache_hit": "21.4%",
    "ti_cache_hit": "100%"
  },
  "results": [...]
}
```

### GET `/health`
System health and monitoring.

**Response:**
```json
{
  "status": "healthy",
  "server_up_time": 3600.5,
  "cache": {
    "threat_intel": {
      "exists": true,
      "entries": 45,
      "size_mb": 0.12
    },
    "ai_response": {
      "exists": true,
      "entries": 120,
      "size_mb": 0.34
    }
  },
  "apis": {
    "gemini_status": "online",
    "abuse_ip_db_status": "online",
    "vt_status": "online"
  }
}
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- API Keys for:
  - [Google AI Studio](https://aistudio.google.com/app/apikey) (Gemini)
  - [AbuseIPDB](https://www.abuseipdb.com/register)
  - [VirusTotal](https://www.virustotal.com/gui/join-us)

### Setup
```bash
# Clone repository
git clone https://github.com/yourusername/ai-alert-triage.git
cd ai-alert-triage

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and add your API keys

# Run the server
python flask_test.py
```

Server starts on `http://localhost:5000`

---

## 🎮 Usage

### Single Alert Analysis
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Brute Force Attack",
    "alert": {
      "user": "admin@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 10,
      "success": true,
      "time": "03:00",
      "location": "Russia",
      "severity": "Critical"
    }
  }'
```

### Batch Processing
```bash
curl -X POST http://localhost:5000/batch \
  -H "Content-Type: application/json" \
  -d @test_batch.json
```

### Health Check
```bash
curl http://localhost:5000/health | jq
```

### Automated Testing
```bash
chmod +x test_api.sh
./test_api.sh
```

---

## 📁 Project Structure

```
ai-alert-triage/
├── flask_test.py              # Flask API server
├── ai_projects/
│   ├── day1_alertclassifier.py   # AI classification logic
│   ├── day2_threatintel.py       # Threat intel enrichment
│   └── batch_processor.py        # Parallel batch processing
├── src/
│   ├── cache_handler.py          # 2-layer cache management
│   ├── logger_config.py          # Centralized logging
│   ├── rate_limiter.py           # API rate limiting
│   └── alert_queue.py            # Priority queue sorting
├── cache/
│   ├── cache.json                # Threat intel cache
│   └── ai_cache.json             # AI response cache
├── data/
│   └── test_batch.json           # Sample test data
├── output/
│   ├── output_batch.log          # Batch test results
│   └── output_analyze.log        # Single alert results
├── test_api.sh                # API test script
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| **Language** | Python 3.10+ |
| **AI/LLM** | Google Gemini 2.5 Flash |
| **Web Framework** | Flask 3.0+ |
| **Threat Intel** | AbuseIPDB, VirusTotal APIs |
| **Concurrency** | ThreadPoolExecutor |
| **Caching** | JSON-based with TTL pruning |
| **Logging** | RotatingFileHandler |
| **HTTP Client** | requests library |

---

## 🗺️ Roadmap

### ✅ Week 1 (Complete)
- [x] AI-powered alert classification
- [x] Multi-source threat intelligence
- [x] Intelligent caching system
- [x] Batch processing with parallelism
- [x] REST API with Flask
- [x] Health monitoring endpoint

### 🚧 Week 2 (In Progress)
- [ ] RAG-based security knowledge base
- [ ] Vector database integration (Chroma)
- [ ] Semantic search over runbooks
- [ ] Historical incident lookup

### 📋 Week 3-4 (Planned)
- [ ] Automated detection rule generation
- [ ] Multi-agent architecture
- [ ] MITRE ATT&CK framework integration
- [ ] Advanced analytics dashboard

### 🔮 Future Enhancements
- [ ] User behavior baseline analysis
- [ ] Anomaly detection with ML
- [ ] Integration with SIEM platforms (Sentinel, Splunk)
- [ ] Custom playbook execution
- [ ] Grafana monitoring dashboard

---

## 🤝 Contributing

This is a learning project, but contributions are welcome!

**Areas for improvement:**
- Additional threat intel sources
- Advanced caching strategies
- Performance optimizations
- Additional alert types support

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Google Gemini** for powerful AI capabilities
- **AbuseIPDB & VirusTotal** for threat intelligence APIs
- **SOC analysts everywhere** - this is for you 💙

---

## 📬 Contact

Built by [Your Name] as part of a 24-month DevSecOps journey.

- LinkedIn: [\[Your Profile\]](https://www.linkedin.com/in/mallikarjunan-cybersecpro/)
- GitHub: [@Mallikarjunan-29]


---

**⭐ If you find this useful, please star the repo!**

*Week 1 Complete: November 2025*
