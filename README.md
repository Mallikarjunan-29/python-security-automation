# 🧠 Python Security Automation – AI-Powered SOC Assistant

> Building an AI-driven SOC automation pipeline that classifies alerts, enriches them with threat intelligence, and optimizes performance — step by step.

---

## 🚀 Project Overview

This repository showcases the development of an **AI-based Security Operations (SOC) Automation System**.

The system automatically:
- 🕵️‍♂️ Analyzes login alerts using **Google Gemini 2.5 Flash**
- 🌐 Enriches them with **AbuseIPDB** and **VirusTotal**
- 🧮 Classifies alerts as `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_REVIEW`
- 💾 Caches results to minimize repeated API calls
- ⚡ Tracks token usage and cost efficiency per analysis

---

## 📅 Week 1 Progress (Up to Day 3)

### ✅ **Day 1 – AI Alert Classifier**

**Objective:** Build the core alert classification engine.

**Highlights:**
- Integrated **Gemini 2.5 Flash** for alert reasoning.
- Designed step-by-step classification logic.
- Output structured JSON with:
  - Classification (`TRUE_POSITIVE` / `FALSE_POSITIVE` / `NEEDS_REVIEW`)
  - Confidence score (0–100%)
  - Three-bullet reasoning summary.
- Implemented per-alert cost and token usage tracking.

📂 **Files**
- `day1_alertclassifier.py`
- `day2_threatintel.py`
- `test_alerts.py`

🧠 **Example Output**
Classification: TRUE_POSITIVE
Confidence: 95%
Reasoning:

User 'alice@company.com
' logged in after 8 failed attempts from a TOR exit node.

IP (185.220.101.52) flagged by AbuseIPDB (100%) & VirusTotal (negative reputation).

Matches brute-force pattern and unusual login time.

---

### ✅ **Day 2 – Threat Intelligence Integration**

**Objective:** Add automated enrichment via external threat feeds.

**Highlights:**
- Built dedicated modules for:
  - ☣️ **AbuseIPDB** IP reputation lookup  
  - 🧬 **VirusTotal** IP intelligence
- Added:
  - Private IP detection  
  - Retry mechanism for transient failures  
  - Timeout handling  
- Unified results with an `ip_lookup()` wrapper for consistent enrichment.

📂 **Files**
- `day2_threatintel.py`

🧩 **Example Threat Intel Output**
```json
{
  "AbuseIPDB": {
    "IP": "185.220.101.52",
    "UsageType": "Hosting",
    "AbuseConfidenceScore": 100,
    "IsTor": true
  },
  "VirusTotal": {
    "Owner": "TOR Network",
    "Reputation": -20,
    "Stats": {"harmless": 0, "malicious": 15, "suspicious": 4}
  }
}
✅ Day 3 – Caching & Cost Optimization

Objective: Reduce redundant API calls and improve speed.

Highlights:

Implemented centralized JSON cache for threat intel lookups.

Added TTL-based pruning to keep cache fresh.

Introduced cache hit counter for performance analytics.

Achieved ~60% API call reduction.

Added token cost tracking for each AI classification.

📂 Files

cache_handler.py

logger_config.py

test_alerts.py

🧩 Architecture (as of Day 3)
           ┌─────────────────────┐
           │ test_alerts.py      │
           │  (Batch Executor)   │
           └─────────┬───────────┘
                     │
          ┌──────────┴──────────┐
          │ day1_alertclassifier │
          │  (AI Classification)│
          └──────────┬──────────┘
                     │
          ┌──────────┴──────────┐
          │ day2_threatintel    │
          │ (AbuseIPDB + VT)   │
          └──────────┬──────────┘
                     │
          ┌──────────┴──────────┐
          │ cache_handler.py    │
          │  (Cache Layer)      │
          └─────────────────────┘
💰 Token Usage & Cost Model
Metric	Description	Example
Prompt Tokens	Input tokens sent to model	417
Candidate Tokens	Output tokens from model	200
Total Tokens	Includes internal “thought” tokens	2104
Cost Formula	(Prompt / 1M * $1) + (Candidate / 1M * $3.5)	≈ $0.0245 per alert

💡 Internal “thought” tokens are used by Gemini for reasoning and are not billed.
⚙️ Tech Stack
Category	Tools / Libraries
🧩 Language - 	Python 3.10+
🤖 LLM	 - Google Gemini 2.5 Flash
☣️ Threat Intel - 	AbuseIPDB, VirusTotal
🪵 Logging	 - RotatingFileHandler
💾 Cache	 - JSON-based TTL cache
🧠 Architecture - 	Modular, test-driven design

⚡ Setup & Usage
# Clone the repository
git clone https://github.com/Mallikarjunan-29/python-security-automation.git
cd python-security-automation

# Install dependencies
pip install -r requirements.txt

# Configure API keys in .env
ABUSEIPDB=your_abuseipdb_key
VTKEY=your_virustotal_key
GEMINIKEY=your_gemini_key

# Run alert classification
python test_alerts.py

Classification: TRUE_POSITIVE
Confidence: 95
Reasoning: ["Suspicious login from TOR exit node after failed attempts..."]
Cost: $0.0245
Cache hits: 3

🧠 Key Learnings So Far

⚙️ Caching reduced API usage by ~60%

💾 Single-file cache simplified state management

💰 Cost optimization achieved via token analytics

🧩 Modular design enables future scaling (batch, async, RAG)
🗺️ Next Step (Coming Up)

Day 4 – Batch Processing & Performance Optimization
Goal: Process 500+ alerts with parallelism, rate limiting, and smarter caching.

(Implementation in progress — to be released soon.)

⭐ Support
If you find this useful, please give the repo a ⭐ to follow the evolution of the AI-powered SOC automation series.


---
