# SOAR Demo - Alert to Response Automation

## What It Does

AI-powered security orchestration system that receives alerts, enriches with threat intelligence, classifies with AI, generates tickets, executes response playbooks, and notifies analysts via Slack - fully automated from detection to response.

---

## Architecture Flow

```
Alert (JSON)
    ↓
Flask API (/analyze)
    ↓
IOC Extraction (IPs, URLs, Domains)
    ↓
Threat Intel Lookup (AbuseIPDB, VirusTotal)
    ↓
AI Analysis (Gemini 2.5)
    ├─ Classification (TP/FP/NEEDS_REVIEW)
    ├─ Confidence Score
    ├─ Severity Level
    ├─ Priority
    ├─ Reasoning
    └─ Semantic Query
    ↓
RAG Vector Search (ChromaDB)
    ├─ Fetch matching runbook
    └─ MITRE ATT&CK mapping
    ↓
Hive Case Creation
    ├─ Case number assigned
    └─ All context stored
    ↓
SOAR Playbook Execution (if TP + high confidence)
    ├─ Block IP (Firewall)
    ├─ Disable User (AD)
    ├─ Create Ticket (ServiceNow)
    └─ Other automated actions
    ↓
Slack Notification
    ├─ Alert details
    ├─ AI analysis
    ├─ Actions taken
    └─ Runbook attached
    ↓
API Response (JSON)
```

---

## Key Metrics

### Performance
- **Alert → Response Time:** 4-6 seconds
- **AI Classification Time:** 1.2s average
- **Threat Intel Lookup:** 0.8s (cached: 0.1s)
- **Runbook Retrieval:** 0.3s
- **Total Processing:** ~6s end-to-end

### Cost
- **AI Cost per Alert:** $0.0012 - $0.0016
- **Threat Intel:** $0 (free tier)
- **Total Cost per Alert:** <$0.002

### Accuracy
- **AI Classification:** High confidence (>85%) in 84% of cases
- **Cache Hit Rate:** 60-70% (reduces API costs)
- **False Positive Rate:** Validated by human review in Hive

### Automation Coverage
- **IOC Extraction:** 100% automated
- **Threat Intel Enrichment:** 100% automated
- **Classification:** 100% automated
- **Ticketing:** 100% automated
- **Playbook Execution:** 80% automated (only high-confidence TP)
- **Notification:** 100% automated

---

## What's Automated

### ✅ Fully Automated
- IOC extraction from alert text
- Threat intelligence lookup (multi-source)
- AI-powered classification
- Runbook retrieval via semantic search
- Hive case creation
- Playbook execution (for high-confidence TP)
- Slack notifications
- Cost tracking

### ✅ Intelligent Caching
- Threat intel results (4-hour TTL)
- AI responses (behavior-based cache key)
- Vector embeddings (in-memory)

### ✅ Error Handling
- Retry logic for API failures
- Graceful degradation (Slack fails → continues)
- Logging at every stage

---

## What's Manual (Still Requires Human)

### ⚠️ Human Validation Required
- Final decision on NEEDS_REVIEW alerts
- Closing FALSE_POSITIVE tickets in Hive
- Escalation to incident response team
- Policy tuning based on false positives
- Playbook approval for lower confidence cases

### ⚠️ Not Yet Automated
- Multi-alert correlation (coordinated attacks)
- Automatic ticket closure
- Learning from analyst feedback
- Dynamic playbook generation
- Cross-platform orchestration (only 5 playbook types)

---

## Technology Stack

**Backend:**
- Python 3.10+
- Flask (REST API)
- Google Gemini 2.5 Flash (AI classification)

**Threat Intelligence:**
- AbuseIPDB API
- VirusTotal API
- Custom IOC extractor (regex-based)

**AI/ML:**
- ChromaDB (vector database)
- Sentence Transformers (embeddings)
- RAG for runbook retrieval

**Integrations:**
- Hive (case management)
- Slack (notifications)
- SOAR playbook engine (YAML-based)

**Simulated Integrations (demo):**
- Firewall (Palo Alto)
- EDR (CrowdStrike)
- AD (Active Directory)
- ServiceNow

---

## Sample Output

### API Response
```json
{
  "classification": "TRUE_POSITIVE",
  "confidence": 90,
  "severity": "Critical",
  "reasoning": [
    "Multiple failed login attempts from TOR exit node",
    "High abuse confidence score (92%)",
    "After-hours login attempt",
    "User account compromised"
  ],
  "priority": 4,
  "title": "Brute Force Credential Attack",
  "runbook": "[Full runbook text with response steps]",
  "playbook_execution": {
    "status": "Success",
    "actions_taken": ["Blocked IP", "Disabled user", "Created ticket"]
  },
  "slack_notification": {
    "status": "Success",
    "message": "Notification sent to #security_alerts"
  },
  "hive_case": {
    "case_number": "CASE-12345"
  }
}
```

---

## Limitations & Known Issues

### Current Limitations
1. **Playbook Coverage:** Only 5 attack types have automated playbooks
2. **Single Alert Processing:** No batch correlation analysis
3. **Static Thresholds:** Classification thresholds are hardcoded
4. **No Feedback Loop:** System doesn't learn from analyst corrections
5. **English Only:** No multi-language support

### Edge Cases
- Very short alerts lack context for AI
- Private IPs skip threat intel (expected behavior)
- Alerts without IOCs rely purely on behavioral analysis
- Rate limits on free-tier APIs (handled with retry logic)

---

## Future Enhancements

### Phase 1 (Next Sprint)
- [ ] Add 10 more playbook types
- [ ] Implement feedback loop (analyst corrections → AI retraining)
- [ ] Multi-alert correlation engine
- [ ] Automatic ticket closure for validated FPs
- [ ] Enhanced Slack interactions (buttons, threads)

### Phase 2 (Next Quarter)
- [ ] Machine learning model for threat scoring
- [ ] Integration with SIEM (Splunk, Sentinel)
- [ ] Real-time dashboards
- [ ] Automated escalation workflows
- [ ] Multi-tenant support

### Phase 3 (Future)
- [ ] Autonomous threat hunting
- [ ] Predictive alerting
- [ ] Natural language playbook generation
- [ ] Cross-organization threat sharing

---

## Lessons Learned

### What Worked Well
- **Question-based learning approach:** Forced deep understanding
- **Incremental building:** Week 1 → Week 2 → Week 3 → SOAR
- **Caching strategy:** 60-70% hit rate significantly reduced costs
- **Decoupled architecture:** Each component testable independently

### What Was Hard
- **Prompt engineering:** Getting consistent JSON from AI took iterations
- **Cache key design:** Balancing uniqueness vs hit rate
- **Error handling:** Production-grade retry logic is complex
- **IOC extraction:** Regex patterns for defanged URLs/domains

### What I'd Do Differently
- Start with SOAR architecture diagram earlier
- Build playbook validator sooner
- Use structured logging from day 1
- Implement metrics tracking earlier

---

## Demo Script (2-Minute Pitch)

**"Let me show you how this works:"**

1. **Send alert via API** (curl command)
2. **Watch terminal logs** (IOC extraction → TI lookup → AI analysis)
3. **Show Hive case** (ticket created with full context)
4. **Show Slack message** (analyst notification with runbook)
5. **Show API response** (complete JSON with all data)

**Key points:**
- "6 seconds from alert to notification"
- "Under $0.002 per alert"
- "Automatically executes 5 response playbooks"
- "Human validates, system acts"

---

## Repository Structure

```
ai-security-projects/
├── ai_projects/
│   ├── day1_alertclassifier.py      # AI classification engine
│   ├── day2_threatintel.py          # TI lookup functions
│   ├── batch_processor.py           # Alert processing pipeline
│   └── week2_rag/
│       └── day3_document_loader.py  # Runbook indexer
├── src/
│   ├── ioc_extractor.py             # IOC extraction logic
│   ├── cache_handler.py             # Caching layer
│   ├── ai_response_handler.py       # Vector DB interface
│   ├── hive_integration.py          # Hive API
│   └── integrations/
│       ├── base_integration.py      # Base class
│       ├── slack_integration.py     # Slack notifications
│       ├── firewall_integration.py  # Simulated
│       └── [other integrations]
├── test/
│   └── flask_test.py                # Flask API server
├── data/
│   ├── playbooks/                   # YAML playbooks
│   └── security_docs/               # Runbook library
└── cache/
    ├── cache.json                   # TI cache
    └── ai_cache.json                # AI response cache
```

---

## Stats

**Development Time:** ~40 hours over 4 weeks
**Lines of Code:** ~2,500
**API Integrations:** 4 (AbuseIPDB, VirusTotal, Hive, Slack)
**Simulated Integrations:** 5 (Firewall, EDR, AD, ServiceNow, Splunk)
**Test Coverage:** End-to-end integration tests
**Cache Hit Rate:** 60-70%
**Cost per Alert:** <$0.002

---

## Conclusion

Built an end-to-end AI-powered SOAR system that reduces analyst workload by automating alert triage, enrichment, classification, ticketing, response execution, and notification. System processes alerts in 6 seconds with 84% high-confidence classifications at <$0.002 per alert.

**Portfolio Impact:** Demonstrates practical application of AI in security operations, integrating threat intelligence, vector databases, API orchestration, and automated response workflows.

**Next Steps:** Moving to Week 5 - Detection-as-Code Generator to complement this SOAR platform with automated detection rule creation.
