# Section A: SOAR Fundamentals
Q1: What does SOAR stand for and what does each component mean?

S = Security
O = Orchestration
A = Automated
R = Response

Q2: What's the difference between SIEM and SOAR?

SIEM does: 
    SIEM is a security engine which correlates data from different log sources to arrive at a conclusion, which in this case is an alert based on predefined criteria(use case)
SOAR does: 
    SOAR is a security engine which takes the output of SIEM as input and executed response actions based on predefined logic(playbooks)
How do they work together?
    SIEM identifies suspicious actions based on rules feeds into SOAR and SOAR executes the responses needed to thwart the suspicious actions identified by SIEM

Q3: What is a playbook in cybersecurity?

    Playbook in cybersecurity is a series of steps that are performed in response to incidents in the environment
Give 3 examples of playbook names
    malicious powershell response playbook
    brute force response playbook
    dll reflection response playbook

Q4: What is orchestration?

Definition:
    Example: Orchestrating a phishing response means taking all the inputs of the alert, enriching the alert with all necessary intel, arrive at a conclusion to execute a response

Q5: Why use YAML for playbooks instead of Python code? List 3 advantages List 1 disadvantage

**3 Advantages of YAML over Python for playbooks**

Human-Readable & Easy to Modify
YAML is simple, clean, and readable even for non-developers. Analysts, L1/L2, or auditors can easily review or edit playbooks.

Declarative Format (No Logic Needed)
Playbooks describe what should happen, not how. This avoids writing Python logic and keeps workflows consistent, structured, and tool-agnostic.

Better Integration With Automation/SOAR Tools
Most SOAR platforms (Splunk SOAR, Demisto, Shuffle, n8n, Ansible) natively support YAML. Tools can parse, validate, version-control, and execute YAML workflows easily.

**1 Disadvantage**

Limited Flexibility for Complex Logic
YAML cannot handle loops, conditionals, or advanced logic — for complex branching workflows you still need Python or an embedded scripting engine.

# Section B: Architecture Planning

Q6: What are the components of a playbook?
```yaml
name: brute_force_investigation

trigger:
  type: alert
  source: SIEM
  condition: "Multiple failed logins followed by a successful login"

steps:
  - name: Enrich User
    action: query_active_directory
    input:
      username: ${alert.user}

  - name: IP Reputation Lookup
    action: threat_intel_lookup
    input:
      ip: ${alert.source_ip}

  - name: Check Host Login Details
    action: query_login_history
    input:
      host: ${alert.destination_ip}
      user: ${alert.user}

  - name: Notify L2 If Suspicious
    action: send_notification
    condition: "ip_reputation.score > 80"
    input:
      user: ${alert.user}
      src_ip: ${alert.source_ip}

integration_tools:
  siem: "QRadar / Splunk / Sentinel"
  edr: "CrowdStrike / Defender / SentinelOne"
  threat_intel: "VirusTotal / OTX / GreyNoise"
  directory: "Active Directory / Azure AD"

output:
  enriched_alert: "user_details + ip_reputation + host_info"
  action_taken: "escalated | closed"
  ticket_id: "Generated in ticketing system"

roles_and_responsibilities:
  L1:
    - Triage alert
    - Run enrichment steps
    - Document findings
  L2:
    - Validate anomalies
    - Make containment decisions
  IR_team:
    - Final remediation
    - Evidence collection

success_criteria:
  - "Alert fully enriched"
  - "Decision made (escalate or close)"
  - "Ticket updated and closed with documented evidence"
  - "No pending investigation steps"

```
Q8: Should playbooks support conditional logic?
Scenario: Only isolate host if confidence > 90%
Option A: Build into executor logic
```python
if result['confidence'] > 90:
    execute_playbook()
    ```
Option B: Put in YAML
```yaml
steps:
  - if: ${confidence} > 90
    action: isolate_host
```
Which approach and why?

    Yes, the conditional logic should be part of runbook.
    The approach should be option B
        - The variables should be declarative and not imperative
        - This way the playbook is platform agnostic and avoids the rework of rewriting the code per vendor
        - Most commercial SOARs have active Yaml integration
        - Makes it more human readable for non programming personnel

Q9: Error handling strategy?
If step 2 fails (block IP at firewall), what should happen?

Stop entire playbook?
Continue with remaining steps?
Configurable per action?

    Configurable per action.
        If the entire playbook is sequential then the playbook execution is halted, an escalation sent to L2
        If the playbook has parallel actions, perform the actions, note down what was successful vs what failed and notify to L2

Q10: How do you pass alert context to actions?
Alert has:
json{
  "host": {"hostname": "WIN-123", "ip": "10.0.1.50"},
  "user": {"email": "alice@company.com"},
  "network": {"source_ip": "185.220.101.52"}
}
Playbook needs to isolate the host. How do you reference it?

${alert.host.hostname}
${hostname}
Pass entire alert?

Your design:
    ${alert.host.hostname}.
    This makes sure that the playbook can directly substitute the value of the  hostname and proceed with isolating, else the entire alert has to be parsed again to get the hostname

# Section C: Integration Design
Q11: What makes a good mock integration?
Rate these mock designs (1-5 stars):
Mock A:
pythondef isolate_host(hostname):
    return True
Rating: ⭐ (?/5)
Why:
Mock B:
pythondef isolate_host(hostname):
    time.sleep(0.5)  # Simulate API latency
    return {"status": "success", "host": hostname}
Rating: ⭐⭐⭐ (?/5)
Why:
Mock C:
pythondef isolate_host(hostname):
    if random.random() < 0.1:
        raise Exception("Network timeout")
    time.sleep(0.5)
    return {
        "status": "success",
        "host": hostname,
        "isolation_id": uuid.uuid4(),
        "timestamp": datetime.now()
    }
Rating: ⭐⭐⭐⭐⭐ (?/5)
Why:
    Mock C is better since it convers the following
        Random Network error
        Latency in API calls
        Proper return format

Q12: Should mocks maintain state?
Scenario:
pythonedr.isolate_host("WIN-123")
edr.get_isolation_status("WIN-123")  # Should return "isolated"?

Yes, mocks should track state
No, just return success
Depends on use case

Your answer:Mock should track state, reason being this simulates the entire workflow as it should happen in actual playbook

Q13: Real API response structure - should mocks match?
CrowdStrike real API returns:
json{
  "meta": {
    "query_time": 0.05,
    "powered_by": "crowdstrike"
  },
  "resources": [{
    "device_id": "abc123",
    "status": "contained"
  }],
  "errors": []
}
    Answer: It should match , then this avoids redoing all the work in real endpoint scenario

Q14: Where do you document "how to make this real"?
You mock CrowdStrike integration. A future developer needs to implement the real API.
    I feel code semantics is better, so that a new developer can just look at the code run the steps, see whats not done and can pick it up from there


# Section D: Splunk Integration Planning
Q15: What Splunk SDK/library will you use?

splunk-sdk (official)
requests to REST API
Other?

for python use official splunk-sdk
for simple queries or cross platform support, REST API

Q16: What actions should your Splunk integration support?
List 3-5 actions that make sense for SOAR:
    Execute Search / Run Saved Search

        Query Splunk for events, alerts, or historical data.

    Submit Event / Ingest Data

        Push alerts, logs, or IOC updates into Splunk via HEC.

    Fetch Search Results

        Retrieve results from a search job (streaming or completed).

    Create / Update Notable Event

        Generate or enrich a notable event in Splunk ES.

    Add Tags / Update Event Fields

        Annotate events or enrich them with context from SOAR.

Q17: How do you authenticate to Splunk?

Username/password
API token
Session key

Your choice and why:

    HEC token
        More secure
        can be scoped with minimal permissions
        easier to rotate and audit

Q18: Splunk search is asynchronous. How do you handle it?
When you create a search, Splunk returns a job ID. Results aren't instant.

    Sequential dependencies: Use synchronous execution.

    Parallelizable workflows or long-running searches: Use async (job ID) → check later.
**Q19: What's a realistic Splunk action for SOAR?**

Alert: Malicious PowerShell detected on host WIN-123

What Splunk search would you create?
check what other powershell activities happened for last 24 hours
    index=windows host="${alert.host} source_type="powershell*" _time>relative_time("${alert._time}","-24h")
check if the same command line got executed in other hosts
    index=windows CommandLine="${alert.command_line}" _time>relative_time("${alert._time}","-24h")

**Q20: Where do you store Splunk credentials?**
- Hardcode in integration file
- Environment variables
- Config file
- Other?

environment variable= safest
config - next to environment variable

**Q21: What's the complete flow?**

Number these steps in correct order:
- [5] Execute action on integration
- [4] Parse YAML playbook
- [7] Return execution summary
- [2] Classify alert with AI
- [3] Match alert to playbook
- [1] Enrich with threat intel
- [6] Log action result

**Q22: Who decides which playbook to use?**
- AI classification result
- Manual analyst selection
- Rule-based matching (severity + behavior)
- Other?

Classification+severity+behaviour+analyst feedback

**Q23: What if multiple actions fail?**

Playbook has 5 steps:
1. Isolate host ✅
2. Block IP ❌ (firewall timeout)
3. Reset password ✅
4. Create ticket ❌ (ServiceNow down)
5. Send email ✅

What's the overall status?
- Success (3/5 passed)
- Partial Failure
- Failure
- Other categorization?

Partial failure - the SOAR can retry failed nodes


**Q24: Should execution be synchronous or asynchronous?**

User calls `/execute` endpoint.

**Option A: Synchronous**

Request → Execute all actions → Return results (might take 30s)


**Option B: Asynchronous**

Request → Start execution → Return 202 Accepted + execution_id
Separate call: GET /execution/{id}/status

    Answer: Option B

Q25: What should the API response include?
Design the response structure for /execute:
```json
json{
  "response_code": 202,
  "execution_id": "xyz123hser",
  "status": "pending",
  "message": "Playbook execution started"
}
```

Q26: What are the 5 playbooks you need?
Based on your current detections, list 5 attack scenarios:

Brute Force
Lateral Movement
Network Scanning
Malware Infection
Phishing

Q27: What triggers each playbook?
For each attack type above, define trigger conditions:
```yaml
# Example:
trigger:
  classification: TRUE_POSITIVE
  severity: Critical
  behavior: malicious_powershell
```

```yaml
trigger:
  classification: TRUE_POSITIVE
  severity: HIGH
  behaviour: brute_force or multiple_failed_logins
  confidence: >80

```
```yaml
trigger:
  classification: TRUE_POSITIVE
  severity: HIGH
  behaviour: lateral_movement or suspicious_remote_execution
  confidence: >85
```

```yaml
trigger:
  classification: TRUE_POSITIVE
  severity: MEDIUM
  behaviour: port_scan OR high_volume_connection_attempts
  confidence: >75
```

```yaml
trigger:
  classification: TRUE_POSITIVE
  severity: CRITICAL
  behaviour: malicious_process_execution
  confidence: >90
```

```yaml
trigger:
  classification: TRUE_POSITIVE
  severity: HIGH
  behaviour: malicious_email_detected
  confidence: >80
```

Q28: What actions are common across playbooks?
List actions that appear in multiple playbooks:

Action	Appears in Playbooks
Threat Intel Lookup - 	Brute Force, Lateral Movement, Network Scan, Malware
Isolate Host -  Lateral Movement, Malware, Brute Force
Block IP - 	Brute Force, Network Scanning
Reset Password - 	Brute Force, Phishing
Send Notification - 	All 5 playbooks
Create Ticket - 	All 5 playbooks
Query User / Host Info - 	Brute Force, Lateral Movement, Malware, Phishing

Q29: What actions are scenario-specific?
Malicious PowerShell needs:

[Specific action]

Phishing needs:

[Specific action]

Brute Force needs:

[Specific action]
1. Malicious PowerShell (Malware / Endpoint Infection)

Specific actions:

Retrieve full PowerShell command history (query_powershell_history)

Dump running processes / memory for analysis (collect_process_data)

Quarantine / isolate host (isolate_host)

Collect IOC hashes for further correlation (extract_hashes)

These are specific because only endpoint-execution alerts require host-level investigation.

2. Phishing

Specific actions:

Retrieve email metadata (sender, subject, attachments) (fetch_email_headers)

Analyze URLs and attachments via sandbox / threat intel (scan_attachment_url)

Quarantine email in mailbox (move_to_quarantine)

Notify affected user (send_user_alert)

These are specific because phishing deals with emails and user inboxes, not hosts or network traffic.

3. Brute Force

Specific actions:

Query authentication logs / login history (query_login_history)

Lock or reset affected accounts (reset_user_password)

Block source IP in firewall / proxy (block_ip)

Detect failed login patterns over time (analyze_failed_logins)

These are specific because brute force is user-account focused, not malware or email-based.


Q30: Should metadata be included in playbooks?
yes
```yaml
metadata:
  author: "Security Team"
  version: "1.0"
  last_updated: "2025-11-16"
  mitre_techniques: ["T1059.001", "T1105"]
  description: "Investigates malicious PowerShell execution on endpoints."
  tags: ["malware", "endpoint", "powershell"]
```

Q31: What should the parser do?
Check all that apply:

 [✔] Read YAML file  
[✔] Validate YAML structure  
[✔] Validate required fields exist  
[✔] Validate field types  
[✔] Resolve ${alert.field} variables  
[✔] Validate each step (action/platform/input)  
[✔] Verify referenced alert fields exist  
[✔] Build execution graph  
[✔] Normalize action names  
[✔] Apply default values  
[✔] Validate integrations exist  
[✔] Pre-compile conditions  
[✔] Produce structured playbook object for executor  


Q32: What happens if YAML is invalid?
Scenario: malicious_powershell.yaml has syntax error
Option A: Crash with exception
Option B: Log error, skip playbook
Option C: Return error object with details

Your choice:
     Return structured error object (Option C)

This enables:

UI to show “Playbook validation failed”

CICD pipelines (GitOps) to detect broken YAML before deployment

Logging and alerting

Clear feedback to developers


Q33: Should parsing happen at startup or on-demand?
Option A: Startup
python# When Flask starts:
playbooks = load_all_playbooks()  # Parse all 5 YAMLs once
Option B: On-demand
python# When executing:
playbook = load_playbook("malicious_powershell.yaml")  # Parse when needed
Which for MVP?

Option	Pros	Cons
Startup	- All playbooks loaded into memory
- Fast execution since already parsed	- Slower startup
- Consumes memory for all playbooks, even rarely used
- Harder to update playbooks without restarting
On-demand ✅	- Only parse when needed
- Lower memory footprint
- Can pick up playbook updates without restarting	- Slight parsing delay on first execution
Why on-demand is ideal for MVP

Webhook triggers typically call one playbook at a time.

No need to pre-load all 5 playbooks.

Simplifies development: you can fix YAMLs live and the next execution uses the latest version.


Alert has:
json{
  "classification": "TRUE_POSITIVE",
  "severity": "High"
}
Does this match? (Classification ✅, Severity ❌)
Your matching logic:

All conditions must match (AND)
Any condition matches (OR)
Weighted scoring?


my alert would also include AI confidence

if the classification is True and confidence > 80 i trigger playbook


if no confidence
then Classification - true positive gets 70
low-10
medium 15
high 20
Critical 25

sum should be greater than 80 this will be confidence
