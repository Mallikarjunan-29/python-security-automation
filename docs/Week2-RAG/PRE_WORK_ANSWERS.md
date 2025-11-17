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
yamlname: brute_force_investigation

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