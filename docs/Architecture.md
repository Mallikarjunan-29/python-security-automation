## Learning Resources Review

1. Idea backlog from entire team for scenarios which can be created as rule.
2. Prioritize the ideas one at a time
3. Determine if the same can be implemented with available log sources
4. Every smaller chunk in a CI/CD is a v model


#### **Q1: What are the 4 stages of generating a detection rule?**
Think about how a human detection engineer works:
- What do they do first when asked to write a detection rule?
- What comes after understanding the requirement?
- What happens before the rule goes to production?
- What documentation is needed?

**Resource 1 - Watch (10 min):**
- Search for: "detection engineering workflow tutorial" or "writing SIEM detection rules"
- Focus on: What steps do they follow? What questions do they ask?

**Resource 2 - Read (10 min):**
- Search for: "detection as code blog post" or "KQL detection rule examples"
- Focus on: How do they structure rules? What makes a good detection?

**Resource 3 - Review (10 min):**
- Search for: "MITRE ATT&CK detection examples"
- Focus on: How do professionals map detections to techniques?

**Take notes on what you observe:**
```
What I learned about detection engineering workflow:
1. Idea backlog from entire team for scenarios which can be created as rule.
2. Prioritize the ideas one at a time
3. Determine if the same can be implemented with available log sources

```
Stage 1: 
        - Requirement and threat understanding
            - Define what attack behaviour is being detected
            - Identify the MITRE technique, risk, business impact
            - Identify the data sources for the rule
Stage 2:
        - Rule Authoring & Logic design
            - Write rule logic
            - Decide on detection thresholds
            - validate the log sources/ log fields availability
            - write the correlation logic(if needed)
Stage 3:
        - Testing, Validation and Tuning
            - Test with existing logs
            - Test with simulated attack data
            - Reduce false positives and optimize performance
            - peer review
Stage 4:
        - Deplyment, Documentation and maintenance
            - Document rule (Purpose, Logic, MITRE, data sources, test cases)
            - Deploy it in production
            - Confugure alert routing
            - Versioning and ongoing maintenance

#### **Q2: What information is REQUIRED vs OPTIONAL to write a detection rule?**

**Scenario:** Someone says "Detect brute force"

What questions MUST you ask? What's nice-to-have?

**Write your answer:**
```
REQUIRED (Can't write rule without this):
1. Which log source is used (AD, Okta, VPN, Linux, O365)?
2. What fields are available (username, src_ip, status)?
3. What is the threshold?
4. What is the time frame?
5. What counts as brute force: fails only, or fail+success?
6. What entity is being brute forced (user, endpoint, service)?

OPTIONAL (Improves rule but not critical):
1. Different thresholds for privileged / admin accounts
2. Should repeated alerts be suppressed for same user/IP?
3. Exclusions (service accounts, scanners, test users)
4. Geo/context-based enhancements (IP reputation, MFA failures)
5. Correlations or enrichment

```

---

#### **Q3: How should agents collaborate?**

You have 4 agents: Planner, Coder, Tester, Documenter

**Which execution pattern makes sense?**

Option A: Sequential (Planner → Coder → Tester → Documenter)
Option B: Parallel (All run at once)
Option C: Hybrid (Some sequential, some parallel)

**Write your answer with reasoning:**
```
I choose: [Option A/B/C]

Reasoning:
I choose Option c

Execution flow:
A detection rule is built incrementally. Every small change—whether adding the 
base query, adding the threshold logic, or adding the time window—is checked in 
separately. The Tester validates each increment independently and gives step-level 
sign-off. The Documenter records each change as it happens. Once all increments 
pass their tests, the final end-to-end test is executed and the rule receives 
final approval and is deployed through CI/CD.
```

---

#### **Q4: What could go wrong and how do you handle it?**

**For each scenario, write your handling strategy:**

Scenario 1: AI generates invalid KQL syntax
→ Catch the exception and return a structured error message showing the exact
  syntax issue, line/column, and provide suggested corrections.

Scenario 2: User input is too vague ("detect attacks")
→ Return a structured requirement request asking for:
  - exact behavior to detect
  - log sources available
  - required fields
  - thresholds/time windows
  - scope exclusions
  This forces clarity before proceeding.

Scenario 3: Rule is syntactically correct but logically wrong
→ Not an error — it's an input quality issue. Flag logical risks, suggest
  baseline-aligned thresholds, and request refined requirements.

Scenario 4: Gemini API times out
→ Use rate limiting and exponential backoff with max retries. If still failing,
  return a structured timeout message with the failing step and recommended actions.


---

#### **Q5: Design the data flow between agents**

**What does each agent receive as input and produce as output?**

```
1. Planner Agent

Input:

Plain text requirement from the user or a structured dictionary

Output:

Structured dictionary containing:

Requirement description

Data sources

Fields needed

Thresholds / time window (if provided)

MITRE mapping

Optional additional metadata

Notes:

Output dictionary is designed to be easily consumed by the Coder agent.

2. Coder Agent

Input:

Requirement dictionary from Planner

Includes: numerical thresholds, time thresholds, output fields, data sources

Output:

Detection rule query/code in the required language:

KQL, SPL, Sigma, or other structured query

Includes thresholds, filters, and exceptions as defined

3. Tester Agent

Input:

Query or detection logic produced by Coder

Optional: test harness or synthetic data

Output:

Structured JSON containing:

Test case ID

Test case description

Status (Pass / Fail)

Failure message or logs if failed

Notes:

Provides step-level sign-off

Feedback loop to Coder if any test fails

4. Documenter Agent

Input:

From Planner: requirement dictionary

From Coder: the actual query/detection logic

From Tester: step-level sign-off and final sign-off

Output:

Plain text or structured document ready for conversion to a file

Includes:

Requirement

Rule logic

Thresholds

Test cases and results

MITRE mapping

Version history

Notes:

Documenter can capture incremental updates but final document is only produced after final Tester sign-off
```

## Learning Resources Review
[Summary of what you learned from the 3 resources]

## 1. Rule Generation Stages
[Your answer to Q1 - grounded in real examples]

## 2. Required vs Optional Information
[Your answer to Q2]

## 3. Agent Collaboration Pattern
[Your answer to Q3]

## 4. Error Handling Strategies
[Your answer to Q4]

## 5. Data Flow Between Agents
[Your answer to Q5]

## System Diagram
```
               ┌───────────────┐
               │   User Input  │
               └───────┬───────┘
                       │
                       ▼
               ┌───────────────┐
               │  Planner      │
               │ - Requirement │
               │ - Data Source │
               │ - Thresholds  │
               └───────┬───────┘
                       │
                       ▼
               ┌───────────────┐
               │   Coder       │
               │ - Build query │
               │ - Apply       │
               │   thresholds  │
               │ - Apply time  │
               └───────┬───────┘
                       │
                       ▼
               ┌───────────────┐
               │   Tester      │
               │ - Run tests   │
               │ - Step signoff│
               │ - Feedback →  │
               │   Coder       │
               └───────┬───────┘
                       │
      ┌────────────────┴────────────────┐
      │                                 │
      ▼                                 ▼
┌───────────────┐                ┌───────────────┐
│   Documenter  │                │  Feedback     │
│ - Draft docs  │                │  Loops to     │
│ - Incremental │<───────────────┤  Planner /    │
│   commits     │                │  Coder        │
│ - Final doc   │                └───────────────┘
└───────┬───────┘
        │
        ▼
┌───────────────┐
│   CI/CD       │
│ - Integrate   │
│ - Validate    │
│ - Deploy      │
└───────────────┘
        │
        ▼
┌───────────────┐
│   Production  │
│   SOC Alerts  │
└───────────────┘

```

## Tech Stack Decisions
- LangGraph for: 
        - LangGraph will serve as an orchestrator handling, controls, retries,parallel processing and state mangement of different nodes of the detection as code module
- Gemini 2.5 for: Gemini 2.5 Flash 0 lite offer higher RTM and RPD
- Storage: Chroma DB using persistent client
- Validation: [How do you validate syntax?]
```