# Day 1 Results - AI Alert Triage System

## What I Built
- Gemini-powered alert classification system
- JSON parsing with regex
- Tested on 3 different alert scenarios

## Test Results

### Test 1: Clear Attack (Moscow, RU)
- Alert: alice@company.com, 185.220.101.52, 8 failed logins at 02:00
- Expected: TRUE_POSITIVE
- AI Classification: [TRUE_POSITIVE]
- Confidence: [95]%
- Reasoning: [This alert presents multiple strong indicators of a compromised account. Eight failed login attempts followed by a successful login from a new IP is a classic sign of a brute-force or credential-stuffing attack succeeding. The activity occurring at 02:00 AM (outside typical working hours) further increases suspicion. Most critically, the IP location being Moscow, RU, is a significant geographical anomaly for an average corporate user named 'Alice' and points to unauthorized access from an unexpected region. The combination of these factors strongly indicates a successful account compromise.]
- Match: ✅ YES 

### Test 2: Normal Admin (New York, US)
- Alert: admin@company.com, 10.50.1.100, 2 failed logins at 09:00
- Expected: FALSE_POSITIVE
- AI Classification: [FALSE_POSITIVE]
- Confidence: [90]%
- Reasoning: [A successful login by an admin user after two failed attempts from an internal IP address within the company network during working hours is likely a case of a mistyped password and not a security incident. It is typical behaviour to misstype your password.]
- Match: ✅ YES 

### Test 3: Unclear Case (London, UK)
- Alert: bob@company.com, 203.0.113.50, 4 failed logins at 18:30
- Expected: NEEDS_REVIEW
- AI Classification: [NEEDS_REVIEW]
- Confidence: [70]%
- Reasoning: [Four failed login attempts followed by a successful login from London, UK. This could be a user struggling to remember their password or a successful brute-force attack. Requires further investigation to determine if the IP location is normal for the user and if there are any other anomalous activities associated with the account.]
- Match: ✅ YES

## Accuracy
- Correct classifications: 3/3
- Average confidence: 85X%
- Most confident: [Clear Attack]
- Least confident: [Unclear Case]

## What I Learned

### Technical Skills
- How to structure prompts for security analysis
- JSON parsing with regex (re.DOTALL flag important!)
- Gemini API integration
- Error handling patterns

### Hardest Part
[What took longest? What was confusing?]
Regex took the longest as i am starting new here.The most confusing aspect was all the json strings and regex

### Biggest Breakthrough
[What clicked? What made sense?]


### Surprises
[What surprised you about AI's reasoning?]
the reasoning went far beyong  just country and into time of activity too. It was what was good
[Did it catch something you didn't expect?]
nope.
## Code Improvements Needed

### What Works Well
- Clean function separation
- Error handling present
- Prompt structure is clear

### What Could Be Better
- Add retry logic for API failures
- Add cost/token tracking
- Better error messages (which step failed?)
- Add timestamp to results

## Next Steps (Day 2)

**Enhancements to add:**
1. Threat intel integration (AbuseIPDB, VirusTotal)
2. User behavior baseline context
3. Batch processing (multiple alerts at once)
4. Better prompt engineering (more context = better decisions)
5. Cost tracking per alert

**Questions for Day 2:**
- How do I add threat intel without making prompt too long?
- Should I cache repeated IP lookups?
- How do I handle alerts where IP lookup fails?