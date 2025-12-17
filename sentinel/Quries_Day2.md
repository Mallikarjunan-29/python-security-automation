### Day 2: Aggregation & Pattern Detection
**Scenario:** Security team suspects brute force attacks. Find IPs with excessive failed attempts.

**Challenge 2.1: Brute Force Detection**
- Find IPs with >5 failed logins in 5 minutes
- Show: IP, Count, Time Window, Targeted Accounts
- Exclude known service accounts
```KQL
let AllowedAccounts = dynamic(['svc-backup','svc-sql','svc-monitor','svc-web']);
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
        // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
        // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
        // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
        // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
|where EventID ==4625
|extend UserName=split(Account,"\\")[1]
| where UserName !in(AllowedAccounts)
|summarize 
    FailureCount=count(),
    TargettedAccounts=make_set(UserName) ,
    DistinctUserCount=dcount(Account)
    by IpAddress,WindowStart=bin(TimeGenerated,5m)
|extend WindowEnd=WindowStart+5m-1s
|where FailureCount >5 
|project IpAddress,FailureCount,TargettedAccounts,DistinctUserCount,WindowStart,WindowEnd
```
**Brute Force AllowList**
```KQL
let AllowedAccounts = dynamic(['svc-backup','svc-sql','svc-monitor','svc-web']);
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
        // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
        // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
        // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
        // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
|where EventID ==4625
|extend UserName=split(Account,"\\")[1]
| where UserName !in(AllowedAccounts)
|summarize 
    FailureCount=count(),
    TargettedAccounts=make_set(UserName) ,
    DistinctUserCount=dcount(Account)
    by IpAddress,WindowStart=bin(TimeGenerated,5m)
|extend IPRange=ipv4_is_in_any_range(IpAddress,'10.0.1.0/24','10.0.2.0/24','10.0.3.0/24')
|extend IPSelectionCriteria=iff(IPRange,iff(FailureCount >20,1,0),iff(FailureCount >5,1,0))
|extend WindowEnd=WindowStart+5m-1s
|where IPSelectionCriteria == 1 
|project IpAddress,FailureCount,TargettedAccounts,DistinctUserCount,WindowStart,WindowEnd

```
**AllowList Count Included***
```KQL
let AllowedAccounts = dynamic(['svc-backup','svc-sql','svc-monitor','svc-web']);
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
        // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
        // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
        // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
        // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
|where EventID ==4625
|extend UserName=split(Account,"\\")[1]
| where UserName !in(AllowedAccounts)
|summarize 
    FailureCount=count(),
    TargettedAccounts=make_set(UserName) ,
    DistinctUserCount=dcount(Account)
    by IpAddress,WindowStart=bin(TimeGenerated,5m)
|extend IPRange=ipv4_is_in_any_range(IpAddress,'10.0.1.0/24','10.0.2.0/24','10.0.3.0/24')
|extend IPSelectionCriteria=iff(IPRange,iff(FailureCount >20,1,0),iff(FailureCount >5,1,0))
|extend WindowEnd=WindowStart+5m-1s
|where IPSelectionCriteria == 1 
|extend ExcludedAccountCount= array_length(AllowedAccounts)
|project IpAddress,FailureCount,TargettedAccounts,DistinctUserCount,WindowStart,WindowEnd,ExcludedAccountCount,AllowedAccounts
```

**Confidence Scoring**
```KQL
let AllowedAccounts = dynamic(['svc-backup','svc-sql','svc-monitor','svc-web']);
let Score=0;
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
        // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\svc-monitor", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\svc-web", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
        // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
        // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
        // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
let AllEvents = SecurityEvent|where EventID ==4625;
let ServiceAccounts=AllEvents
|extend UserName=split(Account,"\\")[1]
| where UserName in (AllowedAccounts)
| summarize ExcludedServiceAccountCount=dcount(Account),ExcludedServiceAccounts=make_set(Account) by IpAddress;
let RealEvents= AllEvents|extend UserName=split(Account,"\\")[1]| where UserName !in(AllowedAccounts); 
RealEvents
|join kind= leftouter (ServiceAccounts) on IpAddress
|summarize 
    FailureCount=count(),
    TargettedAccounts=make_set(UserName) ,
    DistinctUserCount=dcount(Account),
    ExcludedServiceAccount=any(ExcludedServiceAccountCount),
    ExcludedServiceAccounts=array_concat_array(ExcludedServiceAccounts)
    by IpAddress,WindowStart=bin(TimeGenerated,1m)
|extend IPRange=ipv4_is_in_any_range(IpAddress,'10.0.1.0/24','10.0.2.0/24','10.0.3.0/24')
|extend IPSelectionCriteria=iff(IPRange,iff(FailureCount >5,1,0),iff(FailureCount >2,1,0))
|where IPSelectionCriteria == 1 
|extend Criticality= iff(FailureCount >5,"CRITICAL",iff(FailureCount >4,"HIGH",iff(FailureCount >3,"MEDIUM","LOW")))
|extend ConfidenceScore = case(
                                Criticality =="CRITICAL",100,
                                Criticality=="HIGH",50,
                                Criticality=="MEDIUM",25,
                                0)
|extend ConfidenceScore=ConfidenceScore+iff(DistinctUserCount >2,50,0)
|extend ConfidenceScore=ConfidenceScore+iff(IPRange,0,50)
| extend Hour= hourofday(WindowStart)
|extend  ConfidenceScore=ConfidenceScore+iff(Hour >18 or Hour <8,50,0)
|project IpAddress,FailureCount,TargettedAccounts,DistinctUserCount,Hour,WindowStart,Criticality,ConfidenceScore,ExcludedServiceAccount,ExcludedServiceAccounts

```
**Challenge 2.2: Attack Pattern Analysis**
- Group by 1-hour time bins
- Show attack volume trends
- Identify peak attack hours

*Failed EventCount per hour*
```KQL
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
    // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
    // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
| where EventID ==4625
| extend UserName=split(Account, "\\")[1]
| summarize 
    EventCount=count(),
    TargettedAccounts=make_set(UserName),
    SourceIPs=make_set(IpAddress),
    DistinctUserCount=dcount(Account)
    by WindowStart=bin(TimeGenerated, 1h)
| extend WindowEnd=WindowStart + 1h - 1s
| project-keep WindowStart,EventCount
| sort by EventCount desc 
|render timechart 
```

*Failed EventCount per hour per IP*
```KQL
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
    // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
    // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
| where EventID ==4625
| extend UserName=split(Account, "\\")[1]
| summarize 
    EventCount=count(),
    TargettedAccounts=make_set(UserName),
    SourceIPs=make_set(IpAddress),
    DistinctUserCount=dcount(Account)
    by WindowStart=bin(TimeGenerated, 1h),IpAddress
| extend WindowEnd=WindowStart + 1h - 1s
| project-keep WindowStart,EventCount,IpAddress
| sort by EventCount desc 
|render timechart 

```
*Failed EventCount per hour per User*
```KQL
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
    // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
    // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
| where EventID ==4625
| extend UserName=split(Account, "\\")[1]
| summarize 
    EventCount=count(),
    TargettedAccounts=make_set(UserName),
    SourceIPs=make_set(IpAddress),
    DistinctUserCount=dcount(Account)
    by WindowStart=bin(TimeGenerated, 1h),Account
| extend WindowEnd=WindowStart + 1h - 1s
| project-keep WindowStart,EventCount,Account
| sort by EventCount desc 
|render columnchart  

```

**Challenge 2.3: Targeted Account Discovery**
- Which accounts are most attacked?
- Are they admin accounts?
- What's the geographic distribution of attackers?
```KQL
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
    // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
    // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
| where EventID ==4625
| extend UserName=split(Account, "\\")[1]
| summarize 
    EventCount=count(),
    SourceIPs=make_set(IpAddress)
    by Account
| project-keep EventCount,Account,SourceIPs
| sort by EventCount desc 
  

```
**Identify password spray patterns (multiple accounts, same IP)**
```KQL
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
    // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
    // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
| where EventID ==4625
| extend UserName=split(Account, "\\")[1]
| summarize 
    TargettedAccountCount=dcount(Account),
    FailureCount=count(),
    TargetterdUsers=make_set(UserName)
    by IpAddress
| sort by TargettedAccountCount desc 
| project IpAddress ,TargettedAccountCount,TargetterdUsers,FailureCount


```
**Detect successful logon after multiple failures from same IP**
```KQL
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
    // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
    // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
let Failure = SecurityEvent
| where EventID ==4625
| extend UserName=split(Account, "\\")[1]
| summarize 
    FailureCount=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated),
    FailedUses=make_set(UserName)
    by IpAddress;
| where FailureCount>1
let Success = SecurityEvent
| where EventID ==4624
| extend UserName=split(Account, "\\")[1]
| summarize 
    SuccessCount=count(),
    FirstSuccess=min(TimeGenerated),
    LastSuccess=max(TimeGenerated),
    SucceededUser=make_set(UserName)
    by IpAddress;
Failure
| join  kind = inner (Success)
on IpAddress
|where LastFailure <FirstSuccess
| project IpAddress,FailureCount,LastFailure,FirstSuccess,FailedUses,SucceededUser

```


***Proper Failures before Success***
```KQL
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: string,
    ResultType: string,
    ResultDescription: string,
    AppDisplayName: string,
    DeviceTrustType: string,
    IsInteractive: bool
)[
    // Normal successful logins
    datetime(2025-10-16 08:15:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365", "Hybrid Azure AD joined", true,
    datetime(2025-10-16 08:20:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Azure Portal", "Azure AD joined", true,
    datetime(2025-10-16 09:00:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "0", "Success", "SharePoint", "Compliant", true,    
    // Brute force attack from single IP
    datetime(2025-10-16 10:00:01), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:00:35), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:12), "root@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:45), "administrator@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:20), "sysadmin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:03:30), "admin@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:04:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    // Password spray from different IPs
    datetime(2025-10-16 11:00:00), "alice@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:05:00), "bob@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:10:00), "charlie@company.com", "192.0.2.45", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:15:00), "david@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:20:00), "eve@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    // Legitimate users with occasional failures
    datetime(2025-10-16 12:00:00), "alice@company.com", "203.0.113.50", "New York, US", "50126", "Invalid username or password", "Office 365", "Hybrid Azure AD joined", true,
    datetime(2025-10-16 12:01:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365", "Hybrid Azure AD joined", true,
    // MFA failures
    datetime(2025-10-16 13:00:00), "bob@company.com", "198.51.100.25", "London, UK", "50074", "MFA denied; user declined the authentication", "Azure Portal", "Azure AD joined", true,
    datetime(2025-10-16 13:02:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Azure Portal", "Azure AD joined", true,
    // Suspicious: Success from previously failing IP
    datetime(2025-10-16 14:00:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // More normal activity
    datetime(2025-10-16 15:00:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "0", "Success", "SharePoint", "Compliant", true,
    datetime(2025-10-16 16:00:00), "david@company.com", "203.0.113.75", "New York, US", "0", "Success", "Teams", "Compliant", true,
    datetime(2025-10-16 17:00:00), "eve@company.com", "198.51.100.88", "London, UK", "0", "Success", "OneDrive", "Azure AD joined", true
];
let Failure=SigninLogs
|where ResultType  <>0 
|summarize FailureCount=count(),FirstFailure=min(TimeGenerated),LastFailure=max(TimeGenerated),FailureNames=make_set(UserPrincipalName),FailureTimes=make_list(TimeGenerated) by IPAddress;
let Success=SigninLogs
|where ResultType  ==0 
|summarize SuccessCount=count(),arg_min(TimeGenerated,*) by IPAddress;
Success
|join kind =inner(Failure)
on IPAddress
| mv-apply FailureTimes to typeof(datetime) on (
    where TimeGenerated > FailureTimes
    |summarize FailureBeforeSuccess=count() by IPAddress
)
|where FailureBeforeSuccess >3
|project FailureBeforeSuccess, IPAddress,TimeGenerated,LastFailure,SuccessCount,FailureCount,UserPrincipalName,FailureNames
```

```SPL
| inputlookup signinlogs.csv
| eventstats 
        min(eval(if (Result=="Success",_time,null()))) as FirstSuccess,
        list(eval(if (Result=="Success",User,null()))) as SuccessUsers,
        list(eval(if (Result=="Success",_time,null()))) as SuccessTimes,
        by IP
| where Result=="Fail" and _time < FirstSuccess
| stats count as Failurecount,
        list(User) as FailedUsers ,
        list(_time) as FailedTimes
        min(_time) as FirstFailure,
        max(_time) as LastFailure,
        values(FirstSuccess) as FirstSuccess,
        values(SuccessUsers) as SuccessUsers,
        values(SuccessTimes) as SuccessTimes,
        by IP
| where Failurecount>=3
```

**Find accounts logging into multiple servers quickly (lateral movement)**
```KQL
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
    // Normal logons
    datetime(2025-10-16 08:00:00), "WKS-001", "CORP\\alice", 4624, "An account was successfully logged on", "203.0.113.50", 10, "Success",
    datetime(2025-10-16 08:05:00), "WKS-002", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", 10, "Success",
    datetime(2025-10-16 08:10:00), "SRV-DC01", "CORP\\admin", 4624, "An account was successfully logged on", "10.0.1.100", 3, "Success",
    // Brute force attack - rapid failures then success
    datetime(2025-10-16 10:00:01), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:15), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:29), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:44), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:00:58), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:12), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:27), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:41), "SRV-WEB01", "CORP\\administrator", 4625, "An account failed to log on", "185.220.101.52", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 10:01:55), "SRV-WEB01", "CORP\\admin", 4624, "An account was successfully logged on", "185.220.101.52", 3, "Success",
    // Password spray - Different accounts, same IP, spread over time
    datetime(2025-10-16 11:00:00), "SRV-FILE01", "CORP\\alice", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:15:00), "SRV-FILE01", "CORP\\bob", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:30:00), "SRV-FILE01", "CORP\\charlie", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 11:45:00), "SRV-FILE01", "CORP\\david", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:00:00), "SRV-FILE01", "CORP\\eve", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",
    datetime(2025-10-16 12:15:00), "SRV-FILE01", "CORP\\frank", 4625, "An account failed to log on", "203.0.113.9", 3, "0xC000006D - Bad username or password",    
    // Service account with legitimate retries
    datetime(2025-10-16 13:00:00), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:00:30), "SRV-SQL01", "CORP\\svc-backup", 4625, "An account failed to log on", "10.0.1.150", 5, "0xC000006D - Bad username or password",
    datetime(2025-10-16 13:01:00), "SRV-SQL01", "CORP\\svc-backup", 4624, "An account was successfully logged on", "10.0.1.150", 5, "Success",
    // Lateral movement indicators
    datetime(2025-10-16 14:00:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:02:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:04:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    datetime(2025-10-16 14:06:00), "SRV-APP01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.1.200", 3, "Success",
    // More normal activity
    datetime(2025-10-16 15:00:00), "WKS-003", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", 10, "Success",
    datetime(2025-10-16 16:00:00), "WKS-004", "CORP\\david", 4624, "An account was successfully logged on", "203.0.113.75", 10, "Success"
];
SecurityEvent
| where EventID == 4624
| summarize 
    HostCount=dcount(Computer),
    SourceIPs=make_set(IpAddress),
    TargettedHosts=make_set(Computer),
    TimeStamps=make_list(TimeGenerated)
    by Account
| where HostCount >1


```
**Bonus Challenge 2**
```KQL
let AdminAccounts=dynamic(["admin","administrator","root"]);
let RiskWeight=dynamic({"HighFailureCount":20,"MultiMachine":30,"CritialAsset":40,"Critical":75,"High":50,"Medium":25,"HighTimeVelocity":50});
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IpAddress: string,
    LogonType: int,
    Status: string
)[
// ----------------- BASELINE: Oct 13-19, 2025 (typical/user baselines) -----------------
datetime(2025-10-13 08:05:00), "SRV-DB01", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-13 09:12:00), "SRV-WEB02", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-13 11:00:00), "SRV-APP05", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-14 07:45:00), "SRV-DB02", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-15 10:30:00), "SRV-LOG01", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-16 14:20:00), "SRV-OPS01", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-17 16:10:00), "SRV-BACK01", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-18 09:00:00), "SRV-MON01", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-19 08:55:00), "SRV-DNS01", "CORP\\it_admin_alan", 4624, "An account was successfully logged on", "10.0.1.10", 3, "Success",
datetime(2025-10-13 08:20:00), "SRV-DB01", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
datetime(2025-10-13 09:55:00), "SRV-WEB01", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
datetime(2025-10-14 10:05:00), "SRV-APP02", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
datetime(2025-10-15 13:30:00), "SRV-OPS02", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
datetime(2025-10-16 15:30:00), "SRV-LOG02", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
datetime(2025-10-17 07:50:00), "SRV-BACK02", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
datetime(2025-10-18 11:45:00), "SRV-MON02", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
datetime(2025-10-19 08:30:00), "SRV-DNS02", "CORP\\admin_beth", 4624, "An account was successfully logged on", "10.0.1.11", 3, "Success",
// three multi-device users (laptop + desktop + conf room pc)
datetime(2025-10-13 08:00:00), "WKS-LAP-ALICE", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.2.21", 10, "Success",
datetime(2025-10-14 08:02:00), "WKS-DESK-ALICE", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.2.21", 10, "Success",
datetime(2025-10-15 09:30:00), "CR-ROOM-01", "CORP\\alice", 4624, "An account was successfully logged on", "10.0.2.21", 10, "Success",
datetime(2025-10-13 09:10:00), "WKS-LAP-BOB", "CORP\\bob", 4624, "An account was successfully logged on", "10.0.2.22", 10, "Success",
datetime(2025-10-14 09:13:00), "WKS-DESK-BOB", "CORP\\bob", 4624, "An account was successfully logged on", "10.0.2.22", 10, "Success",
datetime(2025-10-15 10:00:00), "CR-ROOM-02", "CORP\\bob", 4624, "An account was successfully logged on", "10.0.2.22", 10, "Success",
datetime(2025-10-13 07:45:00), "WKS-LAP-CHARLIE", "CORP\\charlie", 4624, "An account was successfully logged on", "10.0.2.23", 10, "Success",
datetime(2025-10-15 08:01:00), "WKS-DESK-CHARLIE", "CORP\\charlie", 4624, "An account was successfully logged on", "10.0.2.23", 10, "Success",
datetime(2025-10-18 11:20:00), "CR-ROOM-03", "CORP\\charlie", 4624, "An account was successfully logged on", "10.0.2.23", 10, "Success",
// regular users: typically 1-3 machines over week
datetime(2025-10-13 08:10:00), "WKS-101", "CORP\\david", 4624, "An account was successfully logged on", "10.0.2.31", 10, "Success",
datetime(2025-10-14 08:12:00), "WKS-101", "CORP\\david", 4624, "An account was successfully logged on", "10.0.2.31", 10, "Success",
datetime(2025-10-15 08:15:00), "WKS-101", "CORP\\david", 4624, "An account was successfully logged on", "10.0.2.31", 10, "Success",
datetime(2025-10-13 09:00:00), "WKS-102", "CORP\\emma", 4624, "An account was successfully logged on", "10.0.2.32", 10, "Success",
datetime(2025-10-16 09:05:00), "WKS-102", "CORP\\emma", 4624, "An account was successfully logged on", "10.0.2.32", 10, "Success",
datetime(2025-10-14 09:30:00), "WKS-103", "CORP\\frank", 4624, "An account was successfully logged on", "10.0.2.33", 10, "Success",
datetime(2025-10-18 09:35:00), "WKS-103", "CORP\\frank", 4624, "An account was successfully logged on", "10.0.2.33", 10, "Success",
// other normal users (a few examples)
datetime(2025-10-13 10:00:00), "WKS-201", "CORP\\gina", 4624, "An account was successfully logged on", "10.0.2.41", 10, "Success",
datetime(2025-10-14 10:05:00), "WKS-201", "CORP\\gina", 4624, "An account was successfully logged on", "10.0.2.41", 10, "Success",
datetime(2025-10-15 10:10:00), "WKS-202", "CORP\\harry", 4624, "An account was successfully logged on", "10.0.2.42", 10, "Success",
datetime(2025-10-16 10:15:00), "WKS-203", "CORP\\irene", 4624, "An account was successfully logged on", "10.0.2.43", 10, "Success",
datetime(2025-10-17 10:20:00), "WKS-201", "CORP\\gina", 4624, "An account was successfully logged on", "10.0.2.41", 10, "Success",
// ---------- ADMINs (more examples) ----------
// admins regularly touching many servers (10-15 different hostnames over week)
datetime(2025-10-13 07:30:00), "SRV-SEC01", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
datetime(2025-10-13 12:20:00), "SRV-DB03", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
datetime(2025-10-14 09:40:00), "SRV-WEB03", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
datetime(2025-10-15 14:00:00), "SRV-APP03", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
datetime(2025-10-16 16:30:00), "SRV-OPS03", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
datetime(2025-10-17 11:10:00), "SRV-BACK03", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
datetime(2025-10-18 13:20:00), "SRV-MON03", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
datetime(2025-10-19 09:00:00), "SRV-DNS03", "CORP\\sec_admin_carl", 4624, "An account was successfully logged on", "10.0.1.12", 3, "Success",
// ---------- TWO ACTUAL LATERAL MOVEMENT CASES (malicious) ----------
// Malicious actor 1: jdoe — normally touches 1 workstation during baseline (low), but TODAY
// Oct 20 — fast jumps: 4 different machines in ~5 minutes (CRITICAL)
datetime(2025-10-13 08:15:00), "WKS-301", "CORP\\jdoe", 4624, "An account was successfully logged on", "10.0.2.51", 10, "Success",
datetime(2025-10-14 08:12:00), "WKS-301", "CORP\\jdoe", 4624, "An account was successfully logged on", "10.0.2.51", 10, "Success",
datetime(2025-10-15 08:10:00), "WKS-301", "CORP\\jdoe", 4624, "An account was successfully logged on", "10.0.2.51", 10, "Success",
// TODAY: rapid lateral movement across *new* machines
datetime(2025-10-20 00:50:00), "SRV-WEB10", "CORP\\jdoe", 4624, "An account was successfully logged on", "192.168.10.50", 3, "Success",
datetime(2025-10-20 00:52:00), "SRV-APP10", "CORP\\jdoe", 4624, "An account was successfully logged on", "192.168.10.50", 3, "Success",
datetime(2025-10-20 00:54:00), "SRV-FILE10", "CORP\\jdoe", 4624, "An account was successfully logged on", "192.168.10.50", 3, "Success",
datetime(2025-10-20 00:55:00), "WKS-999", "CORP\\jdoe", 4624, "An account was successfully logged on", "192.168.10.50", 3, "Success",
// Malicious actor 2: msmith — baseline accesses 1-2 hosts only; TODAY does 4 machines within 1 hour (HIGH)
datetime(2025-10-13 09:00:00), "WKS-401", "CORP\\msmith", 4624, "An account was successfully logged on", "10.0.2.61", 10, "Success",
datetime(2025-10-15 09:10:00), "WKS-401", "CORP\\msmith", 4624, "An account was successfully logged on", "10.0.2.61", 10, "Success",
datetime(2025-10-20 02:00:00), "SRV-APP20", "CORP\\msmith", 4624, "An account was successfully logged on", "192.168.20.100", 3, "Success",
datetime(2025-10-20 02:20:00), "SRV-FILE20", "CORP\\msmith", 4624, "An account was successfully logged on", "192.168.20.100", 3, "Success",
datetime(2025-10-20 02:40:00), "SRV-DB20", "CORP\\msmith", 4624, "An account was successfully logged on", "192.168.20.100", 3, "Success",
datetime(2025-10-20 02:59:00), "WKS-777", "CORP\\msmith", 4624, "An account was successfully logged on", "192.168.20.100", 3, "Success",
// ---------- A FEW AMBIGUOUS CASES (to test >2x machine count logic) ----------
// user who normally touches 2 machines, today touches 5 (should alert if >2x)
datetime(2025-10-13 09:05:00), "WKS-501", "CORP\\nina", 4624, "An account was successfully logged on", "10.0.2.71", 10, "Success",
datetime(2025-10-14 09:08:00), "WKS-502", "CORP\\nina", 4624, "An account was successfully logged on", "10.0.2.71", 10, "Success",
datetime(2025-10-20 03:00:00), "WKS-501", "CORP\\nina", 4624, "An account was successfully logged on", "10.0.2.71", 10, "Success",
datetime(2025-10-20 03:12:00), "WKS-502", "CORP\\nina", 4624, "An account was successfully logged on", "10.0.2.71", 10, "Success",
datetime(2025-10-20 03:24:00), "SRV-APPS-NEW", "CORP\\nina", 4624, "An account was successfully logged on", "10.0.2.71", 3, "Success",
datetime(2025-10-20 03:36:00), "WKS-503", "CORP\\nina", 4624, "An account was successfully logged on", "10.0.2.71", 10, "Success",
datetime(2025-10-20 03:48:00), "WKS-504", "CORP\\nina", 4624, "An account was successfully logged on", "10.0.2.71", 10, "Success",
// user who normally touches 1 machine, today touches 3 (below 2x threshold; no alert)
datetime(2025-10-13 08:30:00), "WKS-601", "CORP\\oliver", 4624, "An account was successfully logged on", "10.0.2.81", 10, "Success",
datetime(2025-10-20 04:00:00), "WKS-601", "CORP\\oliver", 4624, "An account was successfully logged on", "10.0.2.81", 10, "Success",
datetime(2025-10-20 08:30:00), "WKS-602", "CORP\\oliver", 4624, "An account was successfully logged on", "10.0.2.81", 10, "Success",
// ---------- Admin edge case: admin who accesses >20 machines TODAY (should alert per rule) ----------
datetime(2025-10-13 08:00:00), "SRV-0001", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-14 08:30:00), "SRV-0002", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-15 09:00:00), "SRV-0003", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
// TODAY: many different machines ( >20 ) — server + non-server mixed
datetime(2025-10-20 00:05:00), "SRV-010", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 00:10:00), "SRV-011", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 00:15:00), "SRV-012", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 00:20:00), "SRV-013", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 00:25:00), "SRV-014", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 00:30:00), "WKS-ADMIN-01", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 10, "Success",
datetime(2025-10-20 00:35:00), "WKS-ADMIN-02", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 10, "Success",
datetime(2025-10-20 00:40:00), "CR-ROOM-ADMIN", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 10, "Success",
datetime(2025-10-20 00:45:00), "SRV-015", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 00:50:00), "SRV-016", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 00:55:00), "SRV-017", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 01:00:00), "SRV-018", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 01:05:00), "SRV-019", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 01:10:00), "SRV-020", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 01:15:00), "SRV-021", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 01:20:00), "WKS-ADMIN-03", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 10, "Success",
datetime(2025-10-20 01:25:00), "SRV-022", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
datetime(2025-10-20 01:30:00), "SRV-023", "CORP\\priv_admin_zara", 4624, "An account was successfully logged on", "10.0.1.20", 3, "Success",
// ---------- SOME NOISY/HUMAN-LIKE FAST MOVES (but normal-ish) ----------
// developer moving between 4 machines in 8 hours (MEDIUM)
datetime(2025-10-13 09:00:00), "DEV-01", "CORP\\dev_ron", 4624, "An account was successfully logged on", "10.0.3.11", 10, "Success",
datetime(2025-10-13 13:00:00), "DEV-02", "CORP\\dev_ron", 4624, "An account was successfully logged on", "10.0.3.11", 10, "Success",
datetime(2025-10-20 04:00:00), "DEV-03", "CORP\\dev_ron", 4624, "An account was successfully logged on", "10.0.3.11", 10, "Success",
datetime(2025-10-20 10:00:00), "DEV-04", "CORP\\dev_ron", 4624, "An account was successfully logged on", "10.0.3.11", 10, "Success",
// ---------- NOISY BUT BENIGN: helpdesk admins (admin in name) touching consoles during working hours ---------- 
datetime(2025-10-13 09:00:00), "SRV-HLP01", "CORP\\help_admin_maya", 4624, "An account was successfully logged on", "10.0.1.50", 3, "Success",
datetime(2025-10-14 09:05:00), "SRV-HLP02", "CORP\\help_admin_maya", 4624, "An account was successfully logged on", "10.0.1.50", 3, "Success",
datetime(2025-10-15 09:10:00), "SRV-HLP03", "CORP\\help_admin_maya", 4624, "An account was successfully logged on", "10.0.1.50", 3, "Success",
datetime(2025-10-20 05:00:00), "SRV-HLP04", "CORP\\help_admin_maya", 4624, "An account was successfully logged on", "10.0.1.50", 3, "Success",
// ---------- Edge: user with normal 2 machines but sudden 4 in 5 minutes -> CRITICAL test ----------
datetime(2025-10-13 08:30:00), "WKS-701", "CORP\\paul", 4624, "An account was successfully logged on", "10.0.2.91", 10, "Success",
datetime(2025-10-20 05:10:00), "WKS-701", "CORP\\paul", 4624, "An account was successfully logged on", "10.0.2.91", 10, "Success",
datetime(2025-10-20 05:11:00), "SRV-NEW-A", "CORP\\paul", 4624, "An account was successfully logged on", "10.0.2.91", 3, "Success",
datetime(2025-10-20 05:13:00), "SRV-NEW-B", "CORP\\paul", 4624, "An account was successfully logged on", "10.0.2.91", 3, "Success",
datetime(2025-10-20 05:14:00), "WKS-702", "CORP\\paul", 4624, "An account was successfully logged on", "10.0.2.91", 10, "Success",
// ---------- filler normal events so baselines look realistic ----------
datetime(2025-10-13 11:00:00), "WKS-801", "CORP\\sara", 4624, "An account was successfully logged on", "10.0.2.101", 10, "Success",
datetime(2025-10-14 11:05:00), "WKS-801", "CORP\\sara", 4624, "An account was successfully logged on", "10.0.2.101", 10, "Success",
datetime(2025-10-15 11:10:00), "WKS-802", "CORP\\tina", 4624, "An account was successfully logged on", "10.0.2.102", 10, "Success",
datetime(2025-10-16 11:15:00), "WKS-803", "CORP\\umar", 4624, "An account was successfully logged on", "10.0.2.103", 10, "Success",
datetime(2025-10-17 11:20:00), "WKS-804", "CORP\\victor", 4624, "An account was successfully logged on", "10.0.2.104", 10, "Success",
datetime(2025-10-18 11:25:00), "WKS-805", "CORP\\wendy", 4624, "An account was successfully logged on", "10.0.2.105", 10, "Success",
datetime(2025-10-19 11:30:00), "WKS-806", "CORP\\xander", 4624, "An account was successfully logged on", "10.0.2.106", 10, "Success"
];
let Baseline=SecurityEvent
| where EventID == 4624 and TimeGenerated <ago(48h)
| order  by Account asc, TimeGenerated asc
| extend PrevLogin= prev(TimeGenerated)
| extend LoginInterval=datetime_diff('minute',TimeGenerated,PrevLogin)
| extend IsAdmin = iff(Account has_any(AdminAccounts),1,0)
| summarize
            BaseMachineCount=dcount(Computer),
            BaseMedianInterval=percentile(LoginInterval,50),
            BaseMachinesLogged=make_set(Computer),
            BaseNonServersAccessed=dcountif(Computer,Computer !startswith "SRV-")
            by Account,IsAdmin;
//Baseline
let CurrentDay=SecurityEvent
| where EventID == 4624 and TimeGenerated >ago(48h)
| order by Account asc, TimeGenerated asc 
| extend PrevLogin= prev(TimeGenerated)
| extend IsAdmin= iff(Account has_any (AdminAccounts),1,0)
| extend LoginInterval = datetime_diff('minute',TimeGenerated,PrevLogin)
| summarize
            CurrentMachineCount= dcount(Computer),
            CurrentMedianLoginInterval=percentile(LoginInterval,50),
            CurrentMachinesLogged= make_set(Computer),
            CurrentNonServersAccessed=dcountif(Computer,Computer !startswith "SRV-"),
            FirstLogin=min(TimeGenerated),
            LastLogin=max(TimeGenerated)
            by Account,IsAdmin,bin(TimeGenerated,48h);
let EightHourSummary = SecurityEvent
| where EventID == 4624 and TimeGenerated >ago(48h)
| extend IsAdmin= iff(Account has_any (AdminAccounts),1,0)
| summarize EightHourCount = dcount(Computer) by Account, bin(TimeGenerated,8h);
let HourlySummary = SecurityEvent
| where EventID == 4624 and TimeGenerated >ago(48h)
| extend IsAdmin= iff(Account has_any (AdminAccounts),1,0)
| summarize HourlyCount = dcount(Computer) by Account, bin(TimeGenerated,1h);
let FiveMinuteSummary = SecurityEvent
| where EventID == 4624 and TimeGenerated >ago(48h)
| extend IsAdmin= iff(Account has_any (AdminAccounts),1,0)
| summarize FiveMinuteCount = dcount(Computer) by Account, bin(TimeGenerated,5m);
CurrentDay
|join kind= inner (Baseline) on Account
|join kind = inner (EightHourSummary) on Account
|join kind = inner (HourlySummary) on Account
|join kind = inner (FiveMinuteSummary) on Account
| extend UniqueMachineCount = array_length(set_difference(CurrentMachinesLogged,BaseMachinesLogged))
| extend Criticality = case(
                            FiveMinuteCount >=4,"CRITICAL",
                            HourlyCount>=4,"HIGH",
                            EightHourCount>=4,"MEDIUM",
                            "LOW"
)
| extend UniqueMachinesLogged = set_difference(CurrentMachinesLogged,BaseMachinesLogged)
| extend 
        RiskScore=
        iff((CurrentMachineCount > 2*BaseMachineCount and  UniqueMachineCount >0),toint(RiskWeight.MultiMachine),0)+
        iff((CurrentMedianLoginInterval <BaseMedianInterval/3 or(BaseMedianInterval <0 and CurrentMedianLoginInterval >0)),toint(RiskWeight.HighTimeVelocity),0)+
        iff(((IsAdmin == 1 and (CurrentMachineCount > 20 or CurrentNonServersAccessed > 0)) or (IsAdmin == 0 and CurrentMachineCount > 2)),toint(RiskWeight.HighFailureCount),0)+
        case(Criticality =="CRITICAL",toint(RiskWeight.Critical),
            Criticality=="HIGH",toint(RiskWeight.High),
            Criticality=="Medium",toint(RiskWeight.Medium),
            0
        )
|extend RiskFactors=dynamic([])
|extend RiskFactors=iff((CurrentMachineCount > 2*BaseMachineCount and  UniqueMachineCount >0),array_concat(RiskFactors,dynamic(["HighMachineCount"])),RiskFactors)
|extend RiskFactors=iff((CurrentMedianLoginInterval <BaseMedianInterval/3 or(BaseMedianInterval <0 and CurrentMedianLoginInterval >0)),array_concat(RiskFactors,dynamic(["HighTimeVelocity"])),RiskFactors)
|extend RiskFactors=iff(((IsAdmin == 1 and (CurrentMachineCount > 20 or CurrentNonServersAccessed > 0)) or (IsAdmin == 0 and CurrentMachineCount > 2)),array_concat(RiskFactors,dynamic(["HighFailureCount"])),RiskFactors)
|extend RiskFactors=case(Criticality =="CRITICAL",array_concat(RiskFactors,dynamic(["HighFiveMinFailure"])),
            Criticality=="HIGH",array_concat(RiskFactors,dynamic(["HighHourlyFailure"])),
            Criticality=="Medium",array_concat(RiskFactors,dynamic(["HighDailyFailure"])),
            RiskFactors
        )
|extend Severity=case(
    RiskScore >75,"Critical",
    RiskScore>50,"High",
    RiskScore>25,"Medium",
    "Low"
)
|where RiskScore >50
|summarize MachinesLogged=make_list(UniqueMachinesLogged),RiskFactor=take_any(RiskFactors) by  Account,CurrentMachineCount,BaseMachineCount,CurrentMedianLoginInterval,Criticality,FirstLogin,LastLogin,RiskScore
```
