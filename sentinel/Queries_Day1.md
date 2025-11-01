## 📅 WEEK 1: KQL Fundamentals (Days 1-7)
**Focus:** Master query operators through security use cases

### Day 1: Basic Filtering & Time Analysis
**Scenario:** Your manager asks: "Show me all failed sign-ins from the last 24 hours"

**Challenge 1.1: Failed Authentication Query**
- Filter only failed logins
- Show: Time, User, IP, Failure Reason
- Sort by most recent
- Time range: Last 24 hours


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
SigninLogs
|where ResultType  <>0 and TimeGenerated >ago(24h)
|project TimeGenerated, UserPrincipalName,IPAddress,ResultDescription
```

**Challenge 1.2: Identify Top Failed Users**
- Count failures per user
- Show top 10
- Include their most common failure reason

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
    datetime(2025-10-16 10:00:01), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Bad password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:00:35), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:12), "root@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:45), "administrator@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:20), "sysadmin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:03:30), "admin@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
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
SigninLogs
|where ResultType <>0
|summarize FailureCount=count() by UserPrincipalName,ResultDescription
|summarize 
    TotalFailureCount=sum(FailureCount),
    arg_max(FailureCount,ResultDescription) ,
    FailureBreakdown=make_bag(pack(ResultDescription,FailureCount))by UserPrincipalName
|project  UserPrincipalName, TotalFailureCount,MaxFailureCount=FailureCount,MostCommonFailure=ResultDescription,FailureBreakdown
|limit 10 

```
**Challenge 1.3: Geographic Analysis**
- Group by location
- Show failure count per country
- Identify suspicious locations (VPN exits, Tor nodes)

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
    datetime(2025-10-16 10:00:01), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Bad password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:00:35), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:12), "root@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:45), "administrator@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:20), "sysadmin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:03:30), "admin@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
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
SigninLogs
|where DeviceTrustType has "Unknown"
|extend Country=trim(" ",substring(Location,indexof(Location,",",0)+1,strlen(Location)-indexof(Location,",",0)+1))
|where Country in ("RU", "CN", "UA", "BR") 
|summarize  EventCount=count() by Country
|project Country, EventCount
```

**2. Which user had the most failed login attempts?**
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
SigninLogs
|where ResultType  <>0 
|summarize FailureCount=count() by UserPrincipalName
|top 1 by FailureCount desc 
```

**3. Which IP address has the most failed attempts?**
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
SigninLogs
|where ResultType  <>0 
|summarize FailureCount=count() by IPAddress
|top 1 by FailureCount desc 


```

**Which locations have the most suspicious activity?**
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
SigninLogs
|where ResultType  <>0 
|summarize FailureCount=count() by Location
|top 1 by FailureCount desc 


```

**Find successful logins that came after multiple failures from same IP**

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
|summarize FailureCount=count(),FirstFailure=min(TimeGenerated),LastFailure=max(TimeGenerated),FailureNames=make_set(UserPrincipalName) by IPAddress;
let Success=SigninLogs
|where ResultType  ==0 
|summarize SuccessCount=count(),arg_min(TimeGenerated,*) by IPAddress;
Success
|join kind =inner(Failure)
on IPAddress
|where TimeGenerated >LastFailure and FailureCount >5
|project IPAddress,TimeGenerated,LastFailure,SuccessCount,FailureCount,UserPrincipalName,FailureNames
```

**Find IPs that had failed logins for more than 3 different users in the last 48 hours.**

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
SigninLogs
|where ResultType  <>0 
|summarize FailedPerUser=count() by UserPrincipalName,IPAddress
|summarize Failurecount=sum(FailedPerUser), UserCount=dcount(UserPrincipalName),FailedUsers=make_bag(pack(UserPrincipalName,FailedPerUser))by IPAddress
|where UserCount >=3

```
**Find users who logged in outside normal working hours (e.g., 9 AM–6 PM).**
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
    // Brute force from single IP
    datetime(2025-10-16 10:00:01), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:00:35), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:12), "root@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:45), "administrator@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:20), "sysadmin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:03:30), "admin@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Password spray from multiple IPs
    datetime(2025-10-16 11:00:00), "alice@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:05:00), "bob@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:10:00), "charlie@company.com", "192.0.2.45", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:15:00), "david@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:20:00), "eve@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    // Legit users occasional failures + success
    datetime(2025-10-16 12:00:00), "alice@company.com", "203.0.113.50", "New York, US", "50126", "Invalid username or password", "Office 365", "Hybrid Azure AD joined", true,
    datetime(2025-10-16 12:01:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365", "Hybrid Azure AD joined", true,
    // MFA failures
    datetime(2025-10-16 13:00:00), "bob@company.com", "198.51.100.25", "London, UK", "50074", "MFA denied; user declined the authentication", "Azure Portal", "Azure AD joined", true,
    datetime(2025-10-16 13:02:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Azure Portal", "Azure AD joined", true,
    // Suspicious: success from previously failing IP
    datetime(2025-10-16 14:00:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Account lock events
    datetime(2025-10-16 14:30:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "50128", "Account locked due to failed attempts", "SharePoint", "Compliant", true,
    // Password reset events
    datetime(2025-10-16 15:00:00), "david@company.com", "203.0.113.75", "New York, US", "60001", "Password reset requested", "Teams", "Compliant", true,
    // More normal activity
    datetime(2025-10-16 15:30:00), "eve@company.com", "198.51.100.88", "London, UK", "0", "Success", "OneDrive", "Azure AD joined", true,
    datetime(2025-10-16 16:00:00), "frank@company.com", "203.0.113.60", "Berlin, DE", "0", "Success", "Teams", "Compliant", true,
    datetime(2025-10-16 16:30:00), "george@company.com", "198.51.100.90", "Paris, FR", "0", "Success", "Office 365", "Hybrid Azure AD joined", true
];
SigninLogs
|extend hour = datetime_part("hour",TimeGenerated)
|where hour !between (9..18)
|project IPAddress,UserPrincipalName,TimeGenerated,Location
```
**List IPs with more than 5 failures within a 3 min window and the users affected.**
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
    // Brute force from single IP
    datetime(2025-10-16 10:00:01), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:00:35), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:12), "root@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:45), "administrator@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:20), "sysadmin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:03:30), "admin@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Password spray from multiple IPs
    datetime(2025-10-16 11:00:00), "alice@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:05:00), "bob@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:10:00), "charlie@company.com", "192.0.2.45", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:15:00), "david@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:20:00), "eve@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    // Legit users occasional failures + success
    datetime(2025-10-16 12:00:00), "alice@company.com", "203.0.113.50", "New York, US", "50126", "Invalid username or password", "Office 365", "Hybrid Azure AD joined", true,
    datetime(2025-10-16 12:01:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365", "Hybrid Azure AD joined", true,
    // MFA failures
    datetime(2025-10-16 13:00:00), "bob@company.com", "198.51.100.25", "London, UK", "50074", "MFA denied; user declined the authentication", "Azure Portal", "Azure AD joined", true,
    datetime(2025-10-16 13:02:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Azure Portal", "Azure AD joined", true,
    // Suspicious: success from previously failing IP
    datetime(2025-10-16 14:00:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Account lock events
    datetime(2025-10-16 14:30:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "50128", "Account locked due to failed attempts", "SharePoint", "Compliant", true,
    // Password reset events
    datetime(2025-10-16 15:00:00), "david@company.com", "203.0.113.75", "New York, US", "60001", "Password reset requested", "Teams", "Compliant", true,
    // More normal activity
    datetime(2025-10-16 15:30:00), "eve@company.com", "198.51.100.88", "London, UK", "0", "Success", "OneDrive", "Azure AD joined", true,
    datetime(2025-10-16 16:00:00), "frank@company.com", "203.0.113.60", "Berlin, DE", "0", "Success", "Teams", "Compliant", true,
    datetime(2025-10-16 16:30:00), "george@company.com", "198.51.100.90", "Paris, FR", "0", "Success", "Office 365", "Hybrid Azure AD joined", true
];
let window=3min;
SigninLogs
|where ResultType !=0
|extend TimeWindow=bin(TimeGenerated,window)
|summarize FailureCount= count(), FirstFailure=min(TimeGenerated),LastFailure=max(TimeGenerated),TimeStamps=make_list(TimeGenerated), AffectedUsers=make_set(UserPrincipalName) by IPAddress,TimeWindow
|where FailureCount >5
```
**Correlate failed login events with password reset events for the same user within 1 hour.**
```KQL
let window=1h;
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
    // Brute force from single IP
    datetime(2025-10-16 10:00:01), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:00:35), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:12), "root@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:45), "administrator@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:20), "sysadmin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:03:30), "admin@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Password spray from multiple IPs
    datetime(2025-10-16 11:00:00), "alice@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:05:00), "bob@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:10:00), "charlie@company.com", "192.0.2.45", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:15:00), "david@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:20:00), "eve@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    // Legit users occasional failures + success
    datetime(2025-10-16 12:00:00), "alice@company.com", "203.0.113.50", "New York, US", "50126", "Invalid username or password", "Office 365", "Hybrid Azure AD joined", true,
    datetime(2025-10-16 12:01:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365", "Hybrid Azure AD joined", true,
    // MFA failures
    datetime(2025-10-16 13:00:00), "bob@company.com", "198.51.100.25", "London, UK", "50074", "MFA denied; user declined the authentication", "Azure Portal", "Azure AD joined", true,
    datetime(2025-10-16 13:02:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Azure Portal", "Azure AD joined", true,
    // Suspicious: success from previously failing IP
    datetime(2025-10-16 14:00:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Account lock events
    datetime(2025-10-16 14:30:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "50128", "Account locked due to failed attempts", "SharePoint", "Compliant", true,
    // Password reset events
    datetime(2025-10-16 15:00:00), "david@company.com", "203.0.113.75", "New York, US", "60001", "Password reset requested", "Teams", "Compliant", true,
    // More normal activity
    datetime(2025-10-16 15:30:00), "eve@company.com", "198.51.100.88", "London, UK", "0", "Success", "OneDrive", "Azure AD joined", true,
    datetime(2025-10-16 16:00:00), "frank@company.com", "203.0.113.60", "Berlin, DE", "0", "Success", "Teams", "Compliant", true,
    datetime(2025-10-16 16:30:00), "george@company.com", "198.51.100.90", "Paris, FR", "0", "Success", "Office 365", "Hybrid Azure AD joined", true
];
let Failure=SigninLogs
|where ResultType !=0
|summarize  FirstFailure=min(TimeGenerated),LastFailure=max(TimeGenerated),FailedIPAddress=make_set(IPAddress) by UserPrincipalName;
let Reset = SigninLogs
|where ResultType ==60001
|summarize  ResetTimestamp=min(TimeGenerated),ResetIPAddress=make_set(IPAddress) by UserPrincipalName;
Failure
|join kind = inner (
Reset
)on UserPrincipalName
|extend EndTime=LastFailure+window
|where ResetTimestamp between (LastFailure .. EndTime )
```
**Identify users whose accounts got locked due to repeated failed logins**

```KQL
let window=1h;
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
    // Brute force from single IP
    datetime(2025-10-16 10:00:01), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:00:35), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:12), "root@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:01:45), "administrator@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:20), "sysadmin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:02:55), "admin@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 10:03:30), "admin@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Password spray from multiple IPs
    datetime(2025-10-16 11:00:00), "alice@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:05:00), "bob@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:10:00), "charlie@company.com", "192.0.2.45", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:15:00), "david@company.com", "203.0.113.9", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    datetime(2025-10-16 11:20:00), "eve@company.com", "198.51.100.7", "Singapore, SG", "50126", "Invalid username or password", "Office 365", "Unknown", true,
    // Legit users occasional failures + success
    datetime(2025-10-16 12:00:00), "alice@company.com", "203.0.113.50", "New York, US", "50126", "Invalid username or password", "Office 365", "Hybrid Azure AD joined", true,
    datetime(2025-10-16 12:01:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365", "Hybrid Azure AD joined", true,
    // MFA failures
    datetime(2025-10-16 13:00:00), "bob@company.com", "198.51.100.25", "London, UK", "50074", "MFA denied; user declined the authentication", "Azure Portal", "Azure AD joined", true,
    datetime(2025-10-16 13:02:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Azure Portal", "Azure AD joined", true,
    // Suspicious: success from previously failing IP
    datetime(2025-10-16 14:00:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Office 365", "Unknown", true,
    // Account lock events
    datetime(2025-10-16 14:30:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "50128", "Account locked due to failed attempts", "SharePoint", "Compliant", true,
    // Password reset events
    datetime(2025-10-16 15:00:00), "david@company.com", "203.0.113.75", "New York, US", "60001", "Password reset requested", "Teams", "Compliant", true,
    // More normal activity
    datetime(2025-10-16 15:30:00), "eve@company.com", "198.51.100.88", "London, UK", "0", "Success", "OneDrive", "Azure AD joined", true,
    datetime(2025-10-16 16:00:00), "frank@company.com", "203.0.113.60", "Berlin, DE", "0", "Success", "Teams", "Compliant", true,
    datetime(2025-10-16 16:30:00), "george@company.com", "198.51.100.90", "Paris, FR", "0", "Success", "Office 365", "Hybrid Azure AD joined", true
];
let Failure=SigninLogs
|where ResultType !=0
|summarize  FailureCount=count(),FirstFailure=min(TimeGenerated),LastFailure=max(TimeGenerated),FailedIPAddress=make_set(IPAddress) by UserPrincipalName;
let Lockout = SigninLogs
|where ResultType ==50128
|summarize  LockOutTimestamp=min(TimeGenerated),LockOutIPAddress=make_set(IPAddress) by UserPrincipalName;
Failure
| join kind = inner (Lockout) on UserPrincipalName
|where FailureCount >1 and LockOutTimestamp > FirstFailure

```

**Find users who eventually logged in successfully after 3+ consecutive failed attempts (similar to your original #5, but across all users/IPs in past 24h)**

```KQL
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    ResultDescription: string
)[
    // --- Alice: 3 consecutive failures then success (same IP)
    datetime(2025-10-16 09:00:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-16 09:01:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-16 09:02:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-16 09:03:00), "alice@company.com", "203.0.113.50", "0", "Success",
        // --- Bob: 2 failures then success (should NOT trigger)
    datetime(2025-10-16 10:00:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-16 10:01:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-16 10:02:00), "bob@company.com", "198.51.100.25", "0", "Success",
    // --- Charlie: 4 failures from same IP, then success 10 mins later
    datetime(2025-10-16 11:00:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-16 11:01:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-16 11:02:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-16 11:03:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-16 11:15:00), "charlie@company.com", "192.0.2.100", "0", "Success",
    // --- David: Success then random failure (noise)
    datetime(2025-10-16 12:00:00), "david@company.com", "203.0.113.9", "0", "Success",
    datetime(2025-10-16 12:10:00), "david@company.com", "203.0.113.9", "50126", "Invalid username or password",
    // --- Eve: 3 failures from different IPs (password spray)
    datetime(2025-10-16 13:00:00), "eve@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-16 13:01:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-16 13:02:00), "eve@company.com", "198.51.100.7", "50126", "Invalid username or password",
    datetime(2025-10-16 13:03:00), "eve@company.com", "203.0.113.9", "0", "Success"
];
SigninLogs
| sort  by UserPrincipalName,TimeGenerated asc
|extend IsFailure = iff(ResultType !=0,1,0)
|extend IsSuccess=iff(ResultType==0,1,0)
|serialize 
|extend PrevFail=prev(IsFailure),PrevFail2=prev(IsFailure,2), PrevFaile3=prev(IsFailure,3)
|extend FirstFailure=prev(TimeGenerated),SecondFailure=prev(TimeGenerated,2),ThirdFailure=prev(TimeGenerated,3)
|extend FirstFailedIP=prev(IPAddress),SecondFailedIP=prev(IPAddress,2),ThirdFailedIP=prev(IPAddress,3)
|extend SequenceMatch=iff(IsSuccess==1 and PrevFail ==1 and PrevFail2 ==1 and PrevFaile3 ==1,1,0)
|where SequenceMatch ==1
|project UserPrincipalName,IPAddress,SuccessTime=TimeGenerated,FirstFailure,SecondFailure,ThirdFailure,FirstFailedIP,SecondFailedIP,ThirdFailedIP,Duration=TimeGenerated-ThirdFailure
```

**Find the top 5 users who had the highest number of failed logins in the past 7 days.**
```KQL
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    ResultDescription: string
)[
    // Alice: multiple failures across days
    datetime(2025-10-10 08:00:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-11 09:15:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-12 10:00:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    // Bob: failures + successes
    datetime(2025-10-12 11:00:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-12 11:05:00), "bob@company.com", "198.51.100.25", "0", "Success",
    datetime(2025-10-14 12:30:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    // Charlie: heavy failures
    datetime(2025-10-13 14:00:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-13 14:05:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-13 14:10:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-14 15:00:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    // David: single failures
    datetime(2025-10-15 16:00:00), "david@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-16 09:00:00), "david@company.com", "203.0.113.9", "50126", "Invalid username or password",
    // Eve: some failures
    datetime(2025-10-15 13:00:00), "eve@company.com", "198.51.100.7", "50126", "Invalid username or password",
    datetime(2025-10-15 13:02:00), "eve@company.com", "198.51.100.7", "50126", "Invalid username or password",
    datetime(2025-10-15 13:05:00), "eve@company.com", "198.51.100.7", "50126", "Invalid username or password"
];
SigninLogs
|where ResultType !=0 and TimeGenerated >ago(7d)
|summarize FailedCount=count() by UserPrincipalName
|top 3 by FailedCount
```

**Show all failed login attempts coming from outside your corporate IP range.**
```KQL
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    ResultDescription: string
)[
    datetime(2025-10-16 09:00:00), "alice@company.com", "10.0.0.5", "50126", "Invalid username or password",
    datetime(2025-10-16 09:05:00), "bob@company.com", "10.0.0.12", "50126", "Invalid username or password",
    datetime(2025-10-16 09:10:00), "charlie@company.com", "10.0.1.8", "0", "Success",
    datetime(2025-10-16 10:00:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-16 10:05:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-16 10:10:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-16 10:15:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-16 10:20:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-16 11:00:00), "alice@company.com", "203.0.113.50", "0", "Success",
    datetime(2025-10-16 11:05:00), "bob@company.com", "10.0.0.12", "0", "Success"
];
SigninLogs
| where ResultType !=0 and not( ipv4_is_in_range( IPAddress,"10.0.0.0/24")  or ipv4_is_in_range( IPAddress,"10.0.0.0/16"))
```
**Count the number of failed logins per hour over the last 7 days and visualize peaks.**
```KQL
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    ResultDescription: string
)[
    datetime(2025-10-10 08:05:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-10 08:15:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-10 09:00:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-10 10:30:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-10 11:45:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-11 08:10:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-11 08:20:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-11 09:05:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-11 10:35:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-11 11:50:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-12 08:12:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-12 08:22:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-12 09:10:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-12 10:40:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-12 11:55:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-12 12:45:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-12 12:55:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-13 08:14:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-13 08:25:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-13 09:15:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-13 10:45:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-13 11:59:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-14 08:16:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-14 08:27:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-14 09:20:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-14 10:50:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-14 12:01:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-15 08:18:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-15 08:29:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-15 08:39:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-15 09:29:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-15 09:39:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-15 09:25:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-15 10:55:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-15 12:05:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password",
    datetime(2025-10-16 08:20:00), "alice@company.com", "203.0.113.50", "50126", "Invalid username or password",
    datetime(2025-10-16 08:35:00), "bob@company.com", "198.51.100.25", "50126", "Invalid username or password",
    datetime(2025-10-16 09:30:00), "charlie@company.com", "192.0.2.100", "50126", "Invalid username or password",
    datetime(2025-10-16 10:05:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-16 10:15:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-16 10:25:00), "david@company.com", "185.220.101.52", "50126", "Invalid username or password",
    datetime(2025-10-16 11:10:00), "eve@company.com", "203.0.113.9", "50126", "Invalid username or password"
];
SigninLogs
| extend TimeSpan=bin(TimeGenerated,1h)
|where TimeGenerated >ago(7d) and ResultType !=0
|summarize Failedcount=count() by UserPrincipalName,TimeSpan
|order by UserPrincipalName,TimeSpan desc
|render timechart 
```

**Identify users who successfully logged in from countries they usually don’t log in from in the past week.**
```KQL
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Country: string,
    ResultType: string,
    ResultDescription: string
)[
    // Historical baseline (before last 7 days)
    datetime(2025-10-05 09:00:00), "alice@company.com", "203.0.113.50", "US", "0", "Success",
    datetime(2025-10-05 12:00:00), "bob@company.com", "198.51.100.25", "US", "0", "Success",
    datetime(2025-10-06 10:30:00), "charlie@company.com", "192.0.2.100", "UK", "0", "Success",
    datetime(2025-10-06 11:45:00), "david@company.com", "185.220.101.52", "DE", "0", "Success",
    datetime(2025-10-06 12:10:00), "eve@company.com", "203.0.113.9", "US", "0", "Success",
    // Last 7 days logins
    datetime(2025-10-10 08:05:00), "alice@company.com", "203.0.113.50", "US", "0", "Success",  // usual
    datetime(2025-10-10 09:15:00), "alice@company.com", "198.51.100.35", "FR", "0", "Success", // unusual
    datetime(2025-10-11 08:10:00), "bob@company.com", "198.51.100.25", "US", "0", "Success",  // usual
    datetime(2025-10-12 09:10:00), "charlie@company.com", "192.0.2.101", "UK", "0", "Success", // usual
    datetime(2025-10-12 10:40:00), "charlie@company.com", "203.0.113.9", "FR", "0", "Success", // unusual
    datetime(2025-10-13 11:55:00), "david@company.com", "185.220.101.52", "DE", "0", "Success", // usual
    datetime(2025-10-14 12:01:00), "eve@company.com", "198.51.100.7", "UK", "0", "Success"  // unusual
];
let baseline=SigninLogs
|where TimeGenerated < ago(7d)
| summarize UsualCountries=make_set(Country) by UserPrincipalName;
let recent = SigninLogs
|where TimeGenerated >ago(7d);
baseline
| join kind = inner (recent
) on UserPrincipalName
|where array_index_of(UsualCountries,Country)==-1

```