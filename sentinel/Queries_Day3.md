let SuspiciousCommands = dynamic(["mimikatz","Invoke-Mimikatz","reg save","SAM","SYSTEM"]);
let SuspiciousExtensions = dynamic(["csv","xlsx","zip","txt"]);
let CommonSecurityLog = datatable(
    TimeGenerated: datetime,
    SourceIP: string,
    DestinationIP: string,
    DestinationPort: int,
    Protocol: string,
    DeviceAction: string,
    SentBytes: long,
    ReceivedBytes: long,
    SourceUserName: string
)[
    // Normal traffic
    datetime(2025-10-20 08:00:00), "10.0.1.100", "8.8.8.8", 443, "TCP", "allow", 1500, 45000, "bob",
    datetime(2025-10-20 08:15:00), "10.0.1.101", "1.1.1.1", 443, "TCP", "allow", 2000, 50000, "charlie",    
    // ATTACK: Data exfiltration (25 minutes after compromise)
    datetime(2025-10-20 10:25:00), "10.0.1.200", "185.220.101.52", 443, "TCP", "allow", 524288000, 50000, "alice",
    datetime(2025-10-20 10:26:00), "10.0.1.200", "185.220.101.52", 443, "TCP", "allow", 524288000, 50000, "alice",
    datetime(2025-10-20 10:27:00), "10.0.1.200", "185.220.101.52", 443, "TCP", "allow", 524288000, 50000, "alice",    
    // Normal traffic
    datetime(2025-10-20 11:00:00), "10.0.1.101", "8.8.8.8", 443, "TCP", "allow", 1800, 55000, "bob"
];
let OfficeActivity = datatable(
    TimeGenerated: datetime,
    UserId: string,
    Operation: string,
    ClientIP: string,
    SourceFileName: string,
    SourceFileExtension: string,
    SiteUrl: string,
    ItemType: string
)[
    // Normal file access
    datetime(2025-10-20 08:45:00), "bob@company.com", "FileAccessed", "198.51.100.25", "Q1_Report.xlsx", "xlsx", "https://company.sharepoint.com/sites/finance", "File",
    datetime(2025-10-20 09:15:00), "charlie@company.com", "FileModified", "192.0.2.100", "Project_Plan.docx", "docx", "https://company.sharepoint.com/sites/projects", "File",    
    // ATTACK: Mass file download (20 minutes after compromise)
    datetime(2025-10-20 10:20:00), "alice@company.com", "FileDownloaded", "185.220.101.52", "employee_database.csv", "csv", "https://company.sharepoint.com/sites/hr", "File",
    datetime(2025-10-20 10:20:15), "alice@company.com", "FileDownloaded", "185.220.101.52", "salaries_2025.xlsx", "xlsx", "https://company.sharepoint.com/sites/hr", "File",
    datetime(2025-10-20 10:20:30), "alice@company.com", "FileDownloaded", "185.220.101.52", "customer_list.xlsx", "xlsx", "https://company.sharepoint.com/sites/sales", "File",
    datetime(2025-10-20 10:20:45), "alice@company.com", "FileDownloaded", "185.220.101.52", "financial_records.xlsx", "xlsx", "https://company.sharepoint.com/sites/finance", "File",
    datetime(2025-10-20 10:21:00), "alice@company.com", "FileDownloaded", "185.220.101.52", "source_code.zip", "zip", "https://company.sharepoint.com/sites/engineering", "File",
    datetime(2025-10-20 10:21:15), "alice@company.com", "FileDownloaded", "185.220.101.52", "api_keys.txt", "txt", "https://company.sharepoint.com/sites/devops", "File",
    datetime(2025-10-20 10:21:30), "alice@company.com", "FileDownloaded", "185.220.101.52", "backup_credentials.txt", "txt", "https://company.sharepoint.com/sites/admin", "File",    
    // Normal activity
    datetime(2025-10-20 11:00:00), "bob@company.com", "FileAccessed", "198.51.100.25", "meeting_notes.docx", "docx", "https://company.sharepoint.com/sites/general", "File"
];
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IPAddress: string,
    CommandLine: string
)[
    // Normal workstation activity
    datetime(2025-10-20 08:00:00), "WKS-001", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", "",
    datetime(2025-10-20 08:05:00), "WKS-002", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", "",
    // ATTACK: Lateral movement (10 minutes after compromise)
    datetime(2025-10-20 10:10:00), "SRV-DC01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    datetime(2025-10-20 10:11:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    datetime(2025-10-20 10:12:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    datetime(2025-10-20 10:13:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    // ATTACK: Credential dumping (15 minutes after compromise)
    datetime(2025-10-20 10:15:00), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "185.220.101.52", "powershell.exe Invoke-Mimikatz -DumpCreds",
    datetime(2025-10-20 10:15:30), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "185.220.101.52", "cmd.exe /c reg save HKLM\\SAM C:\\temp\\sam.hive",
    datetime(2025-10-20 10:16:00), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "185.220.101.52", "cmd.exe /c reg save HKLM\\SYSTEM C:\\temp\\system.hive",
    datetime(2025-10-20 10:15:30), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "10.220.101.52", "cmd.exe /c reg save HKLM\\SAM C:\\temp\\sam.hive",
    // Normal activity
    datetime(2025-10-20 10:30:00), "WKS-003", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", ""
];
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: string,
    ResultType: string,
    ResultDescription: string,
    AppDisplayName: string
)[
    // Normal morning logins
    datetime(2025-10-20 08:15:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Office 365",
    datetime(2025-10-20 08:20:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "0", "Success", "SharePoint",
    datetime(2025-10-20 08:30:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365",
    // ATTACK: Brute force on alice's account
    datetime(2025-10-20 10:00:01), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:15), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:29), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:44), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:58), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:01:12), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:01:27), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:01:41), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    // ATTACK: Successful compromise
    datetime(2025-10-20 10:03:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Azure Portal",
    // Normal activity from other users
    datetime(2025-10-20 10:05:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Teams",
    datetime(2025-10-20 10:10:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "0", "Success", "OneDrive",
    // More normal alice activity (legitimate user still working)
    datetime(2025-10-20 10:15:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Teams"
];
let AuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: string,
    TargetResources: string,
    Result: string,
    Category: string,
    IPAddress: string
)[
    // Normal admin work
    datetime(2025-10-20 08:30:00), "Add member to group", "admin@company.com", "IT-Support", "Success", "GroupManagement", "10.0.1.100",
    datetime(2025-10-20 09:00:00), "Reset user password", "admin@company.com", "bob@company.com", "Success", "UserManagement", "10.0.1.100",    
    // ATTACK: Privilege escalation (5 minutes after compromise)
    datetime(2025-10-20 10:05:00), "Add member to group", "alice@company.com", "Domain Admins", "Success", "GroupManagement", "185.220.101.52",
    datetime(2025-10-20 10:05:30), "Add member to group", "alice@company.com", "Enterprise Admins", "Success", "GroupManagement", "185.220.101.52",
    datetime(2025-10-20 10:06:00), "Update service principal", "alice@company.com", "API-Access-Full", "Success", "ApplicationManagement", "185.220.101.52",    
    // Normal activity
    datetime(2025-10-20 11:00:00), "Update user profile", "bob@company.com", "bob@company.com", "Success", "UserManagement", "198.51.100.25"
];
let Success =SigninLogs
| where UserPrincipalName =="alice@company.com" and ResultType ==0
| order by TimeGenerated asc
|summarize SuccessCount=count(),
    FirstSuccess=min(TimeGenerated),
    LastSuccess=max(TimeGenerated) ,
    SuccessLoggedLocations=make_set(Location)by UserPrincipalName,SuccessWindow=bin(TimeGenerated,30m),IPAddress;
let Failure =SigninLogs
| where UserPrincipalName =="alice@company.com" and ResultType !=0
| order by TimeGenerated asc
|summarize FailureCount=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated),
    FailureLoggedLocations=make_set(Location)
    by UserPrincipalName,FailureWindow=bin(TimeGenerated,30m),IPAddress;
let BruteForce=
    Success
    |join kind=inner (Failure)on UserPrincipalName,IPAddress
    | extend TimeBetweenStages=dynamic([])
    | extend TimeBetweenStages =  strcat("Failure-Success",":",FirstSuccess-FirstFailure) 
    | where FirstSuccess >LastFailure and FailureCount >2 and array_length(set_intersect( FailureLoggedLocations,SuccessLoggedLocations))>0
    |summarize take_any(FirstSuccess),
    take_any(SuccessLoggedLocations),
    take_any(FailureCount),
    take_any(FirstFailure),
    take_any(LastFailure),
    take_any(FirstSuccess),
    TimeBetweenStages=make_set(TimeBetweenStages) by UserPrincipalName,IPAddress
    |extend CompriseDuration=FirstSuccess-LastFailure;
let PrivilegeEscalation=
BruteForce
| join kind= inner (AuditLogs
|project-rename UserPrincipalName=InitiatedBy
) on IPAddress,UserPrincipalName
| where TimeGenerated >FirstSuccess and Result =="Success" and TimeGenerated <=FirstSuccess+30m
| order by TimeGenerated asc
| extend OperationDuration =dynamic([])
| extend OperationDuration = strcat(OperationName,":",TimeGenerated-FirstSuccess)
| extend OperationTimeLine=strcat(OperationName,":",TargetResources,":",TimeGenerated)
| summarize ActivityCategory=make_set(Category),
    ActivityNames=make_set(OperationName),
    GroupsAdded=set_difference(make_set(iff(OperationName == "Add member to group",TargetResources,"")),dynamic([""])),
    TargettedResources=make_set(TargetResources),
    Timestamps=make_list(TimeGenerated),
    ActivityLocations=take_any(SuccessLoggedLocations),
    EscalationTime=min(TimeGenerated),
    CompromiseTime=take_any(FirstSuccess),
    FirstSuccess=take_any(FirstSuccess),
    OperationTimeLine=make_list(OperationTimeLine),
    CompromiseDuration=take_any(CompriseDuration),
    TimeBetweenStages=array_concat(coalesce(take_any(TimeBetweenStages),dynamic([])),make_list(OperationDuration)), 
    FaileAttempts=take_any(FailureCount)
    by IPAddress,UserPrincipalName
|extend User= substring(UserPrincipalName,0,indexof(UserPrincipalName,"@",0))
|extend EscalationDuration = EscalationTime-FirstSuccess;
let LaterlaMovement=
PrivilegeEscalation
|join kind = inner (SecurityEvent
| extend index=indexof(Account,"\\",0)
| extend User=substring(Account,index+1,strlen(Account)-index)
| extend  IPAddress=IPAddress
| where EventID ==4688
) on User,IPAddress
|where not( ipv4_is_private( IPAddress)) and Account contains "alice" and Computer contains"SRV-"
| extend OperationDuration = strcat(CommandLine,":",TimeGenerated-EscalationTime)
| extend CommandTimeLine = strcat(CommandLine,":",TimeGenerated)
| order by TimeGenerated asc
| summarize 
    AccountCompromiseTime=take_any(CompromiseTime),
    FIrstSuccessTime=take_any(FirstSuccess),
    CompromiseDuration=take_any(CompromiseDuration),
    PrivilegeEscalationTime=take_any(EscalationTime),
    EscalationDuration = take_any(EscalationDuration),
    SuspiciousActivityStart=min(TimeGenerated),
    SuspiciousActivityEnd=max(TimeGenerated),
    EventIds=make_set(EventID),
    HostCount=dcount(Computer),
    HostsAccessed=make_set(Computer),
    CommandsExecuted=set_difference(make_list(CommandLine),dynamic([""])),
    CommandTimeLine = make_list(CommandTimeLine),
    TimeBetweenStages=array_concat(coalesce(take_any(TimeBetweenStages),dynamic([])),make_list(OperationDuration)),
    OperationTimeLine=take_any(OperationTimeLine)
    by IPAddress,User
| where SuspiciousActivityEnd <=SuspiciousActivityStart+10m;
LaterlaMovement
| join kind = inner (
    OfficeActivity
    |extend User=substring(UserId,0,indexof(UserId,"@",0))
    |extend IPAddress=ClientIP
    |extend FileTimeLine = strcat(SourceFileName,":",TimeGenerated)
    | order by TimeGenerated asc
    | where SourceFileExtension in (SuspiciousExtensions) and Operation =="FileDownloaded"
    | summarize FilesDownloaded=make_set(SourceFileName),
        URLsAccessed=make_set(SiteUrl),
        FileTimelinies=make_list(FileTimeLine),
        FirstFileDownloadTimestamp=min(TimeGenerated),
        LastFileDownloadTimestamp=max(TimeGenerated) by User,IPAddress
    |extend FileDownloadDuration = LastFileDownloadTimestamp-FirstFileDownloadTimestamp
    | where FirstFileDownloadTimestamp <=LastFileDownloadTimestamp+5m
)on User,IPAddress
|join kind = inner(
    CommonSecurityLog
    |extend IPAddress=DestinationIP
    |extend User=SourceUserName
    | extend OutgoingMB=SentBytes/1024/1024
    | extend IncomingMB= ReceivedBytes/1024/1024
) on User,IPAddress
|where CommandsExecuted has_any (SuspiciousCommands)
| order by TimeGenerated asc 
|summarize 
    HostCount=take_any(HostCount),
    FirstSuccess=take_any(FIrstSuccessTime),
    HostName=make_set(HostsAccessed),
    HostIP=make_set(SourceIP),
    CompromiseTime=take_any(AccountCompromiseTime),
    PrivilegeEscalationTime=take_any(PrivilegeEscalationTime),
    LateralMovementStartTime= take_any(SuspiciousActivityStart),
    FileDownloadStart=take_any(FirstFileDownloadTimestamp),
    FileDownloadEnd=take_any(LastFileDownloadTimestamp),
    OutgoingStartTime=min(TimeGenerated),
    OutgoingEndTime=max(TimeGenerated),
    URLsAccessed=take_any(URLsAccessed),
    FilesDownloaded=take_any(FilesDownloaded),
    CompromiseDuration=take_any(CompromiseDuration),
    EscalationDuration = take_any(EscalationDuration),
    FileDownloadDuration=take_any(FileDownloadDuration),    
    FileTimeLines=take_any(FileTimelinies),
    CommandTimeLines=take_any(CommandTimeLine),
    CommandsExecuted=take_any(CommandsExecuted),
    TimeBetweenStages=take_any(TimeBetweenStages),
    OperationTimeLine=take_any(OperationTimeLine),
    TotalOutgoing = sum(OutgoingMB)    by User,IPAddress
| where TotalOutgoing >100
| extend TimeToExfiltration = OutgoingStartTime-FileDownloadStart
| extend CompromiseToExfilDuration=OutgoingStartTime-FirstSuccess
| extend RiskFactor=dynamic([])
| extend RiskScore=iif(toint(TimeToExfiltration)<=30,40,iff(toint(TimeToExfiltration)<=60,30,iif(toint(TimeToExfiltration)<=120,20,0)))
| extend RiskFactor = array_concat(coalesce(RiskFactor,dynamic([])),pack_array(iff(toint(TimeToExfiltration)<=30,"TimeToExfiltration < 30",iff(toint(TimeToExfiltration)<=60,"TimeToExfiltration < 60",iif(toint(TimeToExfiltration)<=120,"TimeToExfiltration < 120",""))))) 
| extend RiskScore=RiskScore+iif(TotalOutgoing >=100,50,iff(TotalOutgoing >=50,25,iff(TotalOutgoing >=25,10,0)))
| extend RiskFactor= array_concat(coalesce(RiskFactor,dynamic([])),pack_array(iif(TotalOutgoing >=100,"Outgoing > 100MB",iff(TotalOutgoing >=50 ,"Outgoing > 50MB",iff(TotalOutgoing >=25,"Outgoing > 25MB",""))))) 
| extend RiskScore=RiskScore+iff(HostCount >=4,50,iff(HostCount >=3,25,iff(HostCount >=2,10,iff(HostCount >=1,5,0))))
| extend RiskFactor= array_concat(coalesce(RiskFactor,dynamic([])),pack_array(iff(HostCount >=3,"Greater than 3 hosts",iff(HostCount >=2,"Greater Than 2 hosts",iff(HostCount >=1,"Greater than or equal to 1 host",""))))) 
| extend RiskFactor = set_difference(RiskFactor,dynamic([""]))
| project User,IPAddress,HostCount,HostIP,HostName,CompromiseTime,PrivilegeEscalationTime,LateralMovementStartTime,FileDownloadStart,FileDownloadEnd,OutgoingStartTime,OutgoingEndTime,CompromiseDuration,EscalationDuration,FileDownloadDuration,TimeToExfiltration,CompromiseToExfilDuration,URLsAccessed,FilesDownloaded,CommandsExecuted,OperationTimeLine,CommandTimeLines,FileTimeLines,TimeBetweenStages,RiskScore,RiskFactor


Another version


let SuspiciousCountries=dynamic(['CN','RU']);
let KnownAdmins = dynamic(['admin@company.com', 'it-support@company.com']);
let SuspiciousFileNames=dynamic([ "password", "credential", "secret", "salary","salaries", "confidential"]);
let VPNRanges = dynamic(['10.50.0.0/16', '10.60.0.0/16']);
let SuspiciousExtension = dynamic(['.key', '.pem', '.pfx', '.p12', '.csv' ]);
let OfficeActivity = datatable(
    TimeGenerated: datetime,
    UserId: string,
    Operation: string,
    ClientIP: string,
    SourceFileName: string,
    SourceFileExtension: string,
    SiteUrl: string,
    ItemType: string
)[
    // Normal file access
    datetime(2025-10-20 08:45:00), "bob@company.com", "FileAccessed", "198.51.100.25", "Q1_Report.xlsx", "xlsx", "https://company.sharepoint.com/sites/finance", "File",
    datetime(2025-10-20 09:15:00), "charlie@company.com", "FileModified", "192.0.2.100", "Project_Plan.docx", "docx", "https://company.sharepoint.com/sites/projects", "File",    
    // ATTACK: Mass file download (20 minutes after compromise)
    datetime(2025-10-20 10:20:00), "alice@company.com", "FileDownloaded", "185.220.101.52", "employee_database.csv", "csv", "https://company.sharepoint.com/sites/hr", "File",
    datetime(2025-10-20 10:20:15), "alice@company.com", "FileDownloaded", "185.220.101.52", "salaries_2025.xlsx", "xlsx", "https://company.sharepoint.com/sites/hr", "File",
    datetime(2025-10-20 10:20:30), "alice@company.com", "FileDownloaded", "185.220.101.52", "customer_list.xlsx", "xlsx", "https://company.sharepoint.com/sites/sales", "File",
    datetime(2025-10-20 10:20:45), "alice@company.com", "FileDownloaded", "185.220.101.52", "financial_records.xlsx", "xlsx", "https://company.sharepoint.com/sites/finance", "File",
    datetime(2025-10-20 10:21:00), "alice@company.com", "FileDownloaded", "185.220.101.52", "source_code.zip", "zip", "https://company.sharepoint.com/sites/engineering", "File",
    datetime(2025-10-20 10:21:15), "alice@company.com", "FileDownloaded", "185.220.101.52", "api_keys.txt", "txt", "https://company.sharepoint.com/sites/devops", "File",
    datetime(2025-10-20 10:21:30), "alice@company.com", "FileDownloaded", "185.220.101.52", "backup_credentials.txt", "txt", "https://company.sharepoint.com/sites/admin", "File",    
    // Normal activity
    datetime(2025-10-20 11:00:00), "bob@company.com", "FileAccessed", "198.51.100.25", "meeting_notes.docx", "docx", "https://company.sharepoint.com/sites/general", "File"
];
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    Account: string,
    EventID: int,
    Activity: string,
    IPAddress: string,
    CommandLine: string
)[
    // Normal workstation activity
    datetime(2025-10-20 08:00:00), "WKS-001", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", "",
    datetime(2025-10-20 08:05:00), "WKS-002", "CORP\\charlie", 4624, "An account was successfully logged on", "192.0.2.100", "",
    // ATTACK: Lateral movement (10 minutes after compromise)
    datetime(2025-10-20 10:10:00), "SRV-DC01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    datetime(2025-10-20 10:11:00), "SRV-FILE01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    datetime(2025-10-20 10:12:00), "SRV-SQL01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    datetime(2025-10-20 10:13:00), "SRV-WEB01", "CORP\\alice", 4624, "An account was successfully logged on", "185.220.101.52", "",
    // ATTACK: Credential dumping (15 minutes after compromise)
    datetime(2025-10-20 10:15:00), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "185.220.101.52", "powershell.exe Invoke-Mimikatz -DumpCreds",
    datetime(2025-10-20 10:15:30), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "185.220.101.52", "cmd.exe /c reg save HKLM\\SAM C:\\temp\\sam.hive",
    datetime(2025-10-20 10:16:00), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "185.220.101.52", "cmd.exe /c reg save HKLM\\SYSTEM C:\\temp\\system.hive",
    datetime(2025-10-20 10:15:30), "SRV-DC01", "CORP\\alice", 4688, "A new process has been created", "10.220.101.52", "cmd.exe /c reg save HKLM\\SAM C:\\temp\\sam.hive",
    // Normal activity
    datetime(2025-10-20 10:30:00), "WKS-003", "CORP\\bob", 4624, "An account was successfully logged on", "198.51.100.25", ""
];
let SigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: string,
    ResultType: string,
    ResultDescription: string,
    AppDisplayName: string
)[
    // Normal morning logins
    datetime(2025-10-20 08:15:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Office 365",
    datetime(2025-10-20 08:20:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "0", "Success", "SharePoint",
    datetime(2025-10-20 08:30:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Office 365",
    // ATTACK: Brute force on alice's account
    datetime(2025-10-20 10:00:01), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:15), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:29), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:44), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:00:58), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:01:12), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:01:27), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    datetime(2025-10-20 10:01:41), "alice@company.com", "185.220.101.52", "Moscow, RU", "50126", "Invalid username or password", "Office 365",
    // ATTACK: Successful compromise
    datetime(2025-10-20 10:03:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "0", "Success", "Azure Portal",
    datetime(2025-10-20 10:03:00), "alice@company.com", "185.220.101.52", "Moscow, RU", "50216", "Invalid username or password", "Azure Portal",
    // Normal activity from other users
    datetime(2025-10-20 10:05:00), "bob@company.com", "198.51.100.25", "London, UK", "0", "Success", "Teams",
    datetime(2025-10-20 10:10:00), "charlie@company.com", "192.0.2.100", "Tokyo, JP", "0", "Success", "OneDrive",
    // More normal alice activity (legitimate user still working)
    datetime(2025-10-20 10:15:00), "alice@company.com", "203.0.113.50", "New York, US", "0", "Success", "Teams"
];
let AuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: string,
    TargetResources: string,
    Result: string,
    Category: string,
    IPAddress: string
)[
    // Normal admin work
    datetime(2025-10-20 08:30:00), "Add member to group", "admin@company.com", "IT-Support", "Success", "GroupManagement", "10.0.1.100",
    datetime(2025-10-20 09:00:00), "Reset user password", "admin@company.com", "bob@company.com", "Success", "UserManagement", "10.0.1.100",    
    // ATTACK: Privilege escalation (5 minutes after compromise)
    datetime(2025-10-20 10:05:00), "Add member to group", "alice@company.com", "Domain Admins", "Success", "GroupManagement", "185.220.101.52",
    datetime(2025-10-20 10:05:30), "Add member to group", "alice@company.com", "Enterprise Admins", "Success", "GroupManagement", "185.220.101.52",
    datetime(2025-10-20 10:06:00), "Update service principal", "alice@company.com", "API-Access-Full", "Success", "ApplicationManagement", "185.220.101.52",    
    // Normal activity
    datetime(2025-10-20 11:00:00), "Update user profile", "bob@company.com", "bob@company.com", "Success", "UserManagement", "198.51.100.25"
];
let SignInLogsCount=toscalar((SigninLogs |summarize count()));
SigninLogs
|where ResultType == 0
|extend Country=split(Location,",")[1]
|summarize 
    SuccessCount=count(),
    FirstSuccess=min(TimeGenerated),
    LastSuccess=max(TimeGenerated),
    SuccessCountries=make_set(Country)
    by UserPrincipalName,SuccessIP=IPAddress
|join kind = inner(SigninLogs
|where ResultType != 0
|extend Country=split(Location,",")[1]
|summarize 
    FailureCount=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated),
    FailureCountries=make_set(Country),
    FailedTimeStamps=make_list(TimeGenerated)
    by UserPrincipalName,FailedIP=IPAddress
 ) on UserPrincipalName
| mv-apply FailedTimeStamps on (
    where FailedTimeStamps <FirstSuccess
    |summarize FailureBeforesuccess=count() by UserPrincipalName
)
|where FailureBeforesuccess >5
| extend RiskScore=iff(UserPrincipalName has_any (KnownAdmins),50,25)
| extend RiskFactor=iff(UserPrincipalName has_any (KnownAdmins),"Admin BruteForce","User BruteForce")
| extend RiskScore=RiskScore+iff((datetime_part( 'hour',FirstSuccess)>18 or datetime_part( 'hour',FirstSuccess)<8) ,50,25)
| extend RiskFactor=strcat(RiskFactor,iff((datetime_part( 'hour',FirstSuccess)>18 or datetime_part( 'hour',FirstSuccess)<8) ,"\nBrute force post office hours","\nBrute Force in Office Hours"))
| extend RiskScore=RiskScore+iff(ipv4_is_in_any_range(SuccessIP,VPNRanges),25,50)
| extend RiskFactor=strcat(RiskFactor,iff(ipv4_is_in_any_range(SuccessIP,VPNRanges),"\nKnown VPN Range","\nUnknown VPN Range"))
| extend RiskScore= RiskScore+iff(SuccessCountries has_any (SuspiciousCountries),50,0)
| extend RiskFactor = strcat(RiskFactor,iff(SuccessCountries has_any (SuspiciousCountries),"\nAccess from Suspicious Countries",""))
|extend TimeBetweenStages=strcat("Failure To Success: ",(datetime_diff('minute',FirstSuccess,FirstFailure))," minutes")
|join kind = leftouter  (AuditLogs
|where OperationName =="Add member to group" and TargetResources contains "admin"
|summarize GroupsAdded=make_set(TargetResources),FirstEscalation=min(TimeGenerated),LastEscalation=max(TimeGenerated),AuditCount=count() by IPAddress
) on $left.SuccessIP==$right.IPAddress
| extend TimeBetweenStages=strcat(TimeBetweenStages,"\nBruteForce to Privilege Escalation :",datetime_diff('minute',FirstEscalation,FirstSuccess)," minutes")
|extend User=tostring(split(UserPrincipalName,"@")[0])
| extend UserType = gettype(User)
| extend RiskScore=RiskScore+iff(array_length(GroupsAdded)>0,50,0)
| extend  RiskFactor=strcat(RiskFactor,iff(array_length(GroupsAdded)>0,"\n Users Added to Admin Group",""))
|join kind=leftouter (
    SecurityEvent
    | extend User=tostring(split(Account,"\\")[1])
    | summarize
        LateralMovementCount=count(),
        HostCount=dcount(Computer),
        HostsAccessed=make_set(Computer),
        CommandsExecuted=make_list(CommandLine),
        FirstMovement=min(TimeGenerated),
        LastMovement=max(TimeGenerated),
        EventIDs=make_set(EventID) by User,IPAddress
    |extend  CommandsExecuted=set_difference(CommandsExecuted,dynamic([""]))
    | where HostCount >1
) on IPAddress and User
| extend TimeBetweenStages=strcat(TimeBetweenStages,"\n First Escalation to First Movement: ", datetime_diff('minute',FirstMovement,FirstEscalation)," minutes")
| extend RiskScore=RiskScore+iff(HostCount >1,50,0)
| extend  RiskFactor=strcat(RiskFactor,iff(HostCount >1,"\n User accessed More than 1 host",""))
| join kind=leftouter (OfficeActivity
| where Operation =="FileDownloaded"
|summarize 
    FilesDownloaded=make_set(SourceFileName),
    SuspiciousFiles= set_difference(make_set(iff(tolower(SourceFileName) has_any (SuspiciousFileNames),SourceFileName,"")),dynamic([""])),
    FileExtensions=make_set(SourceFileExtension),
    SuspiciousFileExtension= set_difference(make_set(iff(tolower(SourceFileExtension) has_any (SuspiciousExtension),SourceFileExtension,"")),dynamic([""])),
    URLsAccessed=make_set(SiteUrl),
    FirstDownload=min(TimeGenerated),
    LastDownload=max(TimeGenerated),
    FileCount=dcount(SourceFileName),
    DataCollectionCount=count()
    by UserId,ClientIP
) on $left.UserPrincipalName==$right.UserId
|extend RiskScore=RiskScore+iff(FileCount >0,50,0)
| extend  RiskFactor=strcat(RiskFactor,iff(FileCount >0,"\n Multiple Files downloaded",""))
|extend  TimeBetweenStages=strcat(TimeBetweenStages,"\n First Lateral Movement To First Exfiltration: ",datetime_diff( 'minute',FirstDownload,FirstMovement)," minutes")
| extend TimeToCompletion=datetime_diff('minute',FirstSuccess,FirstDownload)
| extend RiskScore = case (TimeToCompletion<10, todouble(2*RiskScore),
TimeToCompletion between (10 .. 30),todouble(1.5*RiskScore),
TimeToCompletion between (31 ..120 ), todouble(RiskScore),
todouble(0.7*RiskScore))
|extend RiskFactor=strcat(RiskFactor,case(
    TimeToCompletion<10, "\n Time From First to Last stage is less than 10 minutes",
TimeToCompletion between (10 .. 30),"\n Time From First to Last stage is between 10 and 30 minutes",
TimeToCompletion between (31 ..120 ), "\n Time From First to Last stage is between 31 and 120 minutes",
"\n Time From First to Last stage is greater than 120 minutes"
))
|extend SuspiciousFileCount=array_length(SuspiciousFiles)
| extend SuspiciousExtensionCount=array_length(SuspiciousFileExtension)
| extend  RiskScore= iff(SuspiciousFileCount >0,50,0)
| extend RiskFactor=strcat(RiskFactor,iff(SuspiciousFileCount >0,"\nSuspicious Files Downloaded",""))
| extend  RiskScore= RiskScore+iff(SuspiciousExtensionCount >0,50,0)
| extend RiskFactor=strcat(RiskFactor,iff(SuspiciousExtensionCount >0,"\nSuspicious Extension Downloaded",""))
| extend Severity = case(RiskScore >=100,"CRITICAL",
RiskScore>=75,"HIGH",
RiskScore>=50,"MEDIUM",
RiskScore>=25,"LOW","INFORMATONAL")
| extend SignInLogsCount=SignInLogsCount
|extend RowsProcessed=SuccessCount+FailureCount+AuditCount+LateralMovementCount+DataCollectionCount
| extend InvestigationSummary=strcat(
    "\nATTACK TIMELINE\n",
    "===============\n",
    "Brute Force\n",
    "-----------\n"
    "- ",FailureCount," Failures from the IP ",IPAddress,"\n",
    "- FirstFailure: ",FirstFailure,"\n",
    "- Compromise Time: ",FirstSuccess,"\n",
    "- Compromised User: ",UserPrincipalName,"\n\n",
    "Privilege Escalation \n",
    "--------------------\n"
    "- Groups Added:  ",GroupsAdded,"\n",
    "- FirstEscalation: ",FirstEscalation,"\n",
    "- BruteForce To Escalation Time: ",datetime_diff('minute',FirstEscalation,FirstSuccess)," minutes\n\n",
    "Lateral Movement \n",
    "----------------\n",
    "- Hosts Accessed: ",HostsAccessed,"\n",
    "- Commands Executed: ",CommandsExecuted,"\n",
    "- First Lateral Movement: ",FirstMovement,"\n",
    "- Escalation to Movement Time: ",datetime_diff('minute',FirstMovement,FirstEscalation)," minutes\n\n",
    "Lateral Movement \n",
    "----------------\n",
    " - Files Downloaded: ",FilesDownloaded,"\n",
    " - Sites Accessed: ",URLsAccessed,"\n",
    " - First Download: ",FirstDownload,"\n",
    " - Movement to Exfiltration: ",datetime_diff('minute',FirstDownload,FirstMovement)," minutes\n\n",
    "TOTAL ATTACK TIMELINE: ",datetime_diff('minute',FirstDownload,FirstSuccess)," minutes\n",
    "RISK SCORE: ",RiskScore,"\n",
    "SEVERITY: ",Severity,"\n"    
    )
|project 
    UserPrincipalName,
    ExternalIP=SuccessIP,
    SuccessCountries,
    FailureCountries,
    GroupsAdded,
    HostsAccessed,
    FileExtensions,
    FilesDownloaded,
    SuspiciousFiles,
    URLsAccessed,
    TimeBetweenStages,
    RiskFactor,
    RiskScore,
    FirstSuccess,
    FirstFailure,
    LastFailure,
    LastSuccess,
    FirstEscalation,
    LastEscalation,
    FirstMovement,
    LastMovement,
    FirstDownload,
    LastDownload,
    SignInLogsCount,
    RowsProcessed,
    FailureCount,
    SuccessCount,
    FailureBeforesuccess,
    HostCount,
    AuditCount,
    LateralMovementCount,
    FileCount,
    DataCollectionCount,
    SuspiciousFileCount,
    SuspiciousExtensionCount,
    InvestigationSummary
    
    
