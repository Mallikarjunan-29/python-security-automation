THREAT_CRITICAL_SCORE=75
THREAT_HIGH_SCORE=50
THREAT_MEDIUM_SCORE=25
THREAT_LOW_SCORE=0
BRUTE_FORCE='''index="botsv3" OR index="botsv2" earliest=0
| bin _time span=15m
| search EventCode IN(4625) AND (Account_Name !="-" AND Account_Name !="*$")
| stats count by Account_Name,_time,host
| rename Account_Name as Users,host as Endpoint, count as FailureCount
| where FailureCount>5
| eval Timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table Timestamp,Users, Endpoint,FailureCount'''

