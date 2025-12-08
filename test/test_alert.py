import sys
import time
import json
import os
sys.path.append(os.getcwd())
from ai_projects import day1_alertclassifier
from src import logger_config
from src.cache_handler import CacheHandler

from logging import getLogger
logger=getLogger(__name__)
total_timing={
    'TI_CacheLoad':0,
    'TI_CachePrune':0,
    'AI_CacheLoad':0,
    'AI_CachePrune':0,
    'TILookup':0,
    'TI_FromCache':0,
    'AI_ContentGenerate':0,
    'AI_FromCache':0,
    'ParseAlert':0,
    'CalculateCost':0,
    'TI_WriteCache':0,
    'AI_WriteCache':0
}
test_cases_1 = [
  # BRUTE FORCE ATTACKS (10 alerts)
  {
    "name": "Brute Force 1 - TOR",
    "alert": {
      "user": "alice@company.com",
      "source_ip": "193.32.162.157",
      "failed_logins": 8,
      "success": True,
      "time": "02:00",
      "location": "Moscow, RU"
    },
    "name": "Brute Force 1 - TOR",
    "alert": {
      "user": "alice@company.com",
      "source_ip": "45.115.176.136",
      "failed_logins": 5,
      "success": True,
      "time": "02:00",
      "location": "Haryana, IN"
    }
    
  }
]
test_cases_50 = [
  # BRUTE FORCE ATTACKS (10 alerts)
  {
    "name": "Brute Force 1 - TOR",
    "alert": {
      "user": "alice@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 8,
      "success": True,
      "time": "02:00",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "TOR exit node, high failures"
  },
  {
    "name": "Brute Force 2 - Same TOR",
    "alert": {
      "user": "bob@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 9,
      "success": True,
      "time": "02:15",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same TOR IP, different target - SHOULD CACHE"
  },
  {
    "name": "Brute Force 3 - Same TOR",
    "alert": {
      "user": "charlie@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 7,
      "success": True,
      "time": "02:30",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same TOR IP, third target - SHOULD CACHE"
  },
  {
    "name": "Brute Force 4 - Different TOR",
    "alert": {
      "user": "david@company.com",
      "source_ip": "185.220.102.88",
      "failed_logins": 12,
      "success": True,
      "time": "03:00",
      "location": "Russia"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Different TOR node, similar pattern"
  },
  {
    "name": "Brute Force 5 - Failed Attack",
    "alert": {
      "user": "eve@company.com",
      "source_ip": "185.220.103.15",
      "failed_logins": 15,
      "success": False,
      "time": "03:30",
      "location": "Russia"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Failed but still attack attempt"
  },
  {
    "name": "Brute Force 6 - VPN Provider",
    "alert": {
      "user": "frank@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 10,
      "success": True,
      "time": "04:00",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Data center IP, brute force pattern"
  },
  {
    "name": "Brute Force 7 - Same VPN",
    "alert": {
      "user": "grace@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 8,
      "success": True,
      "time": "04:15",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same VPN IP - SHOULD CACHE"
  },
  {
    "name": "Brute Force 8 - China",
    "alert": {
      "user": "henry@company.com",
      "source_ip": "45.142.215.99",
      "failed_logins": 11,
      "success": True,
      "time": "05:00",
      "location": "China"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Data center, high failures"
  },
  {
    "name": "Brute Force 9 - Netherlands",
    "alert": {
      "user": "iris@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 9,
      "success": True,
      "time": "05:30",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Hosting provider, brute force"
  },
  {
    "name": "Brute Force 10 - Admin Account",
    "alert": {
      "user": "admin@company.com",
      "source_ip": "91.134.124.67",
      "failed_logins": 20,
      "success": True,
      "time": "06:00",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Admin account targeted, high failures"
  },

  # PASSWORD SPRAY ATTACKS (8 alerts)
  {
    "name": "Password Spray 1",
    "alert": {
      "user": "jack@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 1,
      "success": True,
      "time": "07:00",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Low failures, data center IP"
  },
  {
    "name": "Password Spray 2",
    "alert": {
      "user": "karen@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 2,
      "success": True,
      "time": "07:05",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, similar pattern - SHOULD CACHE"
  },
  {
    "name": "Password Spray 3",
    "alert": {
      "user": "larry@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 1,
      "success": True,
      "time": "07:10",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, third target - SHOULD CACHE"
  },
  {
    "name": "Password Spray 4",
    "alert": {
      "user": "mary@company.com",
      "source_ip": "91.134.125.88",
      "failed_logins": 2,
      "success": True,
      "time": "08:00",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Different IP, similar pattern"
  },
  {
    "name": "Password Spray 5",
    "alert": {
      "user": "nancy@company.com",
      "source_ip": "91.134.125.88",
      "failed_logins": 1,
      "success": True,
      "time": "08:05",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP - SHOULD CACHE"
  },
  {
    "name": "Password Spray 6",
    "alert": {
      "user": "oliver@company.com",
      "source_ip": "203.0.113.75",
      "failed_logins": 2,
      "success": True,
      "time": "08:30",
      "location": "Unknown"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Reserved IP range, suspicious"
  },
  {
    "name": "Password Spray 7",
    "alert": {
      "user": "paul@company.com",
      "source_ip": "185.220.104.23",
      "failed_logins": 1,
      "success": True,
      "time": "09:00",
      "location": "Russia"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "TOR node, password spray"
  },
  {
    "name": "Password Spray 8",
    "alert": {
      "user": "quinn@company.com",
      "source_ip": "185.220.104.23",
      "failed_logins": 2,
      "success": True,
      "time": "09:05",
      "location": "Russia"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same TOR - SHOULD CACHE"
  },

  # CREDENTIAL STUFFING (6 alerts)
  {
    "name": "Credential Stuffing 1",
    "alert": {
      "user": "rachel@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 0,
      "success": True,
      "time": "10:00",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Success without failures - leaked creds"
  },
  {
    "name": "Credential Stuffing 2",
    "alert": {
      "user": "steve@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 0,
      "success": True,
      "time": "10:02",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, same pattern - SHOULD CACHE"
  },
  {
    "name": "Credential Stuffing 3",
    "alert": {
      "user": "tina@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 0,
      "success": True,
      "time": "10:04",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, third victim - SHOULD CACHE"
  },
  {
    "name": "Credential Stuffing 4",
    "alert": {
      "user": "uma@company.com",
      "source_ip": "45.142.216.50",
      "failed_logins": 0,
      "success": True,
      "time": "11:00",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Different IP, same pattern"
  },
  {
    "name": "Credential Stuffing 5",
    "alert": {
      "user": "victor@company.com",
      "source_ip": "45.142.216.50",
      "failed_logins": 0,
      "success": True,
      "time": "11:02",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP - SHOULD CACHE"
  },
  {
    "name": "Credential Stuffing 6",
    "alert": {
      "user": "wendy@company.com",
      "source_ip": "185.220.105.77",
      "failed_logins": 0,
      "success": True,
      "time": "11:30",
      "location": "Russia"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "TOR node, credential stuffing"
  },

  # LEGITIMATE USERS (12 alerts)
  {
    "name": "Legitimate 1 - Internal Typo",
    "alert": {
      "user": "xavier@company.com",
      "source_ip": "10.0.5.100",
      "failed_logins": 2,
      "success": True,
      "time": "09:15",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, business hours, low failures"
  },
  {
    "name": "Legitimate 2 - Internal Typo",
    "alert": {
      "user": "yvonne@company.com",
      "source_ip": "10.0.5.101",
      "failed_logins": 1,
      "success": True,
      "time": "09:30",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, business hours"
  },
  {
    "name": "Legitimate 3 - Clean IP",
    "alert": {
      "user": "zack@company.com",
      "source_ip": "203.0.113.25",
      "failed_logins": 1,
      "success": True,
      "time": "10:00",
      "location": "San Francisco, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Clean IP, business hours"
  },
  {
    "name": "Legitimate 4 - VPN Reconnect",
    "alert": {
      "user": "adam@company.com",
      "source_ip": "10.50.1.100",
      "failed_logins": 3,
      "success": True,
      "time": "10:30",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, VPN reconnection"
  },
  {
    "name": "Legitimate 5 - VPN Reconnect",
    "alert": {
      "user": "betty@company.com",
      "source_ip": "10.50.1.101",
      "failed_logins": 2,
      "success": True,
      "time": "11:00",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, business hours"
  },
  {
    "name": "Legitimate 6 - Office IP",
    "alert": {
      "user": "carl@company.com",
      "source_ip": "192.168.1.50",
      "failed_logins": 1,
      "success": True,
      "time": "11:30",
      "location": "Office Network"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Office network, legitimate"
  },
  {
    "name": "Legitimate 7 - Service Account",
    "alert": {
      "user": "svc-backup@company.com",
      "source_ip": "10.0.2.50",
      "failed_logins": 1,
      "success": True,
      "time": "02:00",
      "location": "Internal"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Service account, scheduled job"
  },
  {
    "name": "Legitimate 8 - Service Account",
    "alert": {
      "user": "svc-monitoring@company.com",
      "source_ip": "10.0.2.51",
      "failed_logins": 0,
      "success": True,
      "time": "02:00",
      "location": "Internal"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Service account, automated"
  },
  {
    "name": "Legitimate 9 - Morning Login",
    "alert": {
      "user": "diana@company.com",
      "source_ip": "10.0.6.75",
      "failed_logins": 1,
      "success": True,
      "time": "08:00",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal, morning login"
  },
  {
    "name": "Legitimate 10 - Afternoon",
    "alert": {
      "user": "edward@company.com",
      "source_ip": "10.0.6.76",
      "failed_logins": 0,
      "success": True,
      "time": "14:00",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal, afternoon work"
  },
  {
    "name": "Legitimate 11 - Clean External",
    "alert": {
      "user": "fiona@company.com",
      "source_ip": "203.0.113.100",
      "failed_logins": 0,
      "success": True,
      "time": "09:00",
      "location": "London, UK"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Clean IP, business hours"
  },
  {
    "name": "Legitimate 12 - Mobile",
    "alert": {
      "user": "george@company.com",
      "source_ip": "172.16.5.100",
      "failed_logins": 1,
      "success": True,
      "time": "15:00",
      "location": "Mobile Network"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal mobile range"
  },

  # NEEDS REVIEW (14 alerts)
  {
    "name": "Review 1 - Off-Hours Internal",
    "alert": {
      "user": "admin@company.com",
      "source_ip": "10.0.10.50",
      "failed_logins": 5,
      "success": True,
      "time": "23:00",
      "location": "Internal"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Admin account, off-hours, multiple failures"
  },
  {
    "name": "Review 2 - Travel",
    "alert": {
      "user": "helen@company.com",
      "source_ip": "203.0.113.100",
      "failed_logins": 1,
      "success": True,
      "time": "08:00",
      "location": "London, UK"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Clean IP but unusual location"
  },
  {
    "name": "Review 3 - Data Center",
    "alert": {
      "user": "ian@company.com",
      "source_ip": "91.134.126.99",
      "failed_logins": 3,
      "success": True,
      "time": "12:00",
      "location": "France"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Data center IP, moderate failures"
  },
  {
    "name": "Review 4 - Weekend Login",
    "alert": {
      "user": "julia@company.com",
      "source_ip": "10.0.7.80",
      "failed_logins": 2,
      "success": True,
      "time": "22:00",
      "location": "Internal"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Internal but late night weekend"
  },
  {
    "name": "Review 5 - New Location",
    "alert": {
      "user": "kevin@company.com",
      "source_ip": "203.0.113.150",
      "failed_logins": 2,
      "success": True,
      "time": "07:00",
      "location": "Tokyo, JP"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Clean IP, unusual location"
  },
  {
    "name": "Review 6 - Moderate Failures",
    "alert": {
      "user": "laura@company.com",
      "source_ip": "10.0.8.90",
      "failed_logins": 4,
      "success": True,
      "time": "16:00",
      "location": "Internal"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Internal, moderate failures"
  },
  {
    "name": "Review 7 - Reserved IP",
    "alert": {
      "user": "mike@company.com",
      "source_ip": "203.0.113.50",
      "failed_logins": 4,
      "success": True,
      "time": "18:30",
      "location": "Unknown"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Reserved IP range, suspicious"
  },
  {
    "name": "Review 8 - Hosting Provider",
    "alert": {
      "user": "nina@company.com",
      "source_ip": "91.134.127.111",
      "failed_logins": 2,
      "success": True,
      "time": "13:00",
      "location": "France"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Hosting provider, moderate risk"
  },
  {
    "name": "Review 9 - Unknown Country",
    "alert": {
      "user": "oscar@company.com",
      "source_ip": "203.0.113.175",
      "failed_logins": 3,
      "success": True,
      "time": "10:00",
      "location": "Brazil"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Unusual country, moderate failures"
  },
  {
    "name": "Review 10 - Clean but Suspicious",
    "alert": {
      "user": "peter@company.com",
      "source_ip": "203.0.113.200",
      "failed_logins": 5,
      "success": True,
      "time": "20:00",
      "location": "India"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Clean IP, high failures, unusual location"
  },
  {
    "name": "Review 11 - Admin Off-Hours",
    "alert": {
      "user": "root@company.com",
      "source_ip": "10.0.11.100",
      "failed_logins": 3,
      "success": True,
      "time": "01:00",
      "location": "Internal"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Root account, very late night"
  },
  {
    "name": "Review 12 - VPN Different Country",
    "alert": {
      "user": "rose@company.com",
      "source_ip": "91.134.128.222",
      "failed_logins": 1,
      "success": True,
      "time": "09:00",
      "location": "Germany"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Clean but unexpected location"
  },
  {
    "name": "Review 13 - Moderate Risk",
    "alert": {
      "user": "sam@company.com",
      "source_ip": "203.0.113.225",
      "failed_logins": 6,
      "success": True,
      "time": "19:00",
      "location": "Singapore"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "High failures, distant location"
  },
  {
    "name": "Review 14 - Weekend Admin",
    "alert": {
      "user": "sysadmin@company.com",
      "source_ip": "10.0.12.150",
      "failed_logins": 4,
      "success": True,
      "time": "03:00",
      "location": "Internal"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Admin account, very early morning"
  }
]
test_cases =[
  {
    "name": "Brute Force Attack 1",
    "alert": {
      "user": "alice@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 8,
      "success": True,
      "time": "02:00",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "TOR exit node, brute force pattern"
  },
  {
    "name": "Brute Force Attack 2",
    "alert": {
      "user": "bob@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 9,
      "success": True,
      "time": "02:15",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same attacker, different target - SHOULD CACHE"
  },
  {
    "name": "Brute Force Attack 3",
    "alert": {
      "user": "charlie@company.com",
      "source_ip": "185.220.101.52",
      "failed_logins": 7,
      "success": True,
      "time": "02:30",
      "location": "Moscow, RU"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same attacker, third target - SHOULD CACHE"
  },
  {
    "name": "Password Spray 1",
    "alert": {
      "user": "david@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 1,
      "success": True,
      "time": "03:00",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Different pattern (low failures), different IP"
  },
  {
    "name": "Password Spray 2",
    "alert": {
      "user": "eve@company.com",
      "source_ip": "45.142.214.123",
      "failed_logins": 2,
      "success": True,
      "time": "03:05",
      "location": "Netherlands"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, similar pattern - depends on cache strategy"
  },
  {
    "name": "Legitimate User - Typo",
    "alert": {
      "user": "frank@company.com",
      "source_ip": "10.0.5.100",
      "failed_logins": 2,
      "success": True,
      "time": "09:15",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, business hours, low failures"
  },
  {
    "name": "Legitimate User - VPN",
    "alert": {
      "user": "grace@company.com",
      "source_ip": "203.0.113.25",
      "failed_logins": 1,
      "success": True,
      "time": "10:00",
      "location": "San Francisco, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Clean IP, business hours"
  },
  {
    "name": "Suspicious - Off Hours Internal",
    "alert": {
      "user": "admin@company.com",
      "source_ip": "10.0.10.50",
      "failed_logins": 5,
      "success": True,
      "time": "23:00",
      "location": "Internal"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Internal but suspicious pattern (admin + night + failures)"
  },
  {
    "name": "Credential Stuffing 1",
    "alert": {
      "user": "henry@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 0,
      "success": True,
      "time": "04:00",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Success without failures (leaked creds)"
  },
  {
    "name": "Credential Stuffing 2",
    "alert": {
      "user": "iris@company.com",
      "source_ip": "91.134.123.45",
      "failed_logins": 0,
      "success": True,
      "time": "04:02",
      "location": "France"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Same IP, same pattern - SHOULD CACHE"
  },
  {
    "name": "Failed Brute Force",
    "alert": {
      "user": "jack@company.com",
      "source_ip": "185.220.102.88",
      "failed_logins": 15,
      "success": False,
      "time": "05:00",
      "location": "Russia"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "Attack attempt (failed, but still attack)"
  },
  {
    "name": "Service Account - Normal",
    "alert": {
      "user": "svc-backup@company.com",
      "source_ip": "10.0.2.50",
      "failed_logins": 1,
      "success": True,
      "time": "02:00",
      "location": "Internal"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Service account, internal, scheduled job"
  },
  {
    "name": "VPN Reconnection",
    "alert": {
      "user": "karen@company.com",
      "source_ip": "10.50.1.100",
      "failed_logins": 3,
      "success": True,
      "time": "14:00",
      "location": "New York, US"
    },
    "expected": "FALSE_POSITIVE",
    "notes": "Internal IP, business hours, low failures"
  },
  {
    "name": "Travel - Legitimate",
    "alert": {
      "user": "larry@company.com",
      "source_ip": "203.0.113.100",
      "failed_logins": 1,
      "success": True,
      "time": "08:00",
      "location": "London, UK"
    },
    "expected": "NEEDS_REVIEW",
    "notes": "Clean IP, business hours, but unusual location"
  },
  {
    "name": "Impossible Travel",
    "alert": {
      "user": "mary@company.com",
      "source_ip": "45.142.215.99",
      "failed_logins": 0,
      "success": True,
      "time": "09:00",
      "location": "China"
    },
    "expected": "TRUE_POSITIVE",
    "notes": "If mary logged in from US 1 hour ago, this is impossible"
  }
]

def test_function():
    try:
        
        total_time_start=time.time()
        timing={'TI_CacheLoad':0,
        'TI_CachePrune':0,
        'AI_CacheLoad':0,
        'AI_CachePrune':0,
        'TILookup':0,
        'TI_FromCache':0,
        'AI_ContentGenerate':0,
        'AI_FromCache':0,
        'ParseAlert':0,
        'CalculateCost':0,
        'TI_WriteCache':0,
        'AI_WriteCache':0}
        total_prompt_tokens = 0
        total_completion_tokens = 0
        thoughts_token_count = 0
        #Cache load
        cost=0
        base_path=os.getcwd()
        cache_path=os.path.join(base_path,"cache")
        os.makedirs(cache_path,exist_ok=True)
        #file_name=f"{str(alert['source_ip']).replace(".","_")}.json"
        ti_file_name="cache.json"
        ti_file_path=os.path.join(cache_path,ti_file_name)
        ai_file_name="ai_cache.json"
        ai_file_path=os.path.join(cache_path,ai_file_name)
        cachehandler= CacheHandler()
        ti_cache_data={}
        ai_cache_data={}
        #Loading TI cache
        if os.path.exists(ti_file_path):
            start_time=time.time()
            ti_cache_data=cachehandler.load_cache(ti_file_path) # Loading existing cache
            end_time=time.time()-start_time
            timing.update({"TI_CacheLoad":end_time})
        else:
            timing.update({"TI_CacheLoad":0})
        if ti_cache_data:
            start_time=time.time()
            ti_cache_data=cachehandler.prune_old_cache(ti_cache_data) # Pruning old cache
            end_time=time.time()-start_time
            timing.update({"TI_CachePrune":end_time})
        else:
            timing.update({"TI_CachePrune":0})
        if os.path.exists(ai_file_path):
            start_time=time.time()
            ai_cache_data=cachehandler.load_cache(ai_file_path) # Loading existing cache
            end_time=time.time()-start_time
            timing.update({"AI_CacheLoad":end_time})
        else:
            timing.update({"AI_CacheLoad":0})
        if ai_cache_data:
            start_time=time.time()
            ai_cache_data=cachehandler.prune_old_cache(ai_cache_data) # Pruning old cache
            end_time=time.time()-start_time
            timing.update({"AI_CachePrune":end_time})
        else:
            timing.update({"AI_CachePrune":0})
        for alerts in test_cases_1:
            print(f"="*50)
            print(f"Analysing the alert {alerts['name']}")
            print(f"="*50)

            logger.debug("Classifying alert")
            ai_output,token_count,ti_cache_data,ai_cache_data=day1_alertclassifier.classify_alert(alerts['alert'],ti_cache_data,ai_cache_data,timing)
            print(ai_output)
            if token_count:
                total_prompt_tokens += token_count["PromptToken"]
                total_completion_tokens += token_count["CandidateToken"]
                if token_count["ThoughtsToken"]:
                    thoughts_token_count+=token_count["ThoughtsToken"]
                
                if token_count["PromptToken"]==0:
                    start_time=time.time()
                    print("AI Response loaded from Cache, hence 0 cost")
                    end_time=time.time()-start_time
                    timing.update({"CalculateCost":0})
                else:            
                    start_time=time.time()
                    cost = day1_alertclassifier.calculate_cost(token_count)
                    end_time=time.time()-start_time
                    timing.update({"CalculateCost":end_time})
                    print(f"Token Usage: {token_count}\n")
                    print(f"Cost of this alert analysis: ${cost}\n")
            else:
                logger.error("Token count not available\n")
                print("Token count not available\n")
            print(f"Alert TI cache load timing:{timing['TI_FromCache']}")
            print(f"Alert AI cache load timing:{timing['AI_FromCache']}")
            print(f"TI Look up from cache:{timing['TILookup']}")
            print(f"AI Content Generation time:{timing['AI_ContentGenerate']}")
            print(f"Alert AI Parse timing:{timing['ParseAlert']}")
            print(f"Token Cost Calculation timing:{timing['CalculateCost']}")
            
            total_timing['TI_CacheLoad']+=timing['TI_CacheLoad'] if timing['TI_CacheLoad'] else 0
            total_timing['TI_CachePrune']+=timing['TI_CachePrune'] if timing['TI_CachePrune'] else 0
            total_timing['AI_CacheLoad']+=timing['AI_CacheLoad'] if timing['AI_CacheLoad'] else 0
            total_timing['AI_CachePrune']+=timing['AI_CachePrune'] if timing['AI_CachePrune'] else 0
            total_timing['TI_FromCache']+=timing['TI_FromCache'] if timing['TI_FromCache'] else 0
            total_timing['AI_FromCache']+=timing['AI_FromCache'] if timing['AI_FromCache'] else 0
            total_timing['TI_WriteCache']+=timing['TI_WriteCache'] if timing['TI_WriteCache'] else 0
            total_timing['AI_WriteCache']+=timing['AI_WriteCache'] if timing['AI_WriteCache'] else 0
            total_timing['TILookup']+=timing['TILookup'] if timing['TILookup'] else 0
            total_timing['AI_ContentGenerate']+=timing['AI_ContentGenerate'] if timing['AI_ContentGenerate'] else 0
            total_timing['ParseAlert']+=timing['ParseAlert'] if timing['ParseAlert'] else 0
            total_timing['CalculateCost']+=timing['CalculateCost'] if timing['CalculateCost'] else 0
        # Writing Cache
        if ti_cache_data:
            start_time=time.time()
            cachehandler.write_cache(ti_cache_data,ti_file_path)
            end_time=time.time()-start_time
            timing.update({"TI_WriteCache":end_time})
        if ai_cache_data:
            start_time=time.time()
            cachehandler.write_cache(ai_cache_data,ai_file_path)
            end_time=time.time()-start_time
            timing.update({"AI_WriteCache":end_time})
        total_time=time.time()-total_time_start

        print("BATCH SUMMARY")
        print("="*60)
        print(f"Total Token Usage: {total_prompt_tokens+total_completion_tokens+thoughts_token_count}")
        print(f"Total Cost: ${day1_alertclassifier.calculate_cost({'PromptToken': total_prompt_tokens, 'CandidateToken': total_completion_tokens})}")
        for keys,values in ti_cache_data.items():
            print(f"cache hits for {keys} = {values['CacheHit']}")
        print(f"Threat Intel Overall Cache Load timing:{total_timing['TI_CacheLoad']}")
        print(f"Threat Intel OVerall cache prune timing:{total_timing['TI_CachePrune']}")
        print(f"AI Overall Cache Load timing:{total_timing['AI_CacheLoad']}")
        print(f"AI Overall Cache Prune timing:{total_timing['AI_CachePrune']}")
        print(f"Alert TI cache load timing:{total_timing['TI_FromCache']}")
        print(f"Alert AI cache load timing:{total_timing['AI_FromCache']}")
        print(f"Alert AI Parse timing:{total_timing['ParseAlert']}")
        print(f"Token Cost Calculation timing:{total_timing['CalculateCost']}")
        print(f"TI Cache Write timing:{total_timing['TI_WriteCache']}")
        print(f"AI Cache Write timing:{total_timing['AI_WriteCache']}")
        print(f"TI Look up from cache:{total_timing['TILookup']}")
        print(f"AI Content Generation time:{total_timing['AI_ContentGenerate']}")
        total=0
        for values in total_timing.values():
            total+=values
        print(f"TotalTimeTaken:{total_time}")
    except Exception as e:
        logger.error(e)
        print(e)


def alert_flatten(alert:dict,prefix=""):
    new_alert={}
    for key,value in alert.items():
        if not isinstance(value,dict):
            if prefix=="":
              new_alert[key]=value
            else:
                new_alert[f"{prefix}.{key}"]=value
        else:
            new_alert.update(alert_flatten(value,key))
    return new_alert
        
        
if __name__=="__main__":
    alert={
  "alert_id": "ALRT-99821",
  "name": "Suspicious Console Login",
  "severity": "High",
  "category": "Authentication",
  "timestamp": "2025-12-07T04:22:11Z",
  "actor": {
    "user": {
      "username": "john.doe@company.com",
      "user_id": "AIDA89123XYZ",
      "mfa_enabled": False,
      "roles": ["Admin", "PowerUser"],
      "tags": {
        "department": "Finance",
        "privileged": True
      }}}}
    alert=alert_flatten(alert)
    print(alert)