import os
import sys
import requests
sys.path.append(os.getcwd())

from src.integrations import slack_integration
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
      }
    },
    "source": {
      "ip": "91.212.45.99",
      "geo": {
        "country": "Russia",
        "city": "Moscow",
        "asn": {
          "asn": "AS9009",
          "org": "M247 Ltd"
        }
      },
      "device": {
        "os": "Windows",
        "browser": {
          "name": "Chrome",
          "version": "120.1"
        }
      }
    }
  },
  "target": {
    "resource": "AWS Console",
    "account_id": "987654321000",
    "actions_attempted": [
      "ec2:DescribeInstances",
      "s3:ListBuckets",
      "iam:ListUsers"
    ]
  },
  "signals": {
    "failed_logins_past_hour": 3,
    "impossible_travel": True,
    "prior_login": {
      "timestamp": "2025-12-06T17:00:12Z",
      "source_ip": "172.58.21.11",
      "geo": {
        "country": "USA",
        "city": "Detroit"
      }
    },
    "ioc": {
      "ips": [
        "91.212.45.99",
        "185.220.101.4",
        "45.67.229.44"
      ],
      "domains": [
        "malicious-cn.xyz",
        "stealer-c2.net",
        "dropzone.ru"
      ],
      "urls": [
        "http://stealer-c2.net/payload",
        "http://malicious-cn.xyz/login"
      ]
    }
  },
  "raw_event": {
    "cloudtrail": {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "userName": "john.doe@company.com"
      },
      "eventSource": "signin.amazonaws.com",
      "eventName": "ConsoleLogin",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "91.212.45.99",
      "responseElements": {
        "ConsoleLogin": "Failure"
      },
      "additionalEventData": {
        "MobileVersion": "No",
        "LoginTo": "https://console.aws.amazon.com/console/home",
        "Redirect": "False"
      }
    },
    "payload_size_bytes": 20480,
    "raw_log_lines": [
      "User login attempt detected...",
      "Authentication failure due to incorrect credentials...",
      "Additional context inside raw logs..."
    ]
  }
}
slack=slack_integration.SlackIntegration()
print(slack.alert_flattener(alert))

def send_message():
    url=os.getenv("SLACK_WEBHOOK_URL")
    header={
        "Content-type": "application/json"
    }
    data=        {"text":"Hello, World!"
    }
    response=requests.post(url,headers=header,json=data)

if __name__=="__main__":
    send_message()