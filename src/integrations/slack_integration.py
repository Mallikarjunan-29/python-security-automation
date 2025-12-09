import sys
import os
import requests
sys.path.append(os.getcwd())
from src.integrations.base_integration import BaseIntegration
class SlackIntegration(BaseIntegration):
    def __init__(self):
        super().__init__("Slack")
        self.url=os.getenv("SLACK_WEBHOOK_URL")
    
    def alert_flattener(self,alert,prefix=""):
        flat_alert={}
        for key,values in alert.items():
            if not isinstance(values,dict):
                if prefix=="":
                    flat_alert[key]=values
                else:
                    flat_alert[f"{prefix}.{key}"]=values
            else:
                flat_alert.update(self.alert_flattener(values,key))
        return flat_alert

    def send_alert_notification(self, slack_data):
        url=os.getenv("SLACK_WEBHOOK_URL")
        header={
            "Content-Type":"application/json"
        }
        data = {
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": slack_data['title']
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text":f"*Classification:* {slack_data['classification']}" }
            ]
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text":f"*Confidence:* {slack_data['confidence']}" }
            ]
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text":f"*Severity:* {slack_data['severity']}"}
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Reasoning:*\n{slack_data['reasoning']}"
            }
        }
    ],
    "attachments": [
        {
            "text": slack_data['runbook'],
            "fallback": f"Runbook for alert {slack_data['title']}"
        }
    ]
}

        response=requests.post(url,headers=header,json=data)
        response.raise_for_status()
        
    
    
        