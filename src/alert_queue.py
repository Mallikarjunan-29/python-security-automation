import logging
import re

logger = logging.getLogger(__name__)

priority_map = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}

def extract_severity(alert):
    """
    Extract severity from dict (nested or flat) or text alert.
    Returns severity string or None if not found.
    """
    if isinstance(alert, dict):
        # top-level severity
        if "severity" in alert:
            return alert["severity"]
        # nested 'alert' dict
        if "alert" in alert and isinstance(alert["alert"], dict):
            return alert["alert"].get("severity", None)
        # check any nested dict
        for v in alert.values():
            if isinstance(v, dict) and "severity" in v:
                return v["severity"]
        return None
    elif isinstance(alert, str):
        # match "severity=XXX" or "severity: XXX"
        match = re.search(r"severity[:=]\s*(\w+)", alert, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

def queue_alert(alerts,context):
    try:
        logger.debug("Alert Queue sorting start",extra={
                'request_id':context.get('request_id'),
                'user_id':context.get('user_id')
            })    

        # normalize to list
        if not isinstance(alerts, list):
            alerts = [alerts]

        normalized_alerts = []

        for alert in alerts:
            # if plain text, wrap it
            if not isinstance(alert, dict):
                alert = {"raw": str(alert)}

            # extract severity
            severity = extract_severity(alert) or "Low"  # default if missing
            priority = priority_map.get(severity.capitalize(), 10)  # unknown = 10

            # attach prioritylevel safely
            alert["prioritylevel"] = priority

            normalized_alerts.append(alert)

        # sort by prioritylevel ascending
        normalized_alerts.sort(key=lambda x: x["prioritylevel"])

        logger.debug("Alert Queue sorting ended",extra={
                'request_id':context.get('request_id'),
                'user_id':context.get('user_id')
            })    
        return normalized_alerts

    except Exception as e:
        logger.error(f"Error in queue_alert: {e}",extra={
                'request_id':context.get('request_id'),
                'user_id':context.get('user_id')
            })    
        return alerts
