import re
from urllib.parse import urlparse
import ipaddress
import os
import sys
import json
sys.path.append(os.getcwd())
from src.logger_config import get_logger
logger=get_logger(__name__)

def extract_ioc(data):
    #Extract IPs
    ips=re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",data)
    valid_ips=[]
    for ip in ips:
        try:
            ipaddress.IPv4Address(ip)
            valid_ips.append(ip)
        except Exception as e:
            logger.error(str(e))
            continue
    
    #Extracting URLs
    data = data.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    data = data.replace("hxxp://", "http://").replace("hxxps://", "https://")
    #url_pattern=r"(?i)(?:(?:https?|hxxp|ftp):\/\/)?(?:[a-z0-9](?:[a-z0-9-]{1,61})?[0-9a-z]?\.)+(?:[a-z]{2,}*)?(?::\d{1,5})?(?:\/[^\s]*)?"
    url_pattern=r"https?:\/\/(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z](?:[a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.)*[a-z]{2,}))(?::\d{1,5})?(?:\/[^\s]*)?"
    valid_urls=[]
    valid_domains=[]
    for match in re.finditer(url_pattern,data,re.IGNORECASE):
        url=match.group()
        if not url.startswith(("http://","https://","ftp://","hxxp://")):
            url="http://"+url
        try:
            parsed=urlparse(url)
            if parsed.netloc:
                # Remove space in urls
                valid_urls.append(url)
                if (parsed.hostname ==  ip for ip in valid_ips):
                    continue
                else:
                    valid_domains.append(parsed.hostname)
        except Exception as e:
            logger.error(str(e))
            continue

    # =============================================================
    # EXTRACTING DOMAINS
    # =============================================================
    domains=re.findall(r"(?i)\b(?:[a-z](?:[a-z0-9-]{1,61}[a-z0-9])?\.)+[a-z]{2,}\b",data) 
    for domain in domains:
        if domains in valid_domains:
            continue
        if is_likely_false_positive(domain):
            continue
        valid_domains.append(domain)
    

    
    ioc={
        "ips":valid_ips,
        "urls":valid_urls,
        "domains":valid_domains
    }
    return ioc

def is_likely_false_positive(domain=str):
    logger.debug("Checking false domains")
    try:
        file_extensions=[
            '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', 
                      '.vbs', '.js', '.jar', '.msi', '.zip', '.rar',
                      '.pdf', '.doc', '.xls', '.ppt'
        ]
        if any(domain.endswith(ext) for ext in file_extensions):
            return True
        logger.debug("False domain check complete")
    except Exception as e:
        logger.error(str(e))

def extract_behavior(alert_text: str) -> str:
    """
    Extracts canonical behavior from alert text for vector DB caching.
    Returns one of the 25 behavior strings.
    """
    if isinstance(alert_text, dict):
        # Sort keys for deterministic hash
        alert_str = json.dumps(alert_text, sort_keys=True)
    else:
        alert_str = str(alert_text)
    text = alert_str.lower()

    # 1. Port Scanning
    if "port scan" in text or "scan-type" in text or "tcp_syn" in text:
        return "port_scan"

    # 2. Horizontal Port Scan (many hosts)
    if "horizontal scan" in text:
        return "horizontal_port_scan"

    # 3. Vertical Port Scan (many ports)
    if "vertical scan" in text:
        return "vertical_port_scan"

    # 4. Beaconing
    if "beaconing" in text or "every " in text and "seconds" in text:
        return "beaconing"

    # 5. C2 Traffic
    if "c2" in text or "command and control" in text or "/api/collect" in text:
        return "c2_traffic"

    # 6. Suspicious DNS
    if "dns tunnel" in text or "base64" in text and "dns" in text:
        return "suspicious_dns"

    # 7. Brute Force Authentication
    if "failed login" in text or "brute force" in text or "password spray" in text:
        return "brute_force_auth"
    
    
    # 13. Data Exfil via DNS
    if "exfil" in text or "exfiltration" in text:
        return "data_exfiltration"


    # 9. Ransomware Behavior
    if "file encryption" in text or "shadow copy" in text:
        return "ransomware_behavior"

    # 10. Lateral Movement via SMB
    if "smb" in text or "psexec" in text or "ipc$" in text:
        return "lateral_movement_smb"

    # 11. Lateral Movement via RDP
    if "rdp" in text and "connection" in text:
        return "lateral_movement_rdp"

    # 12. Data Exfil via HTTP
    if "large post" in text or "data transfer" in text or "upload" in text:
        return "data_exfil_http"

    # 13. Data Exfil via DNS
    if "txt dns" in text or "dns exfil" in text:
        return "data_exfil_dns"

    # 14. Privilege Escalation
    if "privilege escalation" in text or "token impersonation" in text:
        return "privilege_escalation"

    # 15. Suspicious Process Creation
    if "cmd.exe" in text or "powershell" in text or "wscript" in text:
        return "suspicious_powershell"

    # 16. Persistence via Registry
    if "run key" in text or "startup folder" in text:
        return "persistence_registry"

    # 17. Persistence via Scheduled Task
    if "schtasks" in text or "autorun" in text:
        return "persistence_scheduled_task"

    # 18. Suspicious PowerShell
    if "invoke-webrequest" in text or "downloadstring" in text or "iex(" in text:
        return "suspicious_powershell"

    # 19. Unusual Outbound Traffic
    if "unusual destination" in text or "rare ip" in text or "high geo" in text:
        return "unusual_outbound_traffic"

    # 20. Cryptocurrency Mining
    if "xmrig" in text or "cpu usage" in text and "mining pool" in text:
        return "crypto_mining"

    # 21. Malware Callback
    if "callback" in text or "command received" in text:
        return "malware_callback"

    # 22. Fileless Attack
    if "fileless" in text or "in-memory" in text:
        return "fileless_attack"

    # 23. Suspicious Admin Tool
    if "mimikatz" in text or "bloodhound" in text or "adfind" in text:
        return "suspicious_admin_tool_usage"

    # 24. Web Attack Pattern
    if "sql injection" in text or "xss" in text or "lfi" in text or "rfi" in text:
        return "web_attack_pattern"

    
    # 8. Malware Download
    if ".exe" in text or ".dll" in text or "malware download" in text:
        return "malware_download"
    
    # 25. Unknown / fallback
    return "unknown"


if __name__=="__main__":
    ioc=extract_ioc({  "alert_id": "alert-1023",  "timestamp": "2025-11-20T15:30:00Z",  "source_ip": "203.0.113.45", "destination_ip": "198.51.100.22",  "user": "bob@victimcorp.com",  "failed_logins": 5,  "description": "Multiple failed login attempts detected",  "urls": [    "http://8.148.5.67/02.08.2022.exe"  ]})
    print(ioc)