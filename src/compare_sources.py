"""
Compare single-source vs multi-source intelligence.
"""
import os
import sys
sys.path.append(os.getcwd())
from src.ioc_enricher import IOCEnricher

print(f"\n{'='*80 }")
print("Comparing single and multi source enricher")
print(f"\n{'='*80 }")
ips=['1.1.1.1','80.82.77.33','36.140.33.10','8.8.8.8']
enricher = IOCEnricher()
for ip in ips:
    abuse_result=enricher.check_ip_in_AbuseDB(ip)
    print(f"\n{'='*80 }")
    print("Abuse Only")
    print(f"         Score:          {abuse_result['abuse_threat_score']}")
    print(f"         Recommendation: {abuse_result['abuse_recommendation']}")
    print(f"\n{'='*80 }")
    multi_result=enricher.enrich_multi_source_ip(ip)
    print(f"\n{'='*80 }")
    print("Multi Source Only")
    print(f"         Abuse Score:     {multi_result['abuse_threat_score']}")
    print(f"         VT Score:        {multi_result['vt_threat_score']}")
    print(f"         Score:           {multi_result['combined_score']}")
    print(f"         Confidence:      {multi_result['confidence']}")
    print(f"         Severity:        {multi_result.get('threat_level','LOW')}")
    print(f"         Recommendation:  {multi_result['recommendation']}")
    print(f"\n{'='*80 }")
    