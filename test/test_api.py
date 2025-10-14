import requests
import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from src.ioc_enricher import IOCEnricher

test= IOCEnricher()
#test.ip_address="8.8.8.8"
#test.check_ip()
#test.check_ip_in_VT("8.8.8.8")
filepath=os.path.join(os.path.dirname(os.path.dirname(__file__)),"data/botsv3_ips.csv")
test.enrich_csv(filepath)
#test.enrich_ip("23.243.244.38")
