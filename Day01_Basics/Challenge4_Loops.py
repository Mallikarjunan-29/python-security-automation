from colorama import Fore,Style,Back
import operator
from collections import Counter
Allowcount=0
BlockCount=0
AllowedIPs= []
BlockedIPs=[]
TotalIPs={}
TopIPsBlocked=[]
def check_ip(ip):
     if ip.startswith("192.168") or ip.startswith("172.16")or ip.startswith("10."):
          return "Allow"
     else:
          return "Block"
     
ips=['192.168.10.1','172.16.10.10','10.10.10.10','1.1.1.1','8.8.8.8','8.8.8.8','20.20.20.20','20.20.20.20','8.8.8.8','20.25.20.20']
for ip in ips:
     if "Allow" in check_ip(ip):
          Allowcount+=1
          AllowedIPs.append(ip)
          
     else:
          BlockCount+=1
          BlockedIPs.append(ip)

#AllowedIPs={i:AllowedIPs.count(i) for i in AllowedIPs}
AllowedIPs= dict(Counter(AllowedIPs))
#BlockedIPs={i:BlockedIPs.count(i) for i in BlockedIPs}
BlockedIPs = dict(Counter(BlockedIPs))
TotalIPs.update(AllowedIPs)
TotalIPs.update(BlockedIPs)
print(Fore.BLACK)
print(f"{Allowcount} IPs allowed and {BlockCount} IPs are blocked")
print(f"Allowed IPs \n {AllowedIPs}")
print(f"Blocked IPs \n {BlockedIPs}")
print(f"Total IPs Processed: \n {len(TotalIPs)}")
print(f"List of IPs Processed:\n{list(TotalIPs.keys())}")
print(f"{len(AllowedIPs)} IPs allowed and {len(BlockedIPs)} Blocked")
SortedBlockedIps=dict(sorted(BlockedIPs.items(),key=operator.itemgetter(1),reverse=True))
BlockedIPs=list(SortedBlockedIps.keys())
TopCount=0
print(f"Top IPs blocked:")
while TopCount<2:
    print(BlockedIPs[TopCount])
    TopCount+=1



          
