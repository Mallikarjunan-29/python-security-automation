from colorama import Fore,Style,Back
import operator
from collections import Counter

#Checks if the IP is internal or external and returns allowed or blocked.
def check_ip(ip):
     if ip.startswith("192.168") or ip.startswith("172.16")or ip.startswith("10."):
          return "Allow"
     else:
          return "Block"
     
def summarize(AllowedIPs,BlockedIPs,TotalIPs,Allowcount,BlockCount):
    print(Fore.BLACK)
    print(f"{Allowcount} IPs allowed and {BlockCount} IPs are blocked")
    print(f"Allowed IPs \n {AllowedIPs}")
    print(f"Blocked IPs \n {BlockedIPs}")
    print(f"Total IPs Processed: \n {len(TotalIPs)}")
    print(f"List of IPs Processed:\n{TotalIPs}")
    print(f"{len(AllowedIPs)} IPs allowed and {len(BlockedIPs)} Blocked")
    TopBlockedIps=get_sorted_ips(BlockedIPs,3)
    print(f"Top IPs blocked:")
    for n in TopBlockedIps:
        print(n)
    
def get_sorted_ips(blocked_ips,n=2):
    blocked_ips=list(dict(sorted(blocked_ips.items(),key=operator.itemgetter(1),reverse=True)).keys())
    return blocked_ips[:n]

def process_summary(ips):
    Allowcount=0
    BlockCount=0    
    AllowedIPs= []
    BlockedIPs=[]
    TopIPsBlocked=[]
    TotalIPs={}

    for ip in ips:  
        if "Allow" in check_ip(ip):
            Allowcount+=1
            AllowedIPs.append(ip)
            
        else:
            BlockCount+=1
            BlockedIPs.append(ip)
    TotalIPs=dict(Counter(ips))
    #AllowedIPs={i:AllowedIPs.count(i) for i in AllowedIPs}
    AllowedIPs= dict(Counter(AllowedIPs))
    #BlockedIPs={i:BlockedIPs.count(i) for i in BlockedIPs}
    BlockedIPs = dict(Counter(BlockedIPs))
    #BlockedIPs=list(dict(sorted(BlockedIPs.items(),key=operator.itemgetter(1),reverse=True)).keys())
    #BlockedIPs=list(SortedBlockedIps.keys())
    summarize(AllowedIPs,BlockedIPs,TotalIPs,Allowcount,BlockCount)

if __name__ =="__main__":
    ips=['192.168.10.1','172.16.10.10','10.10.10.10','1.1.1.1','8.8.8.8','8.8.8.8','20.20.20.20','20.20.20.20','8.8.8.8','20.25.20.20']
    process_summary(ips)
               
