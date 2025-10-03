from colorama import Fore,Style,Back
import operator
from collections import Counter

#Checks if the IP is internal or external and returns allowed or blocked.
def check_ip(ip):
     if ip.startswith("192.168") or ip.startswith("172.16")or ip.startswith("10."):
          return "Allow"
     else:
          return "Block"
     
def summarize(AllowedIPs,BlockedIPs,SuspiciousIPs,TotalIPs):
    print(Fore.BLACK)
    print(f"{len(AllowedIPs)} IPs allowed and {len(BlockedIPs)} IPs are blocked")
    print(f"\nAllowed IPs \n")
    print_list(AllowedIPs.keys())
    print(f"\nBlocked IPs \n")
    print_list(BlockedIPs.keys())
    print(f"\nSuspicious IPs \n")
    print_list(SuspiciousIPs)
    print(f"\nTotal IPs Processed: \n {len(TotalIPs)}")
    print(f"\nList of IPs Processed:\n")
    print_list(TotalIPs.keys())
    TopBlockedIps=get_sorted_ips(BlockedIPs,3)
    print(f"\nTop IPs blocked:")
    print_list(TopBlockedIps)

def print_list(ips):
    for n in ips:
        print(n)

def get_sorted_ips(blocked_ips,n=2):
    blocked_ips=list(dict(sorted(blocked_ips.items(),key=operator.itemgetter(1),reverse=True)).keys())
    return blocked_ips[:n]

def process_summary(ips):
    AllowedIPs= []
    BlockedIPs=[]
    TotalIPs={}
    SuspiciousIPs=[]

    for ip in ips:  
        if "Allow" in check_ip(ip):
            AllowedIPs.append(ip)
            
        else:
            BlockedIPs.append(ip)
    TotalIPs=dict(Counter(ips))
    #AllowedIPs={i:AllowedIPs.count(i) for i in AllowedIPs}
    AllowedIPs= dict(Counter(AllowedIPs))
    #BlockedIPs={i:BlockedIPs.count(i) for i in BlockedIPs}
    BlockedIPs = dict(Counter(BlockedIPs))
    #BlockedIPs=list(dict(sorted(BlockedIPs.items(),key=operator.itemgetter(1),reverse=True)).keys())
    #BlockedIPs=list(SortedBlockedIps.keys())
    # Determining suspicious IPs
    for keys,values in AllowedIPs.items():
        if values>2:
            SuspiciousIPs.append(keys)
    for items in SuspiciousIPs:
        del(AllowedIPs[items])
    summarize(AllowedIPs,BlockedIPs,SuspiciousIPs,TotalIPs)

#if __name__ =="__main__":
#    ips=['192.168.10.1','172.16.10.10','10.10.10.10','1.1.1.1','8.8.8.8','8.8.8.8','20.20.20.20','20.20.20.20','8.8.8.8','20.25.20.20']
#    process_summary(ips)
               
