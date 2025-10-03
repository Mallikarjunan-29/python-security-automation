from colorama import Fore , Style
def check_ip(ip=""):
    if ip.startswith("192.168") or ip.startswith("172.16")or ip.startswith("10."):
        print (Fore.GREEN +Style.BRIGHT+ f"{ip} allowed in firewall")
    else:
        print(Fore.RED+ Style.BRIGHT+ f"{ip} denied in firewall")

ips=['192.168.10.1','172.16.10.10','10.10.10.10','1.1.1.1']
for ip in ips:
    check_ip(ip)