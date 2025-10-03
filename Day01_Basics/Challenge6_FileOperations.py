import os
import re
import Challenge5_Functions as C5
basefolder = os.path.dirname(os.path.dirname(__file__))
logfile=os.path.join(basefolder,"logs","auth.log")
with open(logfile,"r") as f:
    log=f.readlines()
ips=[]
pattern=re.compile(r"((\d{1,3}\.){3}\d{1,3})")
for items in log:
    if "Failed" in items and pattern.search(items):
        ips.append(pattern.search(items).group(0))
C5.process_summary(ips)






