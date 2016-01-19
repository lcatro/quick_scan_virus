##quick_scan_virus.py
---
###How to Using it
		quick_scan_virus.py %file_path%|%directory_path%|all
		quick_scan_virus.py C:\\Windows\\system32\\kernel32.dll
            scan this file
        quick_scan_virus.py C:\\Windows\\system32\\
            scan all files of this directory 
        quick_scan_virus.py all
           scan all files in your computer

###About it 
**quick_scan_virus.py **is a security tool to quick dig APT and other virus in your computer .**quick_scan_virus.py **using **md5 ,sha1 ,sha256** compares with virus hash from famous anti-virus lab (like:`Kaspersky` ,`Symantec` ,`FireEyes` .etc ) .
Warning :the virus hash file collect in `Loki` [git:https://github.com/Neo23x0/Loki]