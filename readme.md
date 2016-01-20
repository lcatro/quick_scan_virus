##quick_scan_virus.py

###How to Using it

		quick_scan_virus.py file_path|directory_path|all
    Example:
		quick_scan_virus.py C:\\Windows\\system32\\kernel32.dll
            scan this file
        quick_scan_virus.py C:\\Windows\\system32\\
            scan all files of this directory 
        quick_scan_virus.py all
            scan all files in your computer

###About it 
**quick_scan_virus.py** is a security tool to quick dig APT and other virus in your computer .**quick_scan_virus.py** using **md5 ,sha1 ,sha256** compares with virus hash from famous anti-virus lab (like:`Kaspersky` ,`Symantec` ,`FireEyes` .etc ) .
Warning :the virus hash file collect in `Loki` [git:https://github.com/Neo23x0/Loki]

---

##online_scan_virus.py

###How to Using it

        online_scan_virus.py file_path
    Example:
        online_scan_virus.py C:\Windows\System32\kernel32.dll

###About it
**online_scan_virus.py** using `VirScan.org` online Anti-Virus scanners to auto analases your update file .**online_scan_virus.py** different from **quick_scan_virus.py** because **quick_scan_virus.py** find a exist virus's signature in hash file ,but **online_scan_virus.py** can dig more unknow virus.

---

##scan_virus.py

###How to Using it

        scan_virus.py file_path
    Example:
        scan_virus.py C:\Windows\System32\kernel32.dll
        
