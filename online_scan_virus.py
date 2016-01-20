#!/usr/bin/env python
#-*- coding:utf-8 -*-

import HTMLParser
import requests
import sys
import os
import time

class upload_packet_resolver(HTMLParser.HTMLParser) :
    def __init__(self) :
        HTMLParser.HTMLParser.__init__(self)
        self.is_script=False
        self.java_script_analazing_flag='parent.window.location.href=\''
        self.java_script_had_scan_flag='parent.document.getElementById(\'info_desc\').innerHTML='
        self.java_script_had_scan_url_flag='parent.document.getElementById(\'scan_url\').href=\''
        self.scan_result_url=''
        
    def handle_starttag(self,tag,attrs) :
        if tag=='script' :
            self.is_script=True
        
    def handle_data(self,data) :
        if self.is_script :
            if data.find(self.java_script_analazing_flag)!=-1 :
                self.scan_result_url=data[data.find(self.java_script_analazing_flag)+len(self.java_script_analazing_flag):]
                self.scan_result_url=self.scan_result_url[:self.scan_result_url.find('\'')]
            elif data.find(self.java_script_had_scan_flag)!=-1 and data.find(self.java_script_had_scan_url_flag)!=-1 :
                self.scan_result_url=data[data.find(self.java_script_had_scan_url_flag)+len(self.java_script_had_scan_url_flag):]
                self.scan_result_url=self.scan_result_url[:self.scan_result_url.find('\'')]
            self.is_script=False
            
    def get_scan_result_url(self) :
        return self.scan_result_url

def upload_file(file_path) :
    file_name=file_path[file_path.rfind('\\')+1:]
    fake_path='C:\\fakepath\\'+file_name
    file_object=open(file_path,'rb')
    file_data=file_object.read()   
    file_object.close()

    upload_packet='------WebKitFormBoundaryiNlGwnLvgAdyNe6P\r\n'
    upload_packet+='Content-Disposition: form-data; name="langkey"\r\n'
    upload_packet+='\r\n'
    upload_packet+='1\r\n'
    upload_packet+='------WebKitFormBoundaryiNlGwnLvgAdyNe6P\r\n'
    upload_packet+='Content-Disposition: form-data; name="setcookie"\r\n'
    upload_packet+='\r\n'
    upload_packet+='1\r\n'
    upload_packet+='------WebKitFormBoundaryiNlGwnLvgAdyNe6P\r\n'
    upload_packet+='Content-Disposition: form-data; name="tempvar"\r\n'
    upload_packet+='\r\n'
    upload_packet+='\r\n'
    upload_packet+='------WebKitFormBoundaryiNlGwnLvgAdyNe6P\r\n'
    upload_packet+='Content-Disposition: form-data; name="upfile"; filename="'
    upload_packet+=file_name
    upload_packet+='"\r\n'
    upload_packet+='Content-Type: text/plain\r\n\r\n'
    upload_packet+=file_data
    upload_packet+='\r\n'
    upload_packet+='------WebKitFormBoundaryiNlGwnLvgAdyNe6P\r\n'
    upload_packet+='Content-Disposition: form-data; name="fpath"\r\n'
    upload_packet+='\r\n'
    upload_packet+='C:\\fakepath\\'
    upload_packet+=file_name
    upload_packet+='\r\n'
    upload_packet+='------WebKitFormBoundaryiNlGwnLvgAdyNe6P--\r\n'
    
    request=requests.post('http://up.virscan.org/up.php',
        headers={
            'Content-Type': 'multipart/form-data;boundary=----WebKitFormBoundaryiNlGwnLvgAdyNe6P'
        },
        data=upload_packet
    )
    
    request_packet=upload_packet_resolver()
    request_packet.feed(request.text)
    result_url=request_packet.get_scan_result_url()
    return result_url

def get_scan_for_linux(file_hash) :
    print 'http://www.virscan.org//index.php?ctl=scanadmin&m=1&f='+file_hash+'&t='+str(int(time.time()*1000))
    result_linux=requests.get('http://www.virscan.org/index.php?ctl=scanadmin&m=1&f='+file_hash+'&t='+str(int(time.time()*1000)))
    return result_linux.json()

def get_scan_for_windows(file_hash) :
    print 'http://www.virscan.org//index.php?ctl=scanadmin&m=2&f='+file_hash+'&t='+str(int(time.time()*1000))
    result_windows=requests.get('http://www.virscan.org/index.php?ctl=scanadmin&m=2&f='+file_hash+'&t='+str(int(time.time()*1000)))
    return result_windows.json()
    
class json_scaner_html_resolver(HTMLParser.HTMLParser) :
    def __init__(self) :
        HTMLParser.HTMLParser.__init__(self)
        self.is_td=False
        self.data_vector=[]
        
    def handle_starttag(self,tag,attrs) :
        if tag=='td' :
            self.is_td=True
    
    def handle_data(self,data) :
        if self.is_td :
            self.data_vector.append(data)
            self.is_td=False
    
    def get_scan_information(self) :
        return self.data_vector
    
def resolve_json(file_report,scan_json) :
    if scan_json.get('state') is 0 :
        html_resolver=json_scaner_html_resolver()
        html_resolver.feed(scan_json.get('content'))
        scanner_information=html_resolver.get_scan_information()
        scanner_virus_lib_update_time=''
        if len(scanner_information) is 4 :
            scanner_name=scanner_information[0]
            scaner_version=scanner_information[1]
            if scanner_information[2].strip()=='Found nothing' :
                scanner_is_virus=True
            else :
                scanner_is_virus=False
            scanner_virus_time=scanner_information[3]
        elif len(scanner_information) is 6 :
            scanner_name=scanner_information[0]
            scaner_version=scanner_information[1]
            scanner_virus_lib_version=scanner_information[2]
            scanner_virus_lib_update_time=scanner_information[3]
            if scanner_information[4].strip()=='Found nothing' :
                scanner_is_virus=True
            else :
                scanner_is_virus=False
            scanner_virus_time=scanner_information[5]
        is_virus_rate=scan_json.get('tips_keyi')
        is_virus_rate=is_virus_rate[is_virus_rate.find('>')+1:]
        is_virus_rate=is_virus_rate[:is_virus_rate.find('<')]
        scan_location=scan_json.get('tips_place')
        scan_location=scan_location[scan_location.find('>')+1:]
        scan_location=scan_location[:scan_location.find('<')]
        print 'scanner:'+scanner_name+'-'+scaner_version+'('+scanner_virus_lib_update_time+')',
        print str(scanner_is_virus)+' ',
        print is_virus_rate+' '+scanner_virus_time+'s '+scan_location
    elif scan_json.get('state') is 2 :
        print 'scan error'
    if scan_json.get('over') :
        return True
    return False
    
def online_analases(file_path) :
    analase_url=upload_file(file_path)
    file_hash=analase_url[analase_url.rfind('/')+1:]
    file_report=[]
    request=requests.get('http://www.virscan.org/scan/'+file_hash)  #  server scan init 
    while True :
        if resolve_json(file_report,get_scan_for_linux(file_hash)) :  #  server scan
            break
        if resolve_json(file_report,get_scan_for_windows(file_hash)) :
            break

if len(sys.argv) is 2 :
    if os.exists(sys.argv[1]) and os.isfile(sys.argv[1]) :
        online_analases(sys.argv[1])
    else :
        print 'this is not a valid file'
else :
    print 'Using:'
    print '    online_scan_virus.py %file_path%'
    print 'Example:'
    print '    online_scan_virus.py C:\Windows\System32\kernel32.dll'
