
import sys
import os

import quick_scan_virus
import online_scan_virus

if __name__=='__main__' :
    if len(sys.argv) is 2 :
        if os.path.isfile(sys.argv[1]) and os.path.exists(sys.argv[1]) :
            print 'Now get local scanning!'
            scan_file=[]
            quick_scan_virus.add_file_in_file_list(scan_file,sys.argv[1])
            quick_scan_virus.search_hash_from_file(scan_file)
            
            print 'Local Scan Virus Alarm Report :'
            if scan_file[0].get('is_virus')=='yes' :
                print '  '+scan_file[0].get('file_path')+' type('+scan_file[0].get('virus_infomarion')+')'
                exit()
            else :
                print 'Local Scan Not Found!'
            
            print 'Now get online scanning!'
            online_scan_is_virus=False
            print 'Online Scan Virus Alarm Resport :'
            scanner_report=online_scan_virus.online_analases(sys.argv[1])
            for scanner_report_index in scanner_report :
                if scanner_report_index.get('is_virus') :
                    print '  Virus Scanner:'+scanner_report_index.get('scanner_name')+'-',
                    print scanner_report_index.get('scaner_version')+'(',
                    print scanner_report_index.get('scanner_virus_lib_update_time')+')',
                    print ' Virus Type:'+scanner_report_index.get('scanner_virus_type')
                    online_scan_is_virus=True
                    
            if not online_scan_is_virus :
                print 'Online Scan Not Found!'
    else :
        print 'Usage:'
        print '    scan_virus.py %file_path%'
        print '    Complete Analysis file '
