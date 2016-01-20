#!/usr/bin/env python
#-*- coding:utf-8 -*-

import hashlib
import sys
import os

def get_file_data(file_name) :
    file_object=open(file_name,'rb')
    file_data=file_object.read()
    file_object.close()
    return file_data

def get_md5(data) :
    md5=hashlib.md5()
    md5.update(data)
    return md5.hexdigest()
    
def get_sha1(data) :
    sha1=hashlib.sha1()
    sha1.update(data)
    return sha1.hexdigest()
    
def get_sha256(data) :
    sha256=hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()
    
def get_file_md5(file_name) :
    return get_md5(get_file_data(file_name))

def get_file_sha1(file_name) :
    return get_sha1(get_file_data(file_name))

def get_file_sha256(file_name) :
    return get_sha256(get_file_data(file_name))

def search_hash_from_file(file_list) :
    file_object=open(os.path.dirname(__file__)+'\\virus_hash.txt','rb')
    for file_line in file_object :
        if file_line[0]=='#' or len(file_line) is 0 :
            continue
        
        hash_recode=file_line[:file_line.find(';')]
        virus_recode=file_line[file_line.find(';')+1:]
        for file_list_index in file_list :
            if hash_recode==file_list_index.get('file_md5') :
                file_list_index['is_virus']=True
                file_list_index['virus_infomarion']=virus_recode
            elif hash_recode==file_list_index.get('file_sha1') :
                file_list_index['is_virus']=True
                file_list_index['virus_infomarion']=virus_recode
            elif hash_recode==file_list_index.get('file_sha256') :
                file_list_index['is_virus']=True
                file_list_index['virus_infomarion']=virus_recode
            else :
                file_list_index['is_virus']=False
    file_object.close()

def add_file_in_file_list(file_list,file_path) :
    file_index={}
    file_index['file_path']=file_path
    file_index['file_md5']=get_file_md5(file_path)
    file_index['file_sha1']=get_file_sha1(file_path)
    file_index['file_sha256']=get_file_sha256(file_path)
    file_list.append(file_index)

if __name__=='__main__' :
    if len(sys.argv) is 2 :
        file_list=[]
        if os.path.isfile(sys.argv[1]) :
            add_file_in_file_list(file_list,sys.argv[1])
        elif not os.path.isfile(sys.argv[1]) and os.path.exists(sys.argv[1]) :
            for walk_directory, walk_directory_subdirs, walk_directory_files in os.walk(sys.argv[1]) :
                for walk_directory_file in walk_directory_files :
                    add_file_in_file_list(file_list,walk_directory+'\\'+walk_directory_file)
        elif sys.argv[1]=='all' :
            pass # You Know , I dont BB ..
        else :
            print 'Parameter ERROR !'
            print '    1.Maybe this file/directory is not exist'
            print '    2.Paramter is not string all'
            exit()

        search_hash_from_file(file_list)
        print 'Report Scan Result'
        for file_scan_index in file_list :
            if file_scan_index.get('is_virus') :
                print 'Virus :'+file_scan_index.get('file_path')+' ('+file_scan_index.get('virus_infomarion')+')'
    else :
        print 'Using:'
        print '    quick_scan_virus.py %file_path%|%directory_path%|all'
        print 'Example:'
        print '    quick_scan_virus.py C:\\Windows\\system32\\kernel32.dll'
        print '        scan this file'
        print '    quick_scan_virus.py C:\\Windows\\system32\\'
        print '        scan all files of this directory '
        print '    quick_scan_virus.py all'
        print '        scan all files in your computer'
