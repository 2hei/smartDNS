#!/usr/bin/python
# -*- coding: utf-8 -*-
# getchinaisp.py
#
# Author: yu2hei@gmail.com
# Date: 2014-03-04
# Version: v1.0
#

__version__ = '1.0'

import sys,re
import socket
import timeoutsocket

ISP_LIST = (
       'CHINANET',
       'CNCGROUP',
       'CMCC',
       'CRTC',
       )

timeoutsocket.setDefaultSocketTimeout(30)
file_apnic = 'FILE'
file_chinaisp = 'china_isp.txt'

fh_apnic = open(file_apnic,'r')
fh_chinaisp = open(file_chinaisp,'w')


#get subnet from apinc FILE
def log2(num,row):
    if (num <= 1):
        return row
    else:
        row = row - 1
        return log2(num/2,row)

#get all cn IPS    
apnic_cn_ip = []
try:
    lines = fh_apnic.readlines()
    for line in lines:
        if re.search("apnic\|CN\|ipv4",line):
            print line.strip()
            ip,snum = line.split('|')[3],line.split('|')[4]
            mask = log2(int(snum),32)
            apnic_cn_ip.append(ip+'|'+str(mask))
except Exception,ex:
    print "read FILE error",ex

fh_apnic.close()

#check whois.apnic.net
try:
    for ips in apnic_cn_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("whois.apnic.net", 43))
        except Exception,ex:
            print 'Can not connect to anic.net',ex

        ip,mask = ips.split('|')[0].strip(),ips.split('|')[1].strip()
        
        try:
            s.send(ip + "\r\n")
            response = ''
            while True:
                data = s.recv(4096)
                response += data
                if data == '':
                    break
        except Exception,ex:
            print 'Can not get response from apnic.net',ex
        
        #get last mnt-by
        mnt_list = []
        for n in response.split('\n'):
            if re.search("mnt",n):
                mnt_list.append(n.split(':')[1].strip())
                
        s.close()
        
        #match ISP
        try:
            for isp in ISP_LIST:
                for s in mnt_list:
                    if re.search(isp,s):
                        #print ip+'/'+str(mask)+':'+isp
                        fh_chinaisp.write(ip+'/'+mask+':'+isp+'\n')
                        raise
        except Exception,ex:
            pass
            
except Exception,ex:
    print "get ip from apnic error",ex
           
fh_chinaisp.close()
