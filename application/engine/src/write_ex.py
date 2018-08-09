import os
import sys
import subprocess
import commands
import DBconnect

def search_ext(scan_id,filename,outputfile):
    ex1=commands.getoutput('grep -H -i -n -r -e "getExternalStorageDirectory()" '+filename+' >> '+outputfile+'/externalstorage.txt')
    ex2=commands.getoutput('grep -H -i -n -r -e "sdcard" '+filename+' >> '+outputfile+'/externalstorage.txt')
    ex4=commands.getoutput('grep -H -i -n -r -e "WRITE_EXTERNAL_STORAGE" '+filename+'/../Uncrypted_AndroidManifest.xml >> '+outputfile+'/externalstorage.txt')
    outfile = open(outputfile+'/externalstorage.txt','r')
    text = outfile.read()
    DBconnect.write_to_db(scan_id,text,8)
    
                   

