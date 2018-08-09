import os
import sys
import subprocess
import commands
import DBconnect

def find_logcat(scan_id,filename,outputfile):
    ex1=commands.getoutput('grep -H -i -w -n -r -e "Log\.d" '+filename+' >> '+outputfile+'/logcat.txt')
    ex2=commands.getoutput('grep -H -i -w -n -r -e "Log\.v" '+filename+' >> '+outputfile+'/logcat.txt')
    ex2=commands.getoutput('grep -H -i -w -n -r -e "Log\.i" '+filename+' >> '+outputfile+'/logcat.txt')
    outfile = open(outputfile+'/logcat.txt','r')
    text = outfile.read()
    DBconnect.write_to_db(scan_id,text,12)