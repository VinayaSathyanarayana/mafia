import os
import sys
import subprocess
import commands
import DBconnect

def shared_preferences(scan_id,filename,outputfile):
    ex1=commands.getoutput('grep -H -i -n -r -e "MODE_WORLD_READABLE" '+filename+' >> '+outputfile+'/shared_pref.txt')
    ex2=commands.getoutput('grep -H -i -n -r -e "MODE_WORLD_WRITEABLE" '+filename+' >> '+outputfile+'/shared_pref.txt')
    outfile = open(outputfile+'/shared_pref.txt','r')
    text = outfile.read()
    DBconnect.write_to_db(scan_id,text,9)