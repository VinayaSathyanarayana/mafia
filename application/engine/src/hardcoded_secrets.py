import os
import sys
import subprocess
import commands
import DBconnect

def get_hardcoded(scan_id,filename,outputfile):
    print "HERE: "+filename
    results = DBconnect.get_hardcode()
    for row in results:
        ex1=commands.getoutput('grep -H -i -n -r -e '+row[1]+' '+filename+' >> '+outputfile+'/hardcoded.txt')
    outfile = open(outputfile+'/hardcoded.txt','r')
    text = outfile.read()
    DBconnect.write_to_db(scan_id,text,13)