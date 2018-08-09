import os
import sys
import subprocess
import DBconnect
import commands
from xml.dom import minidom

def wv_check(scan_id,mf,java_folder,output_folder):
    parsedmf = minidom.parse(mf)
    usessdk = parsedmf.getElementsByTagName("uses-sdk")
    minSdkVersion = usessdk[0].getAttribute("android:minSdkVersion")
    
    if int(minSdkVersion) < 17:
        ex1=commands.getoutput('grep -H -i -n -r -e "addJavascriptInterface" '+java_folder)
        DBconnect.write_to_db(scan_id,ex1,1)

        ex2=commands.getoutput('grep -H -i -n -r -e "@JavascriptInterface" '+java_folder)
        DBconnect.write_to_db(scan_id,ex2,2)