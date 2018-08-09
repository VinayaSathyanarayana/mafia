import os
import sys
import glob
import shutil
import subprocess
import tools
from src import DBconnect
from src import webview
from src import tapjack
from src import cryptos
from src import write_ex
from src import shared_pref
from src import ssl
from src import sql
from src import manifest_analysis
from src import logcat
import commands
from tools.AxmlParserPY import axmlprinter
from xml.dom import minidom
import xml.parsers.expat as expat
import xml.dom.minidom
from androguard.core.bytecodes.apk import APK

global scan_id
scan_id = None

def dircreator(filename):
        mainFolder=filename
        try:
            os.makedirs(mainFolder)
        except:
            pass

        try:
            os.mkdir(mainFolder+'/extracted')
        except:
            pass

        try:
            os.mkdir(mainFolder+'/output')
        except:
            pass

        return mainFolder

def dirremover(mainFolder):
    try:
        shutil.rmtree(mainFolder)
        return True
    except:
        return False


def extraction(pwd,apk,outputdir,mod):
    #Manifest
    #devnull = open('/dev/null', 'w')

    cmd = 'unzip -o '+ apk +' -d '+outputdir+'/extracted/'
    op = commands.getoutput(cmd)

    #Decompiling dex
    print "[+] Decompiling dex."
    cmd = pwd+'/tools/dex2jar/d2j-dex2jar.sh '+ outputdir+'/extracted/classes.dex '+'-o '+outputdir+'/output/classes.jar'
    op=commands.getoutput(cmd)
    
    # Decompiling Class files
    print "[+] Decompiling Classes."
    cmd = 'java -jar '+pwd+'/tools/jd-core.jar '+ outputdir+'/output/classes.jar '+ outputdir+'/output/javas'
    op=commands.getoutput(cmd)
    
    #Decrypting the xml files in the layout
    print "[+] Decrypting the xml files in the layout"
    cmd = pwd+'/tools/apktool/apktool d -s -f ' + apk + ' -o ' + outputdir + '/output/xmls'
    # print cmd
    op = commands.getoutput(cmd)

def manifest_Ext(dirname):
    # print "[+] Decrypting the manifest file"
    ap = axmlprinter.AXMLPrinter(open(dirname+'/extracted/AndroidManifest.xml', 'rb').read())
    buff = minidom.parseString(ap.getBuff()).toxml()
    buff = buff.encode('UTF-8')
    f=open(dirname+'/output/'+'Uncrypted_AndroidManifest.xml','w')
    f.write(buff)
    f.close()
    

def scan_apk(argv):
    print "[+] Welcome To MAFIA"
    scan_id = int(argv[1])

    print "scan_id: ", str(scan_id)

    steps = 13
    mod = 100.0/steps
    DBconnect.progress_update(scan_id,0,"Decompiling dex")
    apk=argv[2]
    # print apk
    pwd = os.getcwd()+"/application/engine"
    print "path: "+pwd
    # sys.exit(1)
    
    outputdir = dircreator(pwd+"/workfiles/"+str(scan_id))
    #print "1"
    java_folder=pwd+'/workfiles/'+str(scan_id)+'/output/javas'
    output_folder=pwd+'/workfiles/'+str(scan_id)+'/output/report'
    try:
        ex1 = os.makedirs(output_folder)
    except:
        pass

    key_path=pwd+'/workfiles/'+str(scan_id)+'/extracted'
    layout_path=pwd+'/workfiles/'+str(scan_id)+'/extracted/res'
    manifest_file = pwd+'/workfiles/'+str(scan_id)+'/output/Uncrypted_AndroidManifest.xml'

    os.system('chmod -R 777 '+pwd+'/workfiles/')

    DBconnect.progress_update(scan_id,mod*1,"Decompiling Classes")
    extraction(pwd,apk,outputdir,mod)


    DBconnect.progress_update(scan_id,mod*2,"Extracting permissions")
    manifest_Ext(outputdir)
    andr = APK(apk)
    perms = list(set(andr.get_permissions())) #list(set()) is needed to get unique items in list

    for perm in perms:
        DBconnect.write_permission(perm,scan_id)

    receivers = list(set(andr.get_receivers())) #list(set()) is needed to get unique items in list

    for receiver in receivers:
        DBconnect.write_receivers(receiver,scan_id)

    DBconnect.progress_update(scan_id,mod*3,"Manifest Analysis")
    manifest_analysis.manifest_analysis(manifest_file,output_folder,scan_id)

    DBconnect.progress_update(scan_id,mod*4,"Webview Security Analysis")
    webview.wv_check(scan_id,manifest_file,java_folder,output_folder)

    DBconnect.progress_update(scan_id,mod*5,"Tapjacking Vulnerabilities")
    tapjack.find_layout(scan_id,layout_path,output_folder)
    
    DBconnect.progress_update(scan_id,mod*6,"Shared Storage Check")
    write_ex.search_ext(scan_id,java_folder,output_folder)
    
    DBconnect.progress_update(scan_id,mod*7,"SQL injection")
    sql.sqlinject(scan_id,java_folder,output_folder)
    
    DBconnect.progress_update(scan_id,mod*8,"Shared preferences")
    shared_pref.shared_preferences(scan_id,java_folder,output_folder)

    DBconnect.progress_update(scan_id,mod*9,"Weak encryption algorithms")
    cryptos.weakalgo(scan_id,java_folder,output_folder)

    DBconnect.progress_update(scan_id,mod*10,"Hardcoded Keys")
    cryptos.keyInFile(scan_id,java_folder,output_folder)

    DBconnect.progress_update(scan_id,mod*11,"Finding Crypto Keys")
    cryptos.find_key_files(scan_id,java_folder,key_path,output_folder)

    DBconnect.progress_update(scan_id,mod*12,"Insecure SSL/TLS implementation")
    ssl.find_ssl_vulnerabilities(scan_id,java_folder,output_folder)
    
    logcat.find_logcat(scan_id,java_folder,output_folder)
    DBconnect.progress_update(scan_id,mod*13,"Scan successfully completed")
    
    print "success"

    # dirremover(outputdir)

if __name__ == "__main__":
    scan_apk(sys.argv)

