import os
import sys, time
import subprocess
import commands
import shutil
from xml.dom import minidom
import time 
from tools.AxmlParserPY import axmlprinter
import string, random
from androguard.core.bytecodes.apk import APK

def dircreator(mainFolder):
    try:
        os.makedirs(mainFolder)
        return mainFolder
    except:
        return None

def dirremover(mainFolder):
    try:
        shutil.rmtree(mainFolder)
        return True
    except:
        return False


def validate(apk,outputdir):
    #Manifest
    manifest_path = outputdir+'/AndroidManifest.xml'
    dex_path = outputdir+'/classes.dex'
    FNULL = open(os.devnull, 'w')
    retcode = subprocess.call(["unzip", apk, "-d", outputdir], stdout=FNULL, stderr=subprocess.STDOUT)

    if retcode !=0 :
    	return {'valid': False,'details': None}

    elif os.path.isfile(manifest_path) is True:
        if os.path.isfile(dex_path) is True:
            ap = axmlprinter.AXMLPrinter(open(outputdir+'/AndroidManifest.xml', 'rb').read())
            buff = minidom.parseString(ap.getBuff()).toxml()
            buff = buff.encode('UTF-8')
            uncrypt_manifest = outputdir+'/Uncrypted_AndroidManifest.xml'
            f=open(uncrypt_manifest,'w')
            f.write(buff)
            f.close()
            parsed_manifest= minidom.parse(uncrypt_manifest)
            for element in parsed_manifest.getElementsByTagName('manifest'):
                package_name = None
                if 'package' in element.attributes.keys():
                    package_name = element.attributes['package'].value
                    
                package_version = None
                if 'android:versionName' in element.attributes.keys():
                    package_version = element.attributes['android:versionName'].value
                    time_of_scan = time.strftime('%Y-%m-%d %H:%M:%S')

            return {'valid': True,'details': [package_name,package_version,time_of_scan]}
    	else:
    		return {'valid': False,'details': None}
    else:
    	return {'valid': False,'details': None}

if __name__ == "__main__":
    apk = sys.argv[1]
    path = ''.join(random.choice(string.lowercase) for x in range(6)) #random path for unzipping
    cwd = os.getcwd()
    outputdir = dircreator(cwd+"/../Backend/android/"+path+"/unzipped")
    validate(apk,outputdir)
    
    dirremover(cwd+"/../Backend/android/"+path)



