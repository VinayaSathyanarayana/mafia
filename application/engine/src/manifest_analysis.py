import os
import sys
from xml.dom import minidom
import xml.dom.minidom
import sys
import ConfigParser
import subprocess
import glob
import DBconnect

#manifest analysis
def manifest_analysis(manifest_file,output_folder,scan_id):
    orig_stdout = sys.stdout
    f = open(output_folder+'/ManifestAnalysis.txt', 'w')
    sys.stdout = f
	
    exported_providers= []
    exported_services= []
    exported_activities= []
    activities = {}
    parsed_manifest= minidom.parse(manifest_file)
    min_sdk = 0
    target_sdk = 0
    num_activities = 0
    num_services = 0
    num_providers = 0
    num_exported_services = 0
    num_exported_providers =0
    num_exported_activities =0 
    
    #Finding the minimum and the target sdk versions       
    for sdk in parsed_manifest.getElementsByTagName('uses-sdk'):
        if 'android:minSdkVersion' in sdk.attributes.keys():
            min_sdk = sdk.attributes['android:minSdkVersion'].value

        if 'android:targetSdkVersion' in  sdk.attributes.keys():
            target_sdk = sdk.attributes['android:targetSdkVersion'].value    

    flag =0 
    for app in parsed_manifest.getElementsByTagName('application'):

        if 'android:permission' in app.attributes.keys():
            flag =1
            for activity in parsed_manifest.getElementsByTagName('activity'):
                if 'android:permission' in activity.attributes.keys():
                    print "The activity " + activity.attributes["android:name"].value + " requires " + activity.attributes["android:permission"].value +" permission"
    
        for service in app.childNodes:
            if service.nodeName == 'service':
                if service.nodeName =='service':
                    num_services =num_services +1
                IntentFilter = False
                ServicePermission = False
                for node in service.childNodes:
                    if node.nodeName == 'intent-filter':
                        IntentFilter = True
                        print 'There is an intent filter for the service --- ' + service.attributes["android:name"].value
                        flag=1
                    if 'android:permission' in service.attributes.keys():
                        ServicePermission = True
                        print "There is service permission for" + service.attributes["android:name"].value + "and the permission is " + service.attributes["android:permission"].value

                    elif 'android:permission' in app.attributes.keys():
                        
                        print "The permissions to this service are same as that of the application --- " + app.attributes['android:permission'].value

                if IntentFilter==False and ServicePermission==False and ('android:exported' in service.attributes.keys() and service.attributes['android:exported'].value =='true'):
                    num_exported_services = num_exported_services + 1
                    exported_services.append(service.attributes['android:name'].value)
                    
                    print "No permissions for the service " + service.attributes['android:name'].value
        
        for service in app.childNodes:
            if service.nodeName == 'activity':
                num_activities = num_activities +1
                IntentFilter = False
                ServicePermission = False
                for node in service.childNodes:
                    if node.nodeName == 'intent-filter':
                            IntentFilter = True
                            print 'There is an intent filter for the activity --- ' + service.attributes["android:name"].value
                            flag=1
                            
                    if 'android:permission' in service.attributes.keys():
                        ServicePermission = True
                        print "There is service permission for" + service.attributes["android:name"].value + "and the permission is " + service.attributes["android:permission"].value
                    
                    elif 'android:permission' in app.attributes.keys():
                        print "The permissions to this service are same as that of the application --- " + app.attributes['android:permission'].value

                if IntentFilter==False and ServicePermission==False and ('android:exported' in service.attributes.keys() and service.attributes['android:exported'].value =='true'):
                    num_exported_activities = num_exported_activities + 1
                    exported_activities.append(service.attributes['android:name'].value)
            
                    print "No permissions for the service " + service.attributes['android:name'].value

    #checking the protection level of android
    for node in parsed_manifest.getElementsByTagName('permission'):
        if 'android:protectionLevel' in node.attributes.keys():
            if (node.attributes['android:protectionLevel'].value == 'signature' or node.attributes['android:protectionLevel'].value == 'normal' or node.attributes['android:protectionLevel'].value =='dangerous'):
                for uses in parsed_manifest.getElementsByTagName('uses-sdk'): #To check the  min sdk version and hence the existance of the vulnerablitlity
                    if uses.getAttribute("android:minSdkVersion")<21:
                        print "The protection level is not secure enough " + node.attributes['android:protectionLevel'].value

    #check if backup is enabled.
    backup_db = "False"
    for backup in parsed_manifest.getElementsByTagName('application'):
        if 'android:allowBackup' in backup.attributes.keys():
            if backup.attributes['android:allowBackup'].value =='true':
                backup_db = "True"
                # print "The backup option is set to true in " + backup.attributes['android:name'].value

    #check if the debug option is enabled
    debuggable = "False"
    for debug in parsed_manifest.getElementsByTagName('application'):
        if 'android:debuggable' in debug.attributes.keys():
            if debug.attributes['android:debuggable'].value== 'true':
                # print "The debuggable option is set open in the android manifest file"
                debuggable = "True"
                
        # else:
        #     print "The app is disabled to debugging"

    #checking the content providers for the access permissions
    for providers in app.childNodes:
        if providers.nodeName == 'provider':
            num_providers = num_providers +1
            if min_sdk < 16 or target_sdk < 16:
                if 'android:exported' in providers.attributes.keys():
                    if providers.attributes['android:exported'].value == 'false':
                        print "The android:exported is set to false for -- " + providers.attributes['android:name'].value + "  SAFE!"
                    else:
                        num_exported_providers = num_exported_providers + 1
                        exported_providers.append(providers.attributes['android:name'].value)
                        print "The android:exported is set to true for -- " + providers.attributes['android:name'].value + "  DANGER!!"
                else:
                    num_exported_providers = num_exported_providers + 1
                    exported_providers.append(providers.attributes['android:name'].value)
                    print "The android:exported is set to true for -- " + providers.attributes['android:name'].value + "  DANGER!!"
            else:
                if 'android:exported' in providers.attributes.keys():
                    if providers.attributes['android:exported'].value == 'true':
                        num_exported_providers = num_exported_providers + 1
                        exported_providers.append(providers.attributes['android:name'].value)
                        print "The android:exported is set to true for -- " + providers.attributes['android:name'].value + "  DANGER!!"
                    else:
                        print "The android:exported is set to false for -- " + providers.attributes['android:name'].value + "  SAFE!"
                else:
                    print "The android:exported is set to false for -- " + providers.attributes['android:name'].value + "  SAFE!"

            grant_uri = 0
            if "android:grantUriPermissions" in providers.attributes.keys():
                if providers.attributes['android:grantUriPermissions'].value == 'true':
                    grant_uri =1
                    print "Some of the apps may have one  time access to the data of the  " + providers.attributes['android:name'].value + "since the grantUriPermissions are set to true"
            if grant_uri ==0:
                print "There are no grantUriPermissions for --- " + providers.attributes['android:name'].value

    print 'number of providers = ' + str(num_providers)
    print 'exported providers = ' +str(num_exported_providers)
    print 'number of services = ' + str(num_services)
    print 'exported providers = ' +str(num_exported_providers)
    print 'number of activities = ' + str(num_activities)
    print 'exported activities = ' +str(num_exported_activities)
    print exported_activities
    print exported_providers
    print exported_services

    sys.stdout = orig_stdout
    DBconnect.manifest_update_scan(scan_id,min_sdk,target_sdk,debuggable,backup_db)

    if debuggable == "True":
        debug_text = manifest_file.replace('Uncrypted_','')+":--:android_debuggable"
        DBconnect.write_to_db(scan_id,debug_text,14)

    if backup_db == "True":
        backup_text = manifest_file.replace('Uncrypted_','')+":--:android_allowBackup"
        DBconnect.write_to_db(scan_id,backup_text,15)

    
    for i in range(num_exported_activities):
        DBconnect.manifest_update(scan_id,1,exported_activities[i])

    for i in range(num_exported_providers):
        DBconnect.manifest_update(scan_id,2,exported_providers[i])

    for i in range(num_exported_services):
        DBconnect.manifest_update(scan_id,3,exported_services[i])

    return

