import os
import re
import sys
import ConfigParser
from xml.dom import minidom
import subprocess
import glob
import logging
import commands
import DBconnect

#some global variables in the common file. Refer to it for more info and other variables
source_or_apk = 1

#reading the layout  files
def readLayoutFiles(pathToLayout):
	aapt = glob.glob(getConfig("AndroidSDKPath")+ "build-tools/*/aapt*")
	process = subprocess.Popen([aapt[0], "dump", "xmltree", apkPath, pathToLayout], stdout=subprocess.PIPE)
	output, err = process.communicate()
	print output

#finding the xml files and getting their path
def find_xml(path):
	list_of_files = []
	for dirpath, dirnames, filenames in os.walk(path):
		for filename in filenames:
			if filename[-4:] == '.xml':
				list_of_files.append(os.path.join(dirpath,filename))
	return list_of_files

def find_layout(scan_id,path,output_folder):

	foundButtons=[]
	newButtons = []
	buttonFiles=[]
	layout_dirs=[]
	xml_files = None

	for dirpath, dirnames, filenames in os.walk(path):
		for dirname in dirnames:
			if dirname == "layout":
				xml_files=find_xml(path+"/"+dirname)

	if xml_files:
		for x in xml_files:
			try:
				button=minidom.parse(x)
				for node in button.getElementsByTagName('Button'):
					if 'android:FilterTouchesWhenObscured' in node.attributes.keys():
						if node.attributes['android:FilterTouchesWhenObscured'].value == 'true':
							continue
						else:
							foundButtons.append(node.toxml())
							buttonFiles.append(str(x))
					else:
						foundButtons.append(node.toxml())
						buttonFiles.append(str(x))

				imageButton=minidom.parse(x)
				for node in button.getElementsByTagName('ImageButton'):
					if 'android:FilterTouchesWhenObscured' in node.attributes.keys():
						if node.attributes['android:FilterTouchesWhenObscured'].value == 'true':
							continue
						else:
							try:
								if 'android:id' in node.attributes.keys():
									buttonId=node.attributes['android:id'].value
									buttonId=re.sub(r'.*id\/','',buttonId)
									foundButtons.append(buttonId)
									buttonFiles.append(str(x))
							except Exception as e:
								print "Unable to extract id for Button from layout's xml: " + str(e)
					else:
						try:
							if 'android:id' in node.attributes.keys():
								buttonId=node.attributes['android:id'].value
								buttonId=re.sub(r'.*id\/','',buttonId)
								foundButtons.append(buttonId)
								buttonFiles.append(str(x))
						except Exception as e:
							print "Unable to extract id for Button from layout's xml: " + str(e)
							
			except Exception, ae:
				print str(ae);

	if len(foundButtons) > 0:
		print "The buttons in the xml files"
		print "LENGTH: " + str(len(foundButtons))
		for b in foundButtons:
			try:
				temp = b.replace('<','&lt;')
				temp = temp.replace('>','&gt;')
				temp.encode('utf-8')
				newButtons.append(temp)
			except Exception as e:
				print str(b)
		for i in range(0,len(buttonFiles)):
			print buttonFiles[i]
	else:
		print "No buttons found in xml layouts"
	for i in range(0,len(foundButtons)):
		DBconnect.custom_update(scan_id,10,buttonFiles[i],newButtons[i])
	return
