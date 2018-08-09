import tools.plyj.parser as jp
import tools.plyj.model as md
import re
import sys
import os
import DBconnect

def find_javas(path):
	list_of_files = []
	for root, subdirs, files in os.walk(path):
		for filename in files:
			if filename[-5:] == '.java':
				list_of_files.append(os.path.join(root,filename))
	return list_of_files
    
def find_ssl_vulnerabilities(scan_id,java_folder,output_folder):
	orig_stdout = sys.stdout
	f = open(output_folder+'/DebugAnalysis.txt', 'w')
	sys.stdout = f
	java_files = find_javas(java_folder)
	errorfile = open(output_folder+'/errors_ssl.txt','w')
	parser = jp.Parser()
	for f in java_files:
		filename = str(f)
		try:
			parse_tree = parser.parse_file(filename)
		except Exception as e:
			errorfile.write(f+'\n')
			print e
			continue
		if parse_tree is not None:
			for declaration in parse_tree.type_declarations:
				if type(declaration) == md.ClassDeclaration:
					for field in declaration.body:
						trust_manager(scan_id,field,filename)
						hostname_verifier(scan_id,field,filename)
	sys.stdout = orig_stdout
	errorfile.close()

def trust_manager(scan_id,field,filename):
	if type(field) == md.MethodDeclaration:
		if str(field.name) == 'checkServerTrusted':
			if len(field.body) == 0:
				DBconnect.custom_update(scan_id,4,filename,'checkServerTrusted method is empty.')

			else:
				if type(field.body[0])==md.Return:
					DBconnect.custom_update(scan_id,4,filename,'checkServerTrusted method only returns.')
	elif type(field) == list :
		for element in field:
			trust_manager(scan_id,element,filename)
	else:
		if hasattr(field,'_fields'):
			for element in field._fields:
				item = getattr(field,element)
				trust_manager(scan_id,item,filename)

def hostname_verifier(scan_id,field,filename):
    if type(field) == md.Assignment:
        if type(field.rhs) is md.InstanceCreation:
            if hasattr(field.rhs,'type'):
                if hasattr(field.rhs.type,'name'):
                    if hasattr(field.rhs.type.name,'value'):
                        if str(field.rhs.type.name.value)=='AllowAllHostnameVerifier':
                        	if hasattr(field.lhs):
                        		DBconnect.custom_update(scan_id,3,filename,'AllowAllHostnameVerifier method found.')

    elif type(field) is md.MethodInvocation:
        if hasattr(field,'name'):
	    	if str(field.name) == 'setHostnameVerifier':
	                if hasattr(field,'arguments'):
	                    for element in field.arguments:
	                        if type(element) is md.Name:
	                            if hasattr(element,'value'):
	                            	if re.search(r'\.ALLOW_ALL_HOSTNAME_VERIFIER$',str(element.value)):
	                            		DBconnect.custom_update(scan_id,3,filename,'ALLOW_ALL_HOSTNAME_VERIFIER invoked.')

    elif type(field) is list:
        for element in field:
        	hostname_verifier(scan_id,element,filename)
    else:
    	if hasattr(field,'_fields'):
    		for element in field._fields:
    			item = getattr(field,element)
    			hostname_verifier(scan_id,item,filename)
