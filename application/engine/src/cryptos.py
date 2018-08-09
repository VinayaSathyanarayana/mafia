import os
import sys
import subprocess
import DBconnect
import commands

def weakalgo(scan_id,filename,outputfile):
    ex1=commands.getoutput('grep -H -i -n -r -e "MD4" '+filename+' >> '+outputfile+'/temp.txt')
    ex2=commands.getoutput('grep -H -i -n -r -e "MD5" '+filename+' >> '+outputfile+'/temp.txt')
    ex3=commands.getoutput('grep -H -i -n -r -e "RC4" '+filename+' >> '+outputfile+'/temp.txt')
    ex4=commands.getoutput('grep -H -i -n -r -e "SHA1" '+filename+' >> '+outputfile+'/temp.txt')
    ex5=commands.getoutput('grep -H -i -n -r -e "base64" '+filename+' >> '+outputfile+'/temp.txt')
    ex6a=commands.getoutput("grep -H -i -n -r -e '\"DES\"' "+filename+' >> '+outputfile+'/temp.txt')
    ex7=commands.getoutput('grep -H -i -n -r -e "AES/ECB" '+filename+' >> '+outputfile+'/temp.txt')
    ex8=commands.getoutput('grep -i  "import" ' +outputfile+'/temp.txt'+ ' >>'+ outputfile+'/Weakencryption.txt')
    ex9=commands.getoutput('grep -i  "cipher.getinstance" ' +outputfile+'/temp.txt'+ ' >>'+ outputfile+'/Weakencryption.txt')
    ex10=commands.getoutput('grep -i  "keygenerator.getinstance" ' +outputfile+'/temp.txt'+ ' >>'+ outputfile+'/Weakencryption.txt')
    ex11=commands.getoutput('grep -i  "KeyFactory.getinstance" ' +outputfile+'/temp.txt'+ ' >>'+ outputfile+'/Weakencryption.txt')
    ex12=commands.getoutput('grep -i  "Signature.getinstance" ' +outputfile+'/temp.txt'+ ' >>'+ outputfile+'/Weakencryption.txt')
    ex13=commands.getoutput('grep -i  "MessageDigest.getinstance" ' +outputfile+'/temp.txt'+ ' >>'+ outputfile+'/Weakencryption.txt')
    ex14=commands.getoutput('rm '+ outputfile+'/temp.txt')        
    outfile = open(outputfile+'/Weakencryption.txt','r')
    text = outfile.read()
    DBconnect.write_to_db(scan_id,text,6)


def findKeys(path):
    list_of_files = []
    for (dirpath, dirnames, filenames) in os.walk(path):
        for filename in filenames:
            if filename[-4:] == '.pem':
                list_of_files.append(os.path.join(dirpath,filename))
            elif filename[-4:] == '.key':
                list_of_files.append(os.path.join(dirpath,filename))
    return list_of_files


def find_key_files(scan_id,filename,path,outputfile):
    possibleKeyFiles=findKeys(path)
    for x in possibleKeyFiles:
        ex1=commands.getoutput('grep -H -i -n -r -e "PRIVATE KEY" '+x+' >> '+outputfile+'/exposedkey.txt')
    ex2=commands.getoutput("grep -H -i -n -r -e 'key.*=.*\".*\".*;' "+filename+' >> '+outputfile+'/exposedkey.txt')
    outfile = open(outputfile+'/exposedkey.txt','r')
    text = outfile.read()
    DBconnect.write_to_db(scan_id,text,11)


def keyInFile(scan_id,filename,outputfile):
    ex1=commands.getoutput("grep -H -i -n -r -e 'SQLiteDatabase.openOrCreateDatabase.(.*,.*\".*\".*,.*);' "+filename+' >> '+outputfile+'/key.txt')       
    ex3=commands.getoutput("grep -H -i -n -r -e 'getWritableDatabase(.*\".*\".*)' "+filename+' >> '+outputfile+'/key.txt') 
    outfile = open(outputfile+'/key.txt','r')
    text = outfile.read()
    DBconnect.write_to_db(scan_id,text,7)

                   

