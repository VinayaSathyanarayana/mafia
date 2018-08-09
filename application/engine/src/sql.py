import os
import sys
import subprocess
import tools
import DBconnect
import commands
from tools.AxmlParserPY import axmlprinter
from xml.dom import minidom
import xml.parsers.expat as expat
import xml.dom.minidom

def sqlinject(scan_id,filename,outputfile):
    ex1 = commands.getoutput('grep -H -i -r -n -e "where" '+filename+' | grep -e \+ >'+outputfile+'/sql.txt')

    # ex1=commands.getoutput('grep -H -i -n -r -e "select " '+filename+' >> '+outputfile+'/tempsql1.txt')
    # ex2=commands.getoutput('grep -i -r -e "from " '+outputfile+'/tempsql1.txt >> '+outputfile+'/tempsql2.txt')
    # ex3=commands.getoutput('grep -i -r -e "where " '+outputfile+'/tempsql2.txt >> '+outputfile+'/sql.txt')
    # ex4=commands.getoutput('rm '+ outputfile+'/tempsql1.txt')
    # ex5=commands.getoutput('rm '+ outputfile+'/tempsql2.txt')     
    # ex6=commands.getoutput('grep -H -i -n -r -e "insert " '+filename+' >> '+outputfile+'/tempsql.txt')
    # ex7=commands.getoutput('grep -i -r -e "into " '+outputfile+'/tempsql.txt >> '+outputfile+'/sql.txt')
    # ex8=commands.getoutput('rm '+ outputfile+'/tempsql.txt')
    # ex9=commands.getoutput('grep -H -i -n -r -e "delete " '+filename+' >> '+outputfile+'/tempsql.txt')
    # ex10=commands.getoutput('grep -i -r -e "from " '+outputfile+'/tempsql.txt >> '+outputfile+'/sql.txt')
    # ex11=commands.getoutput('rm '+ outputfile+'/tempsql.txt')
    # ex12=commands.getoutput('grep -H -i -n -r -e "alter " '+filename+' >> '+outputfile+'/tempsql.txt')
    # ex13=commands.getoutput('grep -i -r -e "table " '+outputfile+'/tempsql.txt >> '+outputfile+'/sql.txt')
    # ex14=commands.getoutput('rm '+ outputfile+'/tempsql.txt')
    # ex15=commands.getoutput('grep -H -i -n -r -e "update " '+filename+' >> '+outputfile+'/tempsql.txt')
    # ex16=commands.getoutput('grep -i -r -e "set " '+outputfile+'/tempsql.txt >> '+outputfile+'/sql.txt')
    # ex17=commands.getoutput('rm '+ outputfile+'/tempsql.txt')
    outfile = open(outputfile+'/sql.txt','r')
    text = outfile.read()
    # print text
    DBconnect.write_to_db(scan_id,text,5)
    

   
                   

