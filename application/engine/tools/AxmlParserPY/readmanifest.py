#!/usr/bin/python
import sys
import axmlprinter
from xml.dom import minidom

def main():
  filename=sys.argv[1]
  ap = axmlprinter.AXMLPrinter(open(filename+'/AndroidManifest.xml', 'rb').read())
  buff = minidom.parseString(ap.getBuff()).toxml()
  print(buff)
  f = open(filename+'/AndroidManifest_readable.xml', 'w')
  f.write(buff)
  f.close()

if __name__ == "__main__":
  main()
