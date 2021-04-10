import os
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("-i", "--ip", required=True, help="IP to scan")
args = parser.parse_args()
ip = args.ip

nmap_parse = "/home/libereau/nmap-parse-output/nmap-parse-output"

os.system("nmap "+ip+" --min-rate 1000 --top-ports 1000 -A -sC -sV -T5 --version-intensity 8 -oX scan_"+ip+"/output.xml >/dev/null")
os.system(nmap_parse+" scan_"+ip+"/output.xml html > scan_"+ip+"/output.html") #marche pas


os.system("firefox scan_"+ip+"/output.html")
