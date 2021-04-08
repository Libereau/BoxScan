import os, sys
import nmap3
import json
import argparse
import pyfiglet
from colorama import Fore, Style


if not os.geteuid() == 0:
    sys.exit(Fore.RED + "\nNeed to be run as root\n" + Style.RESET_ALL)

os.system('clear')

ascii_banner = pyfiglet.figlet_format("BoxScan")
print(ascii_banner + "By Libereau")

print("\n --------------------------------------- \n")

nmap = nmap3.NmapScanTechniques()

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", required=True, help="IP to scan")
parser.add_argument("-s", "--scan", required=True, type=str, choices=['FULL', 'DEFA', 'VERS'], help="Type of scans, FULL, DEFA, VERS")
args = parser.parse_args()

tab_port = []
ip = args.ip
choice = args.scan

def pingScan():
    print("Scan of "+ip+"\n")

    try:
        os.mkdir("scan_"+ip)
    except:
        print("[!] Directory already exist..\n")

    file_ping = open("scan_"+ip+"/ping_"+ip, "w")

    results = nmap.nmap_ping_scan(ip)
    json.dump(results, file_ping)

    file_ping.close()

    file_ping = open("scan_"+ip+"/ping_"+ip, "r")
    data = json.load(file_ping)

    try:
        state = data[ip]["state"]["state"]

    except:
        sys.exit(Fore.RED + "Host is down." + Style.RESET_ALL)

    print(Fore.GREEN + f"State : {state}" + Style.RESET_ALL)
    scan()


def scan():
    if choice == "FULL":
        full_scan()

    elif choice == "DEFA":
        defa_scan()

    elif choice == "VERS":
        vers_scan()


def full_scan():
    print(Fore.RED + "\n-- Full Scan --\n" + Style.RESET_ALL)

    fullScan = open("scan_"+ip+"/fullScan_"+ip, "w")
    results = nmap.scan_top_ports(ip, 65300, args="-A")
    json.dump(results, fullScan)

    fullScan = open("scan_"+ip+"/fullScan_"+ip, "r")

    data = json.load(fullScan)
    tab_ports = data[ip]["ports"]

    output = ""
    for i in tab_ports:
        port = i['portid']
        tab_port.append(port)
        output += "[+] "+port+" "
        if "name" in i['service']:
            name = i['service']['name']
            output += "\t"+name

            if 'product' in i['service']:
                product = i['service']['product']
                output += "\t"+product

                if 'version' in i['service']:
                    version = i['service']['version']
                    output += "\t"+version

                    searchsploit = ""
                    searchsploit = " ".join(output.replace("\t"," ").split(" ")[4:])
                    #os.system("echo \r\n"+searchsploit+" > scan_"+ip+"/searchsploit_"+ip)
                    os.system("searchsploit "+searchsploit+" >> scan_"+ip+"/searchsploit_"+ip)
                    searchsploit = ""

                    for j in i['scripts'] :
                        if 'raw' in j:
                            if ("Drupal" in j['raw']) or ("Wordpress" in j['raw']) or ("Joomla" in j['raw']):
                                version_cms = j['raw']
                                output += "\t"+version_cms
                                version_cms = " ".join(version_cms.split(" ")[:-1])
                                #os.system("echo \r\n"+version_cms+" >> scan_"+ip+"/searchsploit_"+ip)
                                cmd = "searchsploit "+version_cms+" >> scan_"+ip+"/searchsploit_"+ip
                                os.system(cmd)

        print(Fore.GREEN + output + Style.RESET_ALL)
        output = ""
    print("\n")


def defa_scan():
    print(Fore.RED + "\n-- Default Scan --\n" + Style.RESET_ALL)
    defaultScan = open("scan_"+ip+"/defaultScan_"+ip, "w")
    results = nmap.scan_top_ports(ip, 1000, args="-A")
    json.dump(results, defaultScan)

    defaultScan = open("scan_"+ip+"/defaultScan_"+ip, "r")

    data = json.load(defaultScan)
    name = ""
    version = ""
    product = ""
    tab_ports = data[ip]["ports"]

    output = ""

    for i in tab_ports:

        port = i['portid']
        tab_port.append(port)
        output += "[+] "+port+" "

        if "name" in i['service']:
            name = i['service']['name']
            output += "\t"+name

            if 'product' in i['service']:
                product = i['service']['product']
                output += "\t"+product

                if 'version' in i['service']:
                    version = i['service']['version']
                    output += "\t"+version

                    searchsploit = ""
                    searchsploit = " ".join(output.replace("\t"," ").split(" ")[4:])
                    #os.system("echo \r\n"+searchsploit+" > scan_"+ip+"/searchsploit_"+ip)
                    os.system("searchsploit "+searchsploit+" >> scan_"+ip+"/searchsploit_"+ip)
                    searchsploit = ""

                    for j in i['scripts'] :
                        if 'raw' in j:
                            if ("Drupal" in j['raw']) or ("Wordpress" in j['raw']) or ("Joomla" in j['raw']):
                                version_cms = j['raw']
                                output += "\t"+version_cms
                                version_cms = " ".join(version_cms.split(" ")[:-1])
                                #os.system("echo \r\n"+version_cms+" >> scan_"+ip+"/searchsploit_"+ip)
                                cmd = "searchsploit "+version_cms+" >> scan_"+ip+"/searchsploit_"+ip
                                os.system(cmd)

        print(Fore.GREEN + output + Style.RESET_ALL)
        output = ""


    # TODO print("Go check searchsploit file if not empty")
    try :
        if os.stat("scan_"+ip+"/searchsploit_"+ip).st_size != 0 :
            print(Fore.RED + "\n\t[!] Go check searchsploit_"+ip+" if public known exploit !" + Style.RESET_ALL)

    except:
        pass


def vers_scan():
    print(Fore.RED + "\n-- Version Scan --\n" + Style.RESET_ALL)
    versionScan = open("scan_"+ip+"/versionScan_"+ip, "w")
    results = nmap.scan_top_ports(ip, 100, args="-sV")
    json.dump(results, versionScan)

    versionScan = open("scan_"+ip+"/versionScan_"+ip, "r")

    data = json.load(versionScan)
    tab_ports = data[ip]["ports"]

    output = ""
    for i in tab_ports:
        port = i['portid']
        tab_port.append(port)
        output += "[+] "+port+" "
        if "name" in i['service']:
            name = i['service']['name']
            output += "\t"+name

            if 'product' in i['service']:
                product = i['service']['product']
                output += "\t"+product

                if 'version' in i['service']:
                    version = i['service']['version']
                    output += "\t"+version

        print(Fore.GREEN + output + Style.RESET_ALL)
        output = ""
    print("\n")

def openPort(ip):
    for port in tab_port:
        if port == "21":
            print(Fore.RED + "\n[+] FTP Server \n" + Style.RESET_ALL)
            cmd = f"sudo nmap --script=ftp-anon.nse -p 21 {ip}"
            os.system(cmd)

        elif port == "53":
            domain_name = input("\nEnter domain name (name or nothing): ")

            if domain_name != "":
                scan1 = "dnsenum "+domain_name
                os.system(scan1)

                scan2 = "dnsrecon "+domain_name
                os.system(scan2)

                # transfer zone
                scan3 = "dnsrecon -d "+domain_name+" -a"
                os.system(scan3)

            else :
                print("Skiping..\n")

        elif port == "79":
            print(Fore.RED + "\n[+] Finger enumeration\n" + Style.RESET_ALL)

            cmd1 = "finger @"+ip
            os.system(cmd1)

            user = input("User (user or nothing) : ")

            if user != "":
                cmd2 = "finger "+user+"@"+ip
                os.system(cmd2)


        elif port == "161":
            print(Fore.RED + "\n[+] SNMP\n" + Style.RESET_ALL)
            # TODO

        elif port == "445" : # port == 139
            print(Fore.RED + "\n[+] Smb enumeration\n" + Style.RESET_ALL)
            print(Fore.RED + "[-] Enum4Linux\n" + Style.RESET_ALL)
            cmd1 = "enum4linux -U -S "+ip
            os.system(cmd1)
            print(Fore.RED + "[-] Smbclient" + Style.RESET_ALL)
            cmd2 = "smbclient -L //"+ip+" -U=libereau%root"
            os.system(cmd2)

        elif port == "2049":
            print(Fore.RED + "\n[+] NFS\n" + Style.RESET_ALL)
            cmd1 = "showmount -e "+ip
            os.system(cmd1)

            print("\nCommand to perform next : ")
            # subprocess to grab showmount output
            print("\tsudo mount -v -t nfs "+ip+":<SHARE> <DIRECTORY>")

        elif port == "5800" or port == "58001" or port == "5900" or port == "5901":
            print(Fore.RED + "\n[+] VNC enumeration\n" + Style.RESET_ALL)
            cmd1 = "nmap -sV --script=vnc-info,realvnc-auth-bypass,vnc-title -v -p "+port+" "+ip
            os.system(cmd1)

            cmd2 = "vncviewer "+ip+" "+port
            os.system(cmd2)

    if ("80" in tab_port) or ("443" in tab_port) :
        print(Fore.RED + "\n[+] Web Server\n" + Style.RESET_ALL)

        # Input "go check before ?"
        input("Go check the website before...")

        choices = ["gobuster","hosts","directory", ""]
        choice = input("Actions (gobuster | hosts | directory | '' ) ? ")

        while choice not in choices:
            choice = input("Actions (gobuster | hosts | directory) ?")

        if choice == "gobuster":
            print("Running gobuster.. \n")
            cmd = "gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,html,sh,php -u http://"+ip
            os.system(cmd)

        elif choice == "hosts":
            print("Editing hosts file.. \n")
            cmd1 = "sudo nano /etc/hosts"
            os.system(cmd1)
            print("Running gobuster.. \n")
            cmd2 = "gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,html,sh,php -u http://"+ip
            os.system(cmd2)

        elif choice == "directory":
            dir = input("Directory to add : ")
            ip += "/"+dir # 127.0.0.1/bonjour
            print("Running gobuster.. \n")
            cmd = "gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,html,sh,php -u http://"+ip
            os.system(cmd)

        else :
            pass

pingScan()
openPort(ip)
