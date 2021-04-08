# BoxScan

![image](https://user-images.githubusercontent.com/41334665/114028605-f478ff80-9878-11eb-900e-f54254e99e7d.png)

Project started on March 30th 2021.
Written in python3.

## Presentation

This script is aimed for automated enumeration for OSCP certification.
It will perform :
- Ping scan
- Nmap scan (default, full scan, or version scan)
- Specific scan according to nmap output

## Usage

Basic usage :
- ./boxscan.py [-i | --ip] <ip> [-s | --scan] {FULL | DEFA | VERS}

## Requirements

See requirements.txt

Command :
- `pip3 install -r requirements`

## TODO

- [ ] Add execution time
- [X] Ping Scan - Need to check for host down
- [X] Scan nmap

- [X] Searchsploit on services / versions - OK, but need to be better
- [X] Parsing nmap according to open ports
- [X] Launch specific scans (focus web)
- [ ] Add file for scan's output 
- [ ] Nmap output in xml and spawn python server (better reading experience)

Later :
- [ ] Create report
- [ ] Change nmap for masscan
