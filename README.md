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
- Then it will scan, with nmap, more aggressivly the box, output the result in xml, convert it in html, and show the output in Firefox

## Usage

Basic usage :
- `./boxscan.py [-i | --ip] <ip> [-s | --scan] {FULL | DEFA | VERS}`

## Requirements

See requirements.txt

Command :
- `pip3 install -r requirements`

## DONE

- [X] Add execution time
- [X] Ping Scan - Need to check for host down
- [X] Scan nmap
- [X] Parsing nmap output according to open ports
- [X] Launch specific scans
- [X] Nmap output in xml and spawn firefox with the output displayed

## TODO
- [ ] Add file for scan's output
- [ ] Create report
- [ ] Change nmap for masscan
