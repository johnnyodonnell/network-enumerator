#!/bin/bash

# Created initially to help with the OSCP course

TARGET=$1


############################### TCP enumeration ###############################
sudo nmap -sV $TARGET # Will scan the top 1000 ports
sudo nmap -v -p- $TARGET # Will scan all ports
sudo nmap -v -p- --max-scan-delay 5ms --max-retries 1 $TARGET


############################### UDP enumeration ###############################
# Supporting documents:
# https://nmap.org/book/scan-methods-udp-scan.html
# https://github.com/johnnyodonnell/notes-on-oscp-lab-machines/blob/master/10.11.1.111/notes.txt

# TFTP is scanned in a separate command because it is a top 20 UDP protocol
# accroding to nmap and because it requires a separate script to determine
# if it is actually open

# https://nmap.org/book/scan-methods-udp-scan.html warns against limiting
# scan delay for UDP scans because it risks overlooking open UDP ports;
# but, I haven't seen any issues with this in practice so far

sudo nmap -sUV --top-ports 20 $TARGET
sudo nmap -sU --script=tftp-enum -p 69 $TARGET

sudo nmap -v -sUV $TARGET # Will scan the top 1000 ports
sudo nmap -v -sUV --max-scan-delay 50ms --max-retries 1 $TARGET
sudo nmap -v -sU --script=tftp-enum $TARGET
sudo nmap -v -sU --script=tftp-enum --max-scan-delay 50ms --max-retries 1 $TARGET

sudo nmap -v -sUV -p- $TARGET # Will scan all ports
sudo nmap -v -sU --script=tftp-enum -p- $TARGET
sudo nmap -v -sUV -p- --max-scan-delay 50ms --max-retries 1 $TARGET
sudo nmap -v -sU --script=tftp-enum -p- --max-scan-delay 50ms --max-retries 1 $TARGET

