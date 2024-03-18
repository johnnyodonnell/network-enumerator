#!/bin/bash

TARGET=$1


### Ping scans ################################################################

sudo nmap -sn $TARGET # Ping scan (ARP ping)
nmap -sn $TARGET # Ping scan (TCP Connect)
sudo nmap -sn -PE -PP -PM $TARGET # Ping scan (Timestamp and address mask)

### No ping, top ports ########################################################

sudo nmap -Pn $TARGET
sudo nmap -Pn -sA -p- $TARGET # TCP ACK

### No ping, all ports ########################################################

sudo nmap -Pn -p- $TARGET
sudo nmap -Pn -sA -p- $TARGET # TCP ACK

