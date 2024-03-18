#!/bin/bash

HOSTS=$1


### Ping scans ################################################################

sudo nmap -sn $HOSTS # Ping scan (ARP ping)
nmap -sn $HOSTS # Ping scan (TCP Connect)
sudo nmap -sn -PE -PP -PM $HOSTS # Ping scan (Timestamp and address mask)

### No ping, top ports ########################################################

sudo nmap -Pn $HOSTS
sudo nmap -Pn -sA -p- $HOSTS # TCP ACK

### No ping, all ports ########################################################

sudo nmap -Pn -p- $HOSTS
sudo nmap -Pn -sA -p- $HOSTS # TCP ACK

