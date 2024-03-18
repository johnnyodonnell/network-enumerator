#!/bin/bash

TARGET=$1


### Ping scans ################################################################

sudo nmap -sn -PE -PP -PM $TARGET # Ping scan (ARP ping, ICMP Timestamp, Address Mask)
sudo nmap -sn -PA443 -PA80 $TARGET # Ping scan (TCP ACK Ping ports 80 + 443)
nmap -sn $TARGET # Ping scan (TCP Connect)

### No ping, standard scan ####################################################

sudo nmap -Pn $TARGET # top ports
sudo nmap -Pn -p- $TARGET # all ports

### No ping, special scan, top ports ##########################################

sudo nmap -Pn -sA $TARGET # TCP ACK
sudo nmap -Pn -sY $TARGET # SCTP INIT

### No ping, special scan, all ports ##########################################

sudo nmap -Pn -sA -p- $TARGET # TCP ACK
sudo nmap -Pn -sY -p- $TARGET # SCTP INIT


## Currently no UDP scans

