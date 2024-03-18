#!/bin/bash

HOSTS=$1


### Simple ping ###############################################################

sudo nmap -sn $HOSTS # Ping scan (ARP ping)
nmap -sn $HOSTS # Ping scan (TCP Connect)
sudo nmap -sn -PE -PP -PM $HOSTS # Ping scan (Timestamp and address mask)

sudo nmap -Pn $HOSTS # No ping, top ports
sudo nmap -Pn -sA -p- $HOSTS # No ping, TCP ACK, top ports

sudo nmap -Pn -p- $HOSTS # No ping, all ports
sudo nmap -Pn -sA -p- $HOSTS # No ping, TCP ACK, all ports

