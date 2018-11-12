#!/bin/sh
#Iptables configuração.

iptables -A INPUT -p tcp --destination-port 80:65535 -j DROP

