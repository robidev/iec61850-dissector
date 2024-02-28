#!/bin/bash
../tools/asn2wrs.py -b -L -p iec61850 -c ./iec61850.cnf -s ./packet-iec61850-template -D . -O ../src iec61850.asn 
rm parsetab.py
