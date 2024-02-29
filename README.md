# using


## issues
normally, the protocol disector should detect iec61850. However, when the COTP-PRES(presentation) request packet is missing, the disector will not identify the BER OID correctly, and therefore not load the iec-61850 dissector..

This can be fixed by setting the BER OID manually:
right click the packet in the top-window, and go to "protocol preferences"-> "ISO 8823 OSI Presentation Protocol" -> "Users context list.." and add a line with the following data
Context ID: "3"
Syntax name OID: "1.0.9506.2.1"

Context id:3 means mms
Syntax name OID: "1.0.9506.2.1" means the mms schema

now the IEC-61850 dissector will decode the packets.


# building

## ubuntu

### in tree

dependencies
`$ sudo apt install git build-essential cmake` 

clone source
`$ git clone --branch 3.6 https://github.com/wireshark/wireshark.git`

install dependencies
`$ tools/debian-setup.sh` 


### out of tree
dependencies
`$ sudo apt install git build-essential cmake wireshark wireshark-dev` 

clone source
`$ git clone --branch 3.6 https://github.com/robidev/iec61850-dissector.git`
please ensure there are no spaces in the build path! this will give errors when running cmake and make in the next steps!


build plugin
```
$ mkdir build
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make
$ make install
```

### asn1 code generation
dependencies: python3
for building asn.1, copy the tools folder with asn2wrs.py from the correct version of wireshark(3.6 or 4.x matters!)/ and ensure asn/generate.sh refers to it. run it from the folder with all the files. the output is generated in the parent folder(overwriting any similar named file there!


## windows





# developping/debugging
when using the asn1 generator, the #line will cause editors to misalign breakpoints set in packet-iec61850.c
