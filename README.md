# IEC-61850 dissector

IEC-61850 is a mapping on top of MMS that uses a subset of MMS PDU's for its purpose; substation communication.  

While an MMS dissector, which IEC-61850 maps onto already exists, this MMS dissector lacks a lot of IEC-61850  specific context. For example, an unconfirmed-PDU in MMS, may in IEC-61850 be a Report, CommandTermination or Addcause. Each of these messages in turn may contain fields with specific meaning in the context of the protocol-mapping(e.g. first entry shall be ReportID, second field defines included optional fields that in turn define the field-names of subsequent entries). This type of information is quite hard to decode from the pure MMS packet, and therefore this dissector is created to assist with the IEC-61850 context-specific encoding.  

# Using

The dissector can be obtained by downloading the .so or dll from the github releases section for your version of wireshark. I provided compiled versions for wireshark 3.6 (provided by Ubuntu 22.04 LTS apt package) and wireshark 4.2 and 4.3 compiled on Fedora 39. Additionally, a compiled version on windows 10 is provided for wireshark 4.2 (latest stable version as of writing). Alternatively, you can compile your own, by checking out the respective 3.6, 4.2 or 4.3 branch, put it in the plugins/epan folder, and add plugins/epan/iec61850-dissector to the plugin section in CMakeLists.txt before compiling the complete source by following the instructions in the wireshark documentation.  

Installation of the dissector can be done by copying the .so/.dll to the plugin folder, or by using the gui option. (only available in the newest wireshark version).  

## Enable/disable the dissector

The dissector can be enabled/disabled in the preferences under protocols/IEC-61850. The default is to be enabled. If you disable the dissector, the wireshark native dissector is used instead.


## Issues with dissecting

### Missing COTP-PRES request packet

Normally, the protocol disector should detect iec61850. However, when the COTP-PRES(presentation) request packet is missing, the disector will not identify the BER OID correctly, and therefore not load the iec-61850 dissector.  

This can be fixed by setting the BER OID manually:  
right click the packet in the top-window, and go to "protocol preferences"-> "ISO 8823 OSI Presentation Protocol" -> "Users context list.." and add a line with the following data  
Context ID: "3"  
Syntax name OID: "1.0.9506.2.1"  

Context id:3 means mms  
Syntax name OID: "1.0.9506.2.1" means the mms schema  

now the IEC-61850 dissector should decode the packets.  

### Dissecting IEC-61850 on a non-standard port

If a different tcp-port than 102 is used, you need to set decode-as to tell wireshark how to decode the packet. 
For that, you select the following options in the decode-as dialog (right-click a packet, and select 'Decode As..')
Field: TCP Port, Value: [alternative tcp-port], Type: Integer,base 10, Current: TPKT


# Building

## in tree

This build means you build the complete wireshark source, while the dissector is included inside the source-tree, and referenced by the CMakeLists.txt  

dependencies  
`$ sudo apt install git build-essential cmake` 

<<<<<<< HEAD
clone source
`$ git clone --branch 3.6 https://github.com/wireshark/wireshark.git`
=======
clone source  
`$ git clone --branch 4.3 https://github.com/wireshark/wireshark.git`
>>>>>>> 7dff145 (updated readme)

install dependencies  
`$ cd wireshark`  
`$ tools/debian-setup.sh` 

clone dissector source in plugin folder  
`cd plugins/epan`  
`$ git clone --branch 4.3 https://github.com/robidev/iec61850-dissector.git`

edit CMakeLists.txt to include this plugin  
`$ cd ../..`  
`$ vi CMakeLists.txt`  
find the line `set(PLUGIN_SRC_DIRS` around line 1707, and add `plugins/epan/iec61850-dissector`  

create a build dir  
`$ mkdir build`
and build the project  
`cmake ..; make`

the compiled binary should be located in `build/run/plugins/epan` and called `iec61850.so` or similar  

## out of tree

This means building the plugin stand-alone. This has only been tested on Ubuntu 22.04 LTS with wireshark 3.6.  

dependencies  
`$ sudo apt install git build-essential cmake wireshark wireshark-dev` 

<<<<<<< HEAD
clone source
`$ git clone --branch 3.6 https://github.com/robidev/iec61850-dissector.git`
please ensure there are no spaces in the build path! this will give errors when running cmake and make in the next steps!
=======
clone source  
`$ git clone --branch 3.6 https://github.com/robidev/iec61850-dissector.git`
please ensure there are no spaces in the build path! this will give errors when running cmake and make in the next steps!  
>>>>>>> 7dff145 (updated readme)

build plugin  
```
$ mkdir build
$ cmake ..
$ make
$ make install
```
The final step will install the plugin in a local plugin directory that wireshark uses to load plugins from.

## windows build

Windows binaries can only be build in-tree. Follow similar steps as above for building in-tree on linux, but make sure the windows guide is followed that is published as part of the wireshark documentation. [https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWindows] It is quite cumbersome to get right. A plugin build with the mingw alternative or cross-platform build can only be used on a mingw build version of wireshark.

## asn1 code generation
dependencies: python3  

To regenerate the provided packet-iec61850.c and packet-iec61850.h files from the template and .asn/.cnf file in the asn1 directory, copy the tools folder with asn2wrs.py from the correct version of wireshark(3.6,4.2 or 4.3 matters!) and ensure asn/generate.sh refers to it. run it from the folder with all the files. the output is generated in the parent folder(overwriting any similar named file there!)  


# developping/debugging
when using the asn1 generator, the #line will cause editors to misalign breakpoints set in packet-iec61850.c for versions older then 4.3. comment out the line before performing a `$ make; make install`  

## test captures

In the test folder of this project are some IEC-61850 captures that have been found online, and/or made with libiec61850 from mz-automation. I lack access to extensive captures and traces, so if you notice an error in disection, a missing feature or even worse; a crash. Please let me know.

