/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-iec61850.h                                                          */
/* asn2wrs.py -b -L -p iec61850 -c ./iec61850.cnf -s ./packet-iec61850-template -D . -O ../src iec61850.asn */

/* packet-iec61850.h
 * Routines for IEC61850 packet dissection
 *   Ronnie Sahlberg 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_IEC61850_H
#define PACKET_IEC61850_H

#define BUFFER_SIZE_PRE 10
#define BUFFER_SIZE_MORE 1024

typedef struct iec61850_private_data_t
{
	char preCinfo[BUFFER_SIZE_PRE];
	char moreCinfo[BUFFER_SIZE_MORE];
	int MMSpdu;
    int Service;//confirmed/unconfirmed
	int AccessResult; // success/failure
	int VariableAccessSpecification; 
	bool alternateAccess;
	int ObjectName;
	int DataType; //array, struct, bool, bit-string, int, uint, float, octet, vis-string, bin-time, bcd, boolarr, mmsstring, utctime
    
} iec61850_private_data_t;


/* Helper function to get or create the private data struct */
iec61850_private_data_t* iec61850_get_private_data(asn1_ctx_t *actx);
/* Helper function to test presence of private data struct */
gboolean iec61850_has_private_data(asn1_ctx_t *actx);
void private_data_add_preCinfo(asn1_ctx_t *actx, guint32 val);
char* private_data_get_preCinfo(asn1_ctx_t *actx);
void private_data_add_moreCinfo_id(asn1_ctx_t *actx, tvbuff_t *tvb);
void private_data_add_moreCinfo_float(asn1_ctx_t *actx, tvbuff_t *tvb);
char* private_data_get_moreCinfo(asn1_ctx_t *actx);




#endif  /* PACKET_IEC61850_H */

