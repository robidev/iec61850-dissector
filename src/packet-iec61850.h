/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-iec61850.h                                                          */
/* asn2wrs.py -b -L -p iec61850 -c ./iec61850.cnf -s ./packet-iec61850-template -D . -O ../src iec61850.asn */

/* Input file: packet-iec61850-template.h */

#line 1 "./wireshark_dissector/asn1/packet-iec61850-template.h"
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
	u_int8_t preCinfo[BUFFER_SIZE_PRE];
	u_int8_t moreCinfo[BUFFER_SIZE_MORE];
	int32_t MMSpdu;
    int32_t Service;//confirmed/unconfirmed
	int32_t AccessResult; // success/failure
	int32_t VariableAccessSpecification; //RPT/CMDTerm
	int32_t AlternateAccess; // alternate access defined
	int32_t ObjectName;//0,1,2 (VMD-SPECIFIC,domain-specific,aa-specific)
	int32_t objectScope;////0,1,2 (VMD-SPECIFIC,domain-specific,aa-specific)
	int32_t objectClass;//VariableName,NamedVariable, journal
	int32_t Success;//
	int32_t DataType; //array, struct, bool, bit-string, int, uint, float, octet, vis-string, bin-time, bcd, boolarr, mmsstring, utctime
    int32_t indent;
	int32_t invokeID;
	int32_t DataAccessError;

} iec61850_private_data_t;


/* Helper function to get or create the private data struct */
iec61850_private_data_t* iec61850_get_private_data(asn1_ctx_t *actx);
/* Helper function to test presence of private data struct */
int32_t iec61850_has_private_data(asn1_ctx_t *actx);
void private_data_add_preCinfo(asn1_ctx_t *actx, u_int32_t val);
u_int8_t* private_data_get_preCinfo(asn1_ctx_t *actx);
void private_data_add_moreCinfo_id(asn1_ctx_t *actx, tvbuff_t *tvb);
void private_data_add_moreCinfo_float(asn1_ctx_t *actx, tvbuff_t *tvb);
u_int8_t* private_data_get_moreCinfo(asn1_ctx_t *actx);




/*--- Included file: packet-iec61850-exp.h ---*/
#line 1 "./wireshark_dissector/asn1/packet-iec61850-exp.h"

/*--- End of included file: packet-iec61850-exp.h ---*/
#line 52 "./wireshark_dissector/asn1/packet-iec61850-template.h"

#endif  /* PACKET_IEC61850_H */

