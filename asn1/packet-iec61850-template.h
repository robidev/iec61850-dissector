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
	int VariableAccessSpecification; //RPT/CMDTerm
	int ObjectName;//0,1,2 (VMD-SPECIFIC,domain-specific,aa-specific)
	int objectScope;////0,1,2 (VMD-SPECIFIC,domain-specific,aa-specific)
	int objectClass;//VariableName,NamedVariable, journal
	int Success;//
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



#include "packet-iec61850-exp.h"

#endif  /* PACKET_IEC61850_H */

