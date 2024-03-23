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

#define IEC61850_BUFFER_SIZE_PRE 10
#define IEC61850_BUFFER_SIZE_MORE 1024

/* container for all relevant IEC-61850 specific data obtained during disection */
typedef struct iec61850_private_data_t
{
	u_int8_t *preCinfo;
	u_int8_t *moreCinfo;
	int32_t MMSpdu;							/* type of request */
    int32_t Service;						/* confirmed/unconfirmed */
	int32_t AccessResult; 					/* success/failure */
	int32_t VariableAccessSpecification;	/* RPT or CMDTerm */
	int32_t AlternateAccess; 				/* alternate access defined */
	int32_t ObjectName;						/* 0,1,2 (VMD-SPECIFIC,domain-specific,aa-specific) */
	int32_t objectScope;					/* 0,1,2 (VMD-SPECIFIC,domain-specific,aa-specific) */
	int32_t objectClass;					/* VariableName,NamedVariable, journal */
	int32_t Success;						/* true or false */
	int32_t DataType; 						/* array, struct, bool, bit-string, int, uint, float, octet, vis-string, bin-time, bcd, boolarr, mmsstring, utctime */
    int32_t indent;							/* depth during printing */
	int32_t invokeID;						/* id of request and response */
	int32_t DataAccessError;				/* error code of response */
} iec61850_private_data_t;


/* Helper function to get or create the private data struct */
iec61850_private_data_t* iec61850_get_private_data(asn1_ctx_t *actx);
/* Helper function to test presence of private data struct */
int32_t iec61850_has_private_data(asn1_ctx_t *actx);
/* Get the session id added to a packet, for printing in the packet-view info-column */
u_int8_t* iec61850_private_data_get_preCinfo(asn1_ctx_t *actx);
/* Get the information added to a packet, for printing in the packet-view info-column */
u_int8_t* iec61850_private_data_get_moreCinfo(asn1_ctx_t *actx);

/* Create a text string of zeros and ones, based on an array of bytes. Returns the number of '1' bits */
u_int32_t iec61850_print_bytes(wmem_strbuf_t *strbuf, const u_int8_t *bitstring, size_t bytelen, u_int32_t padding);
/* Check if an octet array of bytes contains text, and no characters that cause issues in the dissector tree */
int32_t iec61850_octetstring_is_text(u_int8_t * str);

#include "packet-iec61850-exp.h"

#endif  /* PACKET_IEC61850_H */

