/* map-iec61850.h                                                          
 * Routines for IEC61850 packet dissection
 *   Robin Massink
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MAP_IEC61850_H
#define MAP_IEC61850_H

#include <stdint.h>
/* register all IEC-61850 elements for the disector table */
void register_iec61850_mappings(const int32_t parent,hf_register_info * mms_hf);

/* parse the packet for IEC61850 dissection. Returns 1 if it was a(partial) , decoded IEC-61850 packet *, 0 if it was not recognised as an IEC-61850 service */
int32_t map_iec61850_packet(tvbuff_t *tvb, packet_info *pinfo, asn1_ctx_t *actx, proto_tree *parent_tree, proto_tree *mms_tree, const int32_t proto_iec61850);

#endif  /* MAP_IEC61850_H */

