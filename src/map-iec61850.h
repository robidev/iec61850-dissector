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

void register_iec61850_mappings(const int parent);
int map_iec61850_packet(tvbuff_t *tvb, packet_info *pinfo, asn1_ctx_t *actx, proto_tree *parent_tree, proto_tree *mms_tree, const int proto_iec61850);

#endif  /* MAP_IEC61850_H */

