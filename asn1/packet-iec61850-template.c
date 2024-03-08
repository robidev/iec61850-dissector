/* packet-iec61850_asn1.c
 *
 * Ronnie Sahlberg 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 asn2wrs.py -b -L -p iec61850 -c ./iec61850.cnf -s ./packet-iec61850-template -D . -O ../.. iec61850.asn 
 
 edited mms decoder by robin.dev@gmail.com for iec61850 mapping
 
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "MMS-IEC61850"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include <epan/dissectors/packet-ber.h>

#include "packet-iec61850.h"
#include "map-iec61850.h"

#include <wsutil/wslog.h>

#define PNAME  "IEC-61850 Protocol"
#define PSNAME "IEC61850"
#define PFNAME "iec61850"

#define PNAME_MMS  "MMS Protocol (IEC-61850)"
#define PSNAME_MMS "MMS (IEC61850)"
#define PFNAME_MMS "iec61850.mms"

void proto_register_iec61850(void);
void proto_reg_handoff_iec61850(void);

/* Initialize the protocol and registered fields */
static int32_t proto_iec61850 = -1;
static int32_t proto_mms = -1;

#include "packet-iec61850-hf.c"

/* Initialize the subtree pointers */
static gint ettmms = -1;
#include "packet-iec61850-ett.c"

static expert_field ei_iec61850_mal_timeofday_encoding = EI_INIT;
static expert_field ei_iec61850_mal_utctime_encoding = EI_INIT;
static expert_field ei_mms_zero_pdu = EI_INIT;


static int32_t dissect_acse_EXTERNALt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {  return offset; }
static int32_t dissect_acse_AP_title_stub(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {  return offset; }
static int32_t dissect_acse_AP_invocation_identifier_stub(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {  return offset; }
static int32_t dissect_acse_AE_qualifier_stub(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {  return offset; }
static int32_t dissect_acse_AE_invocation_identifier_stub(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {  return offset; }

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/

/* Helper function to get or create the private data struct */
iec61850_private_data_t* iec61850_get_private_data(asn1_ctx_t *actx)
{
	packet_info *pinfo = actx->pinfo;
	iec61850_private_data_t *private_data = (iec61850_private_data_t *)p_get_proto_data(pinfo->pool, pinfo, proto_iec61850, pinfo->curr_layer_num);
	if(private_data != NULL )
		return private_data;
	else {
		private_data = wmem_new0(pinfo->pool, iec61850_private_data_t);
		p_add_proto_data(pinfo->pool, pinfo, proto_iec61850, pinfo->curr_layer_num, private_data);
		return private_data;
	}
}

/* Helper function to test presence of private data struct */
gboolean
iec61850_has_private_data(asn1_ctx_t *actx)
{
	packet_info *pinfo = actx->pinfo;
	return (p_get_proto_data(pinfo->pool, pinfo, proto_iec61850, pinfo->curr_layer_num) != NULL);
}

void
private_data_add_preCinfo(asn1_ctx_t *actx, guint32 val)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	snprintf(private_data->preCinfo, BUFFER_SIZE_PRE, "%02d ", val);
	private_data->invokeID = val;
}

u_int8_t*
private_data_get_preCinfo(asn1_ctx_t *actx)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	return private_data->preCinfo;
}

void
private_data_add_moreCinfo_domainid(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, 2, tvb_get_guint8(tvb, 1), ENC_STRING), BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, "/", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_itemid(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, 2, tvb_get_guint8(tvb, 1), ENC_STRING), BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_domain(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);

	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, 0, tvb_reported_length_remaining(tvb, 0), ENC_STRING), BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
	
}

void
private_data_add_moreCinfo_float(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	packet_info *pinfo = actx->pinfo;
	u_int8_t *tmp = wmem_alloc0(pinfo->pool, BUFFER_SIZE_MORE );

	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	snprintf(tmp, BUFFER_SIZE_MORE, "%f", tvb_get_ieee_float(tvb, 1, ENC_BIG_ENDIAN));

	(void) g_strlcat(private_data->moreCinfo, tmp, BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_int(asn1_ctx_t *actx, gint val)
{
	packet_info *pinfo = actx->pinfo;
	u_int8_t *tmp = wmem_alloc0(pinfo->pool, BUFFER_SIZE_MORE );

	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	snprintf(tmp, BUFFER_SIZE_MORE,
				"%i", val);
	(void) g_strlcat(private_data->moreCinfo, tmp, BUFFER_SIZE_MORE);			
	(void) g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_str(asn1_ctx_t *actx, char* str)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, str, BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_vstr(asn1_ctx_t *actx,tvbuff_t * tvb, int offset)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, "\"", BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_STRING), BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, "\" ", BUFFER_SIZE_MORE);
}


void
private_data_add_moreCinfo_ostr(asn1_ctx_t *actx,tvbuff_t * tvb, int offset)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, "'", BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_STR_HEX), BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, "' ", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_bstr(asn1_ctx_t *actx,tvbuff_t * tvb, int offset)
{
	packet_info *pinfo = actx->pinfo;

	size_t bytelen = 0;
	size_t berlength = tvb_reported_length_remaining(tvb, 0)-1;
	if(berlength < 1)
	{
		ws_error("could not decode bitstring, ber length too small");
		return;
	}
	u_int32_t padding = tvb_get_guint8(tvb, 0);
	if(padding > 7)
	{
		ws_error("could not decode bitstring, padding value too large");
		return;
	}
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	u_int8_t *bitstring = tvb_get_bits_array(actx->pinfo->pool,tvb, 8, (berlength*8)-padding,&bytelen, ENC_BIG_ENDIAN);

	int32_t i;
	wmem_strbuf_t *strbuf;
	strbuf = wmem_strbuf_new(pinfo->pool, "");

	for (i = 0; i < bytelen; i++)
	{
		wmem_strbuf_append_printf(strbuf, "%02x", bitstring[i]);
	}

	(void) g_strlcat(private_data->moreCinfo, wmem_strbuf_get_str(strbuf), BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
}


void
private_data_add_moreCinfo_bool(asn1_ctx_t *actx, int boolean)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, boolean? "true" : "false", BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_structure(asn1_ctx_t *actx, int dir)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, dir? "{ " : "} ", BUFFER_SIZE_MORE);
}

void
private_data_add_moreCinfo_array(asn1_ctx_t *actx, int dir)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, dir? "[ " : "] ", BUFFER_SIZE_MORE);
}

u_int8_t*
private_data_get_moreCinfo(asn1_ctx_t *actx)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	return private_data->moreCinfo;
}

/*****************************************************************************/


#include "packet-iec61850-fn.c"

/*
* Dissect iec61850 PDUs inside a PPDU.
*/
static int32_t
dissect_iec61850(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int32_t offset = 0;
	int32_t old_offset;
	int32_t decoded = 0;

	proto_item *item=NULL;
	proto_tree *mms_tree=NULL;

	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	
	col_clear(pinfo->cinfo, COL_INFO);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
		mms_tree = proto_item_add_subtree(item, ettmms);
	}

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_iec61850_MMSpdu(FALSE, tvb, offset, &asn1_ctx , mms_tree, -1);
		if(offset == old_offset){
			proto_tree_add_expert(mms_tree, pinfo, &ei_mms_zero_pdu, tvb, offset, -1);
			break;
		}
	}
	//if mms is parsed succesfull, try to map to iec61850 pdu's
	decoded = map_iec61850_packet(tvb, pinfo, &asn1_ctx, parent_tree, mms_tree, proto_iec61850);


	if(decoded == 0)// not an iec61850 PDU
	{
		iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(&asn1_ctx);
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
		if( (private_data->MMSpdu!=-1) && iec61850_MMSpdu_vals[private_data->MMSpdu].strptr ){
			
			if (iec61850_has_private_data(&asn1_ctx))
				col_append_fstr(asn1_ctx.pinfo->cinfo, COL_INFO, "%s%s%s",
					private_data_get_preCinfo(&asn1_ctx), iec61850_MMSpdu_vals[private_data->MMSpdu].strptr, private_data_get_moreCinfo(&asn1_ctx));
			else
				col_append_fstr(asn1_ctx.pinfo->cinfo, COL_INFO, "%s",
					iec61850_MMSpdu_vals[private_data->MMSpdu].strptr);
		}
	}
	else // an iec61850 PDU
	{
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEC-61850");
	}

	return tvb_captured_length(tvb);
}


/*--- proto_register_iec61850 -------------------------------------------*/
void proto_register_iec61850(void) {

	/* List of fields */
	static hf_register_info hf[] =
	{
		//generated items
#include "packet-iec61850-hfarr.c"
	};

	/* List of subtrees */
	static gint *ett_mms[] = {
		&ettmms,
#include "packet-iec61850-ettarr.c"
	};

	static ei_register_info ei_mms[] = {
		{ &ei_iec61850_mal_timeofday_encoding, { "iec61850.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
		{ &ei_iec61850_mal_utctime_encoding, { "iec61850.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
		{ &ei_mms_zero_pdu, { "iec61850.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte iec61850 PDU", EXPFILL }},
	};

	expert_module_t* expert_mms;

	/* Register mms protocol */
	proto_mms = proto_register_protocol(PNAME_MMS, PSNAME_MMS, PFNAME_MMS);
	/* Register fields and subtrees */
	proto_register_field_array(proto_mms, hf, array_length(hf));
	proto_register_subtree_array(ett_mms, array_length(ett_mms));
	expert_mms = expert_register_protocol(proto_mms);
	expert_register_field_array(expert_mms, ei_mms, array_length(ei_mms));

	/* Register iec-61850 protocol */
	proto_iec61850 = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	register_iec61850_mappings(proto_iec61850, hf);
	//proto_register_field_array(protoiec61850, hf, array_length(hf));
	
	//disector register
	register_dissector("iec61850", dissect_iec61850, proto_iec61850);
}


static gboolean
dissect_iec61850_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	/* must check that this really is an iec61850 packet */
	int32_t offset = 0;
	int32_t length = 0 ;
	int32_t oct;
	int32_t idx = 0 ;

	int8_t tmp_class;
	int32_t tmp_pc;
	int32_t tmp_tag;
	/*NOTES

	find_conversation();
conversation_get_proto_data(conversation_t *conv, int proto);
read numbers, store numbers, store a string


NO char[]!!!
use int64_t

tvb_ensure_bytes_exist

sprintf() -> snprintf()

don't use "%lld", "%llu", "%llx", or "%llo" - not all platforms
support "%ll" for printing 64-bit integral data types.  Instead use
the macros in <inttypes.h>, for example:

    proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len,
                                       val, "%" PRIu64, val);


   wmem_strbuf_t *strbuf;
   strbuf = wmem_strbuf_new(pinfo->pool, "");
   wmem_strbuf_append_printf(strbuf, ...

   buffer=wmem_alloc(pinfo->pool, MAX_BUFFER);

Use ws_assert() instead of g_assert() 

*/


		/* first, check do we have at least 2 bytes (pdu) */
	if (!tvb_bytes_exist(tvb, 0, 2))
		return FALSE;	/* no */

	/* can we recognize IEC61850 PDU ? Return FALSE if  not */
	/*   get IEC61850 PDU type */
	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

	/* check IEC61850 type */

	/* Class should be constructed */
	if (tmp_class!=BER_CLASS_CON)
		return FALSE;

	/* see if the tag is a valid IEC61850 PDU */
	try_val_to_str_idx(tmp_tag, iec61850_MMSpdu_vals, &idx);
	if  (idx == -1) {
	 	return FALSE;  /* no, it isn't an IEC61850 PDU */
	}

	/* check IEC61850 length  */
	oct = tvb_get_guint8(tvb, offset)& 0x7F;
	if (oct==0)
		/* IEC61850 requires length after tag so not IEC61850 if indefinite length*/
		return FALSE;

	offset = get_ber_length(tvb, offset, &length, NULL);
	/* do we have enough bytes? */
	if (!tvb_bytes_exist(tvb, offset, length))
		return FALSE;

	dissect_iec61850(tvb, pinfo, parent_tree, data);
	return TRUE;
}

/*--- proto_reg_handoff_iec61850 --- */
void proto_reg_handoff_iec61850(void) {
	register_ber_oid_dissector("1.0.9506.2.3", dissect_iec61850, proto_iec61850,"IEC61850");
	register_ber_oid_dissector("1.0.9506.2.1", dissect_iec61850, proto_iec61850,"iec61850-abstract-syntax-version1(1)");
	heur_dissector_add("cotp", dissect_iec61850_heur, "IEC61850 over COTP", "iec61850_cotp", proto_iec61850, HEURISTIC_ENABLE);
	heur_dissector_add("cotp_is", dissect_iec61850_heur, "IEC61850 over COTP (inactive subset)", "iec61850_cotp_is", proto_iec61850, HEURISTIC_ENABLE);
}

