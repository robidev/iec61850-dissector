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
#define PSNAME "IEC-61850"
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

static int32_t use_iec61850_mapping = TRUE;

static void proto_update_iec61850_settings(void);
static int32_t dissect_acse_EXTERNALt(int32_t implicit_tag _U_, tvbuff_t *tvb _U_, int32_t offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int32_t hf_index _U_) {  return offset; }
static int32_t dissect_acse_AP_title_stub(int32_t implicit_tag _U_, tvbuff_t *tvb _U_, int32_t offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int32_t hf_index _U_) {  return offset; }
static int32_t dissect_acse_AP_invocation_identifier_stub(int32_t implicit_tag _U_, tvbuff_t *tvb _U_, int32_t offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int32_t hf_index _U_) {  return offset; }
static int32_t dissect_acse_AE_qualifier_stub(int32_t implicit_tag _U_, tvbuff_t *tvb _U_, int32_t offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int32_t hf_index _U_) {  return offset; }
static int32_t dissect_acse_AE_invocation_identifier_stub(int32_t implicit_tag _U_, tvbuff_t *tvb _U_, int32_t offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int32_t hf_index _U_) {  return offset; }

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
	{
		return private_data;
	}
	else 
	{
		private_data = wmem_new0(pinfo->pool, iec61850_private_data_t);
		private_data->preCinfo = wmem_alloc0(pinfo->pool, IEC61850_BUFFER_SIZE_PRE);
		private_data->moreCinfo = wmem_alloc0(pinfo->pool, IEC61850_BUFFER_SIZE_MORE);
		p_add_proto_data(pinfo->pool, pinfo, proto_iec61850, pinfo->curr_layer_num, private_data);
		return private_data;
	}
}

/* Helper function to test presence of private data struct */
int32_t iec61850_has_private_data(asn1_ctx_t *actx)
{
	packet_info *pinfo = actx->pinfo;
	return (p_get_proto_data(pinfo->pool, pinfo, proto_iec61850, pinfo->curr_layer_num) != NULL);
}

static void
private_data_add_preCinfo(asn1_ctx_t *actx, u_int32_t val)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	snprintf(private_data->preCinfo, IEC61850_BUFFER_SIZE_PRE, "%02d ", val);
	private_data->invokeID = val;
}

u_int8_t*
iec61850_private_data_get_preCinfo(asn1_ctx_t *actx)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	return private_data->preCinfo;
}

static void
private_data_add_moreCinfo_domainid(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, 2, tvb_get_guint8(tvb, 1), ENC_STRING), IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, "/", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_itemid(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, 2, tvb_get_guint8(tvb, 1), ENC_STRING), IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_vmd(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, "<", IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, 0, tvb_reported_length_remaining(tvb, 0), ENC_STRING), IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, "> ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_domain(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);

	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, 0, tvb_reported_length_remaining(tvb, 0), ENC_STRING), IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
	
}

static void
private_data_add_moreCinfo_float(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	packet_info *pinfo = actx->pinfo;
	u_int8_t *tmp = wmem_alloc0(pinfo->pool, IEC61850_BUFFER_SIZE_MORE );

	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	snprintf(tmp, IEC61850_BUFFER_SIZE_MORE, "%f", tvb_get_ieee_float(tvb, 1, ENC_BIG_ENDIAN));

	(void) g_strlcat(private_data->moreCinfo, tmp, IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_int(asn1_ctx_t *actx, int32_t val)
{
	packet_info *pinfo = actx->pinfo;
	u_int8_t *tmp = wmem_alloc0(pinfo->pool, IEC61850_BUFFER_SIZE_MORE );

	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	snprintf(tmp, IEC61850_BUFFER_SIZE_MORE,"%i", val);
	(void) g_strlcat(private_data->moreCinfo, tmp, IEC61850_BUFFER_SIZE_MORE);			
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_str(asn1_ctx_t *actx, u_int8_t* str)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, str, IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_vstr(asn1_ctx_t *actx,tvbuff_t * tvb, int32_t offset)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, "\"", IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
				tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_STRING), IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, "\" ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_enum(asn1_ctx_t *actx, int32_t value, const value_string * enum_list)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, try_val_to_str(value, enum_list), IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static int32_t is_text(u_int8_t * str)
{
	int32_t i = 0;
	if(g_str_is_ascii(str))
	{
		for(i = 0; i < strlen(str); i++)
		{
			if( str[i] < 0x20)
			{
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

static void
private_data_add_moreCinfo_ostr(asn1_ctx_t *actx,tvbuff_t * tvb, int32_t offset)
{
	int32_t i;
	u_int8_t temp[4] = "";
	u_int8_t * ostr = NULL;
	size_t len;
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);

	ostr = tvb_get_string_enc(actx->pinfo->pool, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII);
	len = strlen(ostr);
	if(len > 0)
	{
		(void) g_strlcat(private_data->moreCinfo, "'", IEC61850_BUFFER_SIZE_MORE);
		for (i = 0; i < len; i ++) 
		{
			snprintf(temp, sizeof(temp),"%02x", ostr[i]);
			(void) g_strlcat(private_data->moreCinfo, temp, IEC61850_BUFFER_SIZE_MORE);
		}
		(void) g_strlcat(private_data->moreCinfo, "'", IEC61850_BUFFER_SIZE_MORE);

		if(is_text(ostr) == TRUE)
		{
			(void) g_strlcat(private_data->moreCinfo, "( ", IEC61850_BUFFER_SIZE_MORE);
			(void) g_strlcat(private_data->moreCinfo, ostr, IEC61850_BUFFER_SIZE_MORE);
			(void) g_strlcat(private_data->moreCinfo, " )", IEC61850_BUFFER_SIZE_MORE);
		}
		(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
	}
 	else
		(void) g_strlcat(private_data->moreCinfo, "'' ", IEC61850_BUFFER_SIZE_MORE);
}

u_int32_t iec61850_print_bytes(wmem_strbuf_t *strbuf, u_int8_t *bitstring, size_t bytelen, u_int32_t padding)
{
  	u_int32_t count = 0;
    u_int8_t byte;
    int32_t i, j, end = 0;

	wmem_strbuf_append_printf(strbuf,"b'");
    for (i = 0; i < bytelen; i++) 
	{
		if(i == bytelen-1) /* padding applies */
		{
			end = padding;			
		}
		else
		{
			end = 0;			
		}
        for (j = 7; j >= end; j--) 
		{
            byte = (bitstring[i] >> j) & 1;
            wmem_strbuf_append_printf(strbuf, "%u", byte);
			count += byte;
        }
    }
	wmem_strbuf_append_printf(strbuf,"'");
	return count;
}

static void
private_data_add_moreCinfo_bstr(asn1_ctx_t *actx,tvbuff_t * tvb, int32_t offset)
{
	wmem_strbuf_t *strbuf;
	u_int8_t *bitstring;
	packet_info *pinfo = actx->pinfo;
	
	size_t bytelen = 0;
	size_t berlength = tvb_reported_length_remaining(tvb, 0)-1;
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	if(berlength < 1)
	{
		ws_warning("could not decode bitstring, ber length too small");
    	(void) g_strlcat(private_data->moreCinfo, "b'' ", IEC61850_BUFFER_SIZE_MORE); // it may be valid to leave the field length zero, implying all data is zero
		return;
	}
	u_int32_t padding = tvb_get_guint8(tvb, 0);
	if(padding > 7)
	{
		ws_warning("could not decode bitstring, padding value too large");
		return;
	}
	bitstring = tvb_get_bits_array(actx->pinfo->pool,tvb, 8, (berlength*8)-padding,&bytelen, ENC_BIG_ENDIAN);

	strbuf = wmem_strbuf_new(pinfo->pool, "");
	iec61850_print_bytes(strbuf,bitstring,bytelen, padding);

	(void) g_strlcat(private_data->moreCinfo, wmem_strbuf_get_str(strbuf), IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}


static void
private_data_add_moreCinfo_bool(asn1_ctx_t *actx, int32_t boolean)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, boolean? "true" : "false", IEC61850_BUFFER_SIZE_MORE);
	(void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_structure(asn1_ctx_t *actx, int32_t dir)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, dir? "{ " : "} ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_array(asn1_ctx_t *actx, int32_t dir)
{
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	(void) g_strlcat(private_data->moreCinfo, dir? "[ " : "] ", IEC61850_BUFFER_SIZE_MORE);
}

u_int8_t*
iec61850_private_data_get_moreCinfo(asn1_ctx_t *actx)
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
	int32_t error = 0;
	asn1_ctx_t asn1_ctx;

	proto_item *mms_item=NULL;
	proto_tree *mms_tree=NULL;

	ws_assert(tvb);
	ws_assert(pinfo);

	/* only dissect MMS, and return immediately */
	if(use_iec61850_mapping == FALSE)
	{
		dissector_handle_t mms_dissector = find_dissector( "mms" );
		ws_assert(mms_dissector);
		call_dissector(mms_dissector, tvb, pinfo, parent_tree);
		return tvb_captured_length(tvb);
	}

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_clear(pinfo->cinfo, COL_INFO);

	if(parent_tree)
	{
		mms_item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
		mms_tree = proto_item_add_subtree(mms_item, ettmms);
	}

	while (tvb_reported_length_remaining(tvb, offset) > 0)
	{
		old_offset=offset;
		/* parse mms similar to mms disector to retrieve all relevant values for mapping, and store in private data */
		offset=dissect_iec61850_MMSpdu(FALSE, tvb, offset, &asn1_ctx , mms_tree, -1);
		if(offset == old_offset)
		{
			proto_tree_add_expert(mms_tree, pinfo, &ei_mms_zero_pdu, tvb, offset, -1);
			error = 1;
			break;
		}
	}
	if(error == 0)/* if mms is parsed without issue, try to map to iec61850 pdu's */
	{
		decoded = map_iec61850_packet(tvb, pinfo, &asn1_ctx, parent_tree, mms_tree, proto_iec61850);
	}
	if(decoded == 1)/* if we decoded an IEC-61850 PDU succesfull */
	{
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEC-61850");
	}
	else /*  not an IEC-61850 PDU, so remove IEC-61850 data from this packet, and dissect as mms */
	{
		dissector_handle_t mms_dissector = find_dissector( "mms" );
		ws_assert(mms_dissector);

		proto_item_set_hidden(mms_item); /* hide the iec61850 mms layer, as the mms disector will add its own*/
		col_clear(pinfo->cinfo, COL_INFO);
		call_dissector(mms_dissector, tvb, pinfo, parent_tree);
	}

	return tvb_captured_length(tvb);
}


/*--- proto_register_iec61850 -------------------------------------------*/
void proto_register_iec61850(void) 
{

	/* List of fields */
	static hf_register_info hf[] =
	{
		/*generated items */
#include "packet-iec61850-hfarr.c"
	};

	/* List of subtrees */
	static int32_t *ett_mms[] = {
		&ettmms,
#include "packet-iec61850-ettarr.c"
	};

	static ei_register_info ei_mms[] = {
		{ &ei_iec61850_mal_timeofday_encoding, { "iec61850.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
		{ &ei_iec61850_mal_utctime_encoding, { "iec61850.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
		{ &ei_mms_zero_pdu, { "iec61850.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte iec61850 PDU", EXPFILL }},
	};

	expert_module_t* expert_mms;
	module_t * iec61850_module;

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

	/* disector register */
	register_dissector("iec61850", dissect_iec61850, proto_iec61850);

	/* setting to enable/disable the IEC-61850 mapping on MMS */
    iec61850_module = prefs_register_protocol(proto_iec61850, proto_update_iec61850_settings);

    prefs_register_bool_preference(iec61850_module, "use_iec61850_mapping",
                                 "Use IEC-61850 mapping to decode MMS stream",
                                 "Enables or disables the layer that maps IEC-61850 on top of MMS",
                                 &use_iec61850_mapping);
}


/*--- proto_reg_handoff_iec61850 --- */
void proto_reg_handoff_iec61850(void) 
{
	register_ber_oid_dissector("1.0.9506.2.3", dissect_iec61850, proto_iec61850,"IEC61850");
	register_ber_oid_dissector("1.0.9506.2.1", dissect_iec61850, proto_iec61850,"iec61850-abstract-syntax-version1(1)");
}

static void proto_update_iec61850_settings(void)
{

}