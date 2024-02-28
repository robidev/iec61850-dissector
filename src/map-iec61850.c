/* map-iec61850.c
 *
 * Robin Massink
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "MAP-IEC61850"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include <epan/dissectors/packet-ber.h>

#include "map-iec61850.h"
#include "packet-iec61850.h"

#include <wsutil/wslog.h>


static int hf_iec61850_Unconfirmed = -1;
static int hf_iec61850_Associate = -1;
static int hf_iec61850_GetLogicalNodeDirectory = -1;
static int hf_iec61850_GetDataValue = -1;
static int hf_iec61850_SetDataValue = -1;
static int hf_iec61850_GetDataDirectory = -1;
static int hf_iec61850_GetDataSetDirectory = -1;
static int hf_iec61850_CreateDataSet = -1;
static int hf_iec61850_DeleteDataSet = -1;
static int hf_iec61850_QueryLog = -1;
static int hf_iec61850_SetFile = -1;
static int hf_iec61850_GetFile = -1;
static int hf_iec61850_FileRead = -1;
static int hf_iec61850_FileClose = -1;
static int hf_iec61850_DeleteFile = -1;
static int hf_iec61850_GetServerDirectory_FILE = -1;
static int hf_iec61850_null = -1;

static gint ett_iec61850 = -1;

static expert_field ei_iec61850_mal_timeofday_encoding = EI_INIT;
static expert_field ei_iec61850_mal_utctime_encoding = EI_INIT;
static expert_field ei_iec61850_zero_pdu = EI_INIT;

int Unconfirmed_RPT(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx);
int CommandTerm(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx);
int Associate(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int GetLogicalNodeDirectory(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int GetDataDirectory(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int GetDataValue(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int SetDataValue(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int GetDataSetDirectory(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int CreateDataSet(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int DeleteDataSet(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int QueryLog(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int SetFile(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int GetFile(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int FileRead(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int FileClose(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int DeleteFile(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);
int GetServerDirectory_FILE(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res);

void register_iec61850_mappings(const int parent)
{
    static hf_register_info hf[] = {
		{ 
			&hf_iec61850_Unconfirmed,
      		{ 
				"Unconfirmed", 			// name
				"iec61850.Unconfirmed",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Associate,
      		{ 
				"Associate", 			// name
				"iec61850.Associate",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetLogicalNodeDirectory,
      		{ 
				"GetLogicalNodeDirectory", 			// name
				"iec61850.GetLogicalNodeDirectory",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetDataValue,
      		{ 
				"GetDataValue", 			// name
				"iec61850.GetDataValue",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SetDataValue,
      		{ 
				"SetDataValue", 			// name
				"iec61850.SetDataValue",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetDataDirectory,
      		{ 
				"GetDataDirectory", 			// name
				"iec61850.GetDataDirectory",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetDataSetDirectory,
      		{ 
				"GetDataSetDirectory", 			// name
				"iec61850.GetDataSetDirectory",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_CreateDataSet,
      		{ 
				"CreateDataSet", 			// name
				"iec61850.CreateDataSet",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_DeleteDataSet,
      		{ 
				"DeleteDataSet", 			// name
				"iec61850.DeleteDataSet",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_QueryLog,
      		{ 
				"QueryLog", 			// name
				"iec61850.QueryLog",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SetFile,
      		{ 
				"SetFile", 			// name
				"iec61850.SetFile",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetFile,
      		{ 
				"GetFile", 			// name
				"iec61850.GetFile",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_FileRead,
      		{ 
				"FileRead", 			// name
				"iec61850.FileRead",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_FileClose,
      		{ 
				"FileClose", 			// name
				"iec61850.FileClose",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_DeleteFile,
      		{ 
				"DeleteFile", 			// name
				"iec61850.DeleteFile",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetServerDirectory_FILE,
      		{ 
				"GetServerDirectory_FILE", 			// name
				"iec61850.GetServerDirectory_FILE",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_null,
      		{ 
				"UNKNOWN", 			// name
				"iec61850.Unknown",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		}
    };

	/* List of subtrees */
	static gint *ett_61850[] = {
		&ett_iec61850,
	};

	static ei_register_info ei_61850[] = {
		{ &ei_iec61850_mal_timeofday_encoding, { "iec61850.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
		{ &ei_iec61850_mal_utctime_encoding, { "iec61850.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
		{ &ei_iec61850_zero_pdu, { "iec61850.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte iec61850 PDU", EXPFILL }},
	};

	expert_module_t* expert_iec61850;

    proto_register_field_array(parent, hf, array_length(hf));

	proto_register_subtree_array(ett_61850, array_length(ett_61850));
	expert_iec61850 = expert_register_protocol(parent);
	expert_register_field_array(expert_iec61850, ei_61850, array_length(ei_61850));

}

void proto_tree_print_node(proto_node *node, gpointer data)
{
	int * level = (int *)data;
	field_info   *fi    = PNODE_FINFO(node);
    gchar         label_str[ITEM_LABEL_LENGTH];
    gchar        *label_ptr;

    g_assert(fi);
	if(fi != NULL && fi->hfinfo != NULL && fi->hfinfo->name != NULL && fi->hfinfo->type == FT_STRING){
		ws_message("l: %d [%s] %s", *level, fi->hfinfo->name, fi->value.value.string);
	}
    
	if (node->first_child != NULL) {
		*level = *level + 1;
		if(*level < 100){
			proto_tree_children_foreach(node, proto_tree_print_node, data);
		}
		*level = *level - 1;	
	}
}

static proto_item *get_iec61850_item(tvbuff_t *tvb, proto_tree *parent_tree, const int proto_iec61850)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_iec61850, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_iec61850);
	}
	return item;
}

int map_iec61850_packet(tvbuff_t *tvb, packet_info *pinfo, asn1_ctx_t *actx, proto_tree *parent_tree, proto_tree *mms_tree, const int proto_iec61850)
{
	int offset = 0;
	int old_offset;
	int level = 1;
	int decoded = 0;
    
	/*if(mms_tree != NULL)
	{
		proto_tree_children_foreach(mms_tree, proto_tree_print_node, &level);
	}*/

	if(tvb_reported_length_remaining(tvb, offset) > 0) //while for multiple PDU in 1 packet (may be possible...)
	{
		proto_item *item;
		old_offset=offset;
		
		iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
		switch(private_data->MMSpdu)
		{
			case 0://confirmed-req
			case 1://confirmed-res
			{
				switch(private_data->Service)
				{
					case 1://GetNameList -> GetLogicalNodeDirectory, GetLogicalDeviceDirectory, GetServerDirectory
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetLogicalNodeDirectory(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 4://read -> GetDataSet
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetDataValue(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 5://write -> SetDataSet
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = SetDataValue(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 6: //GetVariableAccessAttributes -> GetDataDirectory, GetDataDefinition
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetDataDirectory(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 11://	CreateDataSet			DefineNamedVariableList
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = CreateDataSet(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 12:// getNamedVariableListAttributes -> GetDataSetDirectory, 
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetDataSetDirectory(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 13://		DeleteDataSet			DeleteNamedVariableList
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = CreateDataSet(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 65:// ReadJournal -> QueryLogByTime, QueryLogAfter
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = QueryLog(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 46://SetFile						46 ObtainFile
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = SetFile(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 72://GetFile						72 fileOpen, 
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetFile(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 73://73 FileRead, 
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = FileRead(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 74://74 FileClose
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = FileClose(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 76://DeleteFile					76 FileDelete
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = DeleteFile(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					case 77://	GetFileAttributeValues	GetServerDirectory(FILE)	77 FileDirectory
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetServerDirectory_FILE(tvb, offset, item, actx, private_data->MMSpdu);
						break;
					default:
						ws_warning("Not an IEC61850 confirmed service: %i", private_data->Service);
						//to_tree_add_item(item, hf_iec61850_null, tvb, offset, -1, ENC_NA);
						//proto_tree_add_expert(tree, pinfo, &ei_iec61850_zero_pdu, tvb, offset, -1);
				}
				break;
			}
			case 2://confirmed-ErrorPDU
			{
				break;
			}
			case 3://unconfirmed PDU
			{
				if(private_data->Service == 0)
				{
					if(private_data->VariableAccessSpecification == 0)
					{
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = CommandTerm(tvb, offset, item, actx);
					}
					else if(private_data->VariableAccessSpecification == 1)
					{
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = Unconfirmed_RPT(tvb, offset, item, actx);
					}
					else
					{
						ws_warning("Not an IEC61850 unconfirmed VariableAccessSpecification: %i", private_data->Service);
						proto_tree_children_foreach(mms_tree, proto_tree_print_node, &level);
					}
				}
				else
				{
					ws_warning("Not an IEC61850 unconfirmed service: %i", private_data->Service);
					proto_tree_children_foreach(mms_tree, proto_tree_print_node, &level);
				}
				break;
			}
			case 4://rejectPDU
			{
				break;
			}
			case 5://cancel-req
			case 6://cancel-res
			{
				break;
			}
			case 7://cancel-Error
			{
				break;
			}
			case 8://Associate - initiate req
			case 9://Associate - initiate res
			{ 
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Associate(tvb, offset, item, actx, private_data->MMSpdu-8);
				break;
			}
			case 10: //	initiate-ErrorPDU		[10] 	IMPLICIT Initiate-ErrorPDU,
			{
				break;
			}
			case 11://Release-req conclude
			case 12://Release-res conclude
			{
				break;
			}
			case 13://Release-Error
			{
				break;
			}
			default:
				ws_error("Not an IEC61850 PDU: %i", private_data->MMSpdu);
				//proto_tree_add_item(item, hf_iec61850_null, tvb, offset, -1, ENC_NA);
				//proto_tree_add_expert(tree, pinfo, &ei_iec61850_zero_pdu, tvb, offset, -1);
		}
		//if(offset == old_offset)????ERROR??
	}
    return decoded;
}

int Unconfirmed_RPT(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx)
{// Report,
//Report: The variableListName ObjectName shall contain the VMD-SPECIFIC value “RPT”
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Unconfirmed, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s", "Unconfirmed-RPT", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int CommandTerm(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx)
{// CommandTermination
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Unconfirmed, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s", "Unconfirmed-CommandTermination", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int Associate(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Associate, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s %s", "Associate", res? "res" : "req" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int GetLogicalNodeDirectory(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{//GetLogicalNodeDirectory, GetLogicalDeviceDirectory, GetServerDirectory
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetLogicalNodeDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetLogicalNodeDirectory", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int GetDataDirectory(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{//GetDataDefinition
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetDataDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetDataDirectory", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int GetDataValue(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{//GetAllDataValues, ,GetDataSetValues,GetEditSGValue,GetSGCBValues,
//GetBRCBValues,GetURCBValues,GetLCBValues,GetLogStatusValues,GetGoCBValues
//GetGsCBValues, 
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetDataValue, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetDataValue", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int SetDataValue(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{//SetDataSetValues,SelectActiveSG,SelectEditSG,SetEditSGValue,ConfirmEditSGValues
//SetBRCBValues,SetURCBValues,SetLCBValues,SetGoCBValues,SetGsCBValues
//Select, SelectWithValue, Cancel,Operate,TimeActivatedOperate
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_SetDataValue, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "SetDataValue", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int GetDataSetDirectory(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetDataSetDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetDataSetDirectory", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int CreateDataSet(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_CreateDataSet, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "CreateDataSet", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int DeleteDataSet(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_DeleteDataSet, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "DeleteDataSet", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int QueryLog(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_QueryLog, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "QueryLog", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int SetFile(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_SetFile, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "SetFile", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int GetFile(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetFile, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetFile", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int FileRead(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_FileRead, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "FileRead", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int FileClose(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_FileClose, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "FileClose", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int DeleteFile(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_DeleteFile, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "DeleteFile", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int GetServerDirectory_FILE(tvbuff_t *tvb, int offset, proto_item *item, asn1_ctx_t *actx, int res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetServerDirectory_FILE, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetServerDirectory(FILE)", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}