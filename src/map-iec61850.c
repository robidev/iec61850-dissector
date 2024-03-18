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
#include <epan/conversation.h>
#include <epan/proto.h>

#include <epan/dissectors/packet-ber.h>

#include "map-iec61850.h"
#include "packet-iec61850.h"

#include <wsutil/wslog.h>

struct _iec61850_key_req {
	u_int32_t conversation;
	u_int32_t invokeID;
} typedef iec61850_key_req;

struct _iec61850_value_req {
	u_int8_t * serviceName;
	int32_t hf_name;
	void * data;
} typedef iec61850_value_req;

struct _tree_data {
	u_int32_t level;
	proto_tree *tree;
	tvbuff_t *tvb;
	u_int32_t offset;
	asn1_ctx_t *actx;
	u_int8_t * request;
} typedef tree_data;

static wmem_map_t *iec61850_request_hash = NULL;
static proto_tree * g_mms_tree = NULL;

static int32_t hf_iec61850_Unconfirmed = -1;
static int32_t hf_iec61850_Error = -1;
static int32_t hf_iec61850_Reject = -1;
static int32_t hf_iec61850_Associate = -1;
static int32_t hf_iec61850_Cancel = -1;
static int32_t hf_iec61850_Release = -1;
static int32_t hf_iec61850_Associate_Error = -1;
static int32_t hf_iec61850_Cancel_Error = -1;
static int32_t hf_iec61850_Release_Error = -1;
static int32_t hf_iec61850_GetServerDirectory = -1;
static int32_t hf_iec61850_GetLogicalDeviceDirectory = -1;
static int32_t hf_iec61850_GetLogicalNodeDirectory = -1;
static int32_t hf_iec61850_GetJournalDirectory = -1;
static int32_t hf_iec61850_GetNameList_response = -1;
static int32_t hf_iec61850_GetDataValue = -1;
static int32_t hf_iec61850_SetDataValue = -1;

static int32_t hf_iec61850_GetRCBValues = -1;
static int32_t hf_iec61850_GetGCBValues = -1;
static int32_t hf_iec61850_GetSGCBValues = -1;
static int32_t hf_iec61850_GetLCBValues = -1;
static int32_t hf_iec61850_Select = -1;
static int32_t hf_iec61850_GetAllDataValues = -1;
static int32_t hf_iec61850_GetDataSetValues = -1;
static int32_t hf_iec61850_SetRCBValues = -1;
static int32_t hf_iec61850_SetGCBValues = -1;
static int32_t hf_iec61850_SetSGCBValues = -1;
static int32_t hf_iec61850_SetLCBValues = -1;
static int32_t hf_iec61850_SetDataSetValues = -1;
static int32_t hf_iec61850_SelectWithValue = -1;
static int32_t hf_iec61850_OperCancel = -1;
static int32_t hf_iec61850_Operate = -1;

static int32_t hf_iec61850_GetDataDirectory = -1;
static int32_t hf_iec61850_GetDataSetDirectory = -1;
static int32_t hf_iec61850_CreateDataSet = -1;
static int32_t hf_iec61850_DeleteDataSet = -1;
static int32_t hf_iec61850_QueryLog = -1;
static int32_t hf_iec61850_SetFile = -1;
static int32_t hf_iec61850_GetFile = -1;
static int32_t hf_iec61850_OpenFile = -1;
static int32_t hf_iec61850_FileRead = -1;
static int32_t hf_iec61850_FileClose = -1;
static int32_t hf_iec61850_DeleteFile = -1;
static int32_t hf_iec61850_GetServerDirectory_FILE = -1;
static int32_t hf_iec61850_null = -1;

static int32_t hf_iec61850_QualityC0 = -1;
static int32_t hf_iec61850_Quality20 = -1;
static int32_t hf_iec61850_Quality10 = -1;
static int32_t hf_iec61850_Quality8 = -1;
static int32_t hf_iec61850_Quality4 = -1;
static int32_t hf_iec61850_Quality2 = -1;
static int32_t hf_iec61850_Quality1 = -1;
static int32_t hf_iec61850_Quality0080 = -1;
static int32_t hf_iec61850_Quality0040 = -1;
static int32_t hf_iec61850_Quality0020 = -1;
static int32_t hf_iec61850_Quality0010 = -1;
static int32_t hf_iec61850_Quality0008 = -1;
static int32_t hf_iec61850_timequality80 = -1;
static int32_t hf_iec61850_timequality40 = -1;
static int32_t hf_iec61850_timequality20 = -1;
static int32_t hf_iec61850_timequality1F = -1;
static int32_t hf_iec61850_Check2 = -1;
static int32_t hf_iec61850_Check1 = -1;
static int32_t hf_iec61850_ReasonCode80 = -1;
static int32_t hf_iec61850_ReasonCode40 = -1;
static int32_t hf_iec61850_ReasonCode20 = -1;
static int32_t hf_iec61850_ReasonCode10 = -1;
static int32_t hf_iec61850_ReasonCode8 = -1;
static int32_t hf_iec61850_ReasonCode4 = -1;
static int32_t hf_iec61850_ReasonCode2 = -1;
static int32_t hf_iec61850_OptFlds80 = -1;
static int32_t hf_iec61850_OptFlds40 = -1;
static int32_t hf_iec61850_OptFlds20 = -1;
static int32_t hf_iec61850_OptFlds10 = -1;
static int32_t hf_iec61850_OptFlds8 = -1;
static int32_t hf_iec61850_OptFlds4 = -1;
static int32_t hf_iec61850_OptFlds2 = -1;
static int32_t hf_iec61850_OptFlds1 = -1;
static int32_t hf_iec61850_OptFlds0080 = -1;
static int32_t hf_iec61850_OptFlds0040 = -1;
static int32_t hf_iec61850_DBPosC = -1;
static int32_t hf_iec61850_BinaryStepC = -1;
static int32_t hf_iec61850_ctlModel = -1;
static int32_t hf_iec61850_orCat = -1;
static int32_t hf_iec61850_Mod = -1;
static int32_t hf_iec61850_Beh = -1;
static int32_t hf_iec61850_Health = -1;
static int32_t hf_iec61850_dir = -1;

static int32_t ett_iec61850 = -1;

static expert_field ei_iec61850_mal_timeofday_encoding = EI_INIT;
static expert_field ei_iec61850_mal_utctime_encoding = EI_INIT;
static expert_field ei_iec61850_zero_pdu = EI_INIT;
static expert_field ei_iec61850_failed_resp = EI_INIT;

static int32_t iec61850_equal(gconstpointer v, gconstpointer w);
static u_int32_t iec61850_hash (gconstpointer v);
static proto_item *get_iec61850_item(tvbuff_t *tvb, proto_tree *parent_tree, const int32_t proto_iec61850);
static void store_invoke_data(packet_info *pinfo, u_int32_t invokeID, iec61850_value_req * data);
static iec61850_value_req *load_invoke_data(packet_info *pinfo, u_int32_t invokeID);
static void free_invoke_data(packet_info *pinfo, u_int32_t invokeID);

int32_t Unconfirmed_RPT(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t CommandTerm(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);

int32_t Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t Reject(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t Associate(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t Cancel(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t Release(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t Associate_Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t Cancel_Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t Release_Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
//confirmed PDU
int32_t GetServerDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t GetLogicalDeviceDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t GetLogicalNodeDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t GetJournalDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx);
int32_t GetNameList_response(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, iec61850_value_req *val);
int32_t GetDataDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t GetDataValue(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res, iec61850_value_req * val);
int32_t SetDataValue(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res, iec61850_value_req * val);
int32_t GetDataSetDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t CreateDataSet(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t DeleteDataSet(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t QueryLog(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t SetFile(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t GetFile(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t FileRead(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t FileClose(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t DeleteFile(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);
int32_t GetServerDirectory_FILE(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res);

static hf_register_info * g_mms_hf;

static const value_string enum_Validity[] = {
    {0, "Good"},
    {1, "Invalid"},
    {2, "Reserved"},
    {3, "Questionable"},
    {0, NULL}
};

static const value_string enum_Source[] = {
    {0, "Process"},
    {1, "Substituted"},
    {0, NULL}
};

static const value_string enum_Health[] = {
	{0,"Uninitialised"},
	{1,"Ok"},
	{2,"Warning"},
	{3,"Alarm"},
	{0, NULL}
};

static const value_string enum_orCategory[] = {
	{0, "not-supported"},
	{1, "bay-control"},
	{2, "station-control"},
	{3, "remote-control"},
	{4, "automatic-bay"},
	{5, "automatic-station"},
	{6, "automatic-remote"},
	{7, "maintenance"},
	{8, "process"},
	{0, NULL}
};

static const value_string enum_Beh_Mod[] = {
	{0,"Uninitialised"},
	{1, "on"},
	{2, "blocked"},
	{3, "test"},
	{4, "test/blocked"},
	{5, "off"},
	{0, NULL}
};

static const value_string enum_ctlModel[] = {
	{0, "status-only"},
	{1, "direct-with-normal-security"},
	{2, "sbo-with-normal-security"},
	{3, "direct-with-enhanced-security"},
	{4, "sbo-with-enhanced-security"},
	{0, NULL}
};

static const value_string enum_operate_Error[] = {
	{0, "No Error"},
	{1, "Unknown"},
	{2, "Timeout Test Not OK"},
	{3, "Operator Test Not OK"},
	{0, NULL}
};

static const value_string enum_AddCause[] = {
	{0, "Unknown"},
	{1, "Not-supported"},
	{2, "Blocked-by-switching-hierarchy"},
	{3, "Select-failed"},
	{4, "Invalid-position"},
	{5, "Position-reached"},
	{6, "Parameter-change-in-execution"},
	{7, "Step-limit"},
	{8, "Blocked-by-Mode"},
	{9, "Blocked-by-process"},
	{10, "Blocked-by-interlocking"},
	{11, "Blocked-by-synchrocheck"},
	{12, "Command-already-in-execution"},
	{13, "Blocked-by-health"},
	{14, "1-of-n-control"},
	{15, "Abortion-by-cancel"},
	{16, "Time-limit-over"},
	{17, "Abortion-by-trip"},
	{18, "Object-not-selected"},
	{19, "Object-already-selected"},
	{20, "No-access-authority"},
	{21, "Ended-with-overshoot"},
	{22, "Abortion-due-to-deviation"},
	{23, "Abortion-by-communication-loss"},
	{24, "Blocked-by-command"},
	{25, "None"},
	{26, "Inconsistent-parameters"},
	{27, "Locked-by-other-client"},
	{0, NULL}
};

static const value_string enum_TimeAccuracy[] = {
	{0,  "0 bits accuracy"},
	{1,  "1 bits accuracy"},
	{2,  "2 bits accuracy"},
	{3,  "3 bits accuracy"},
	{4,  "4 bits accuracy"},
	{5,  "5 bits accuracy"},
	{6,  "6 bits accuracy"},
	{7,  "7 bits accuracy"},
	{8,  "8 bits accuracy"},
	{9,  "9 bits accuracy"},
	{10, "10 bits accuracy"},
	{11, "11 bits accuracy"},
	{12, "12 bits accuracy"},
	{13, "13 bits accuracy"},
	{14, "14 bits accuracy"},
	{15, "15 bits accuracy"},
	{16, "16 bits accuracy"},
	{17, "17 bits accuracy"},
	{18, "18 bits accuracy"},
	{19, "19 bits accuracy"},
	{20, "20 bits accuracy"},
	{21, "21 bits accuracy"},
	{22, "22 bits accuracy"},
	{23, "23 bits accuracy"},
	{24, "24 bits accuracy"},
	{25, "25 bits accuracy"},
	{26, "26 bits accuracy"},
	{27, "27 bits accuracy"},
	{28, "28 bits accuracy"},
	{29, "29 bits accuracy"},
	{30, "Invalid"},
	{31, "Unspecified"},
	{0, NULL}
};

static const value_string enum_ServiceType[] = {
	{0, "Unknown"},
	{1, "Associate"},
	{2, "Abort"},
	{3, "Release"},
	{4, "GetServerDirectory"},
	{5, "GetLogicalDeviceDirectory"},
	{6, "GetAllDataVaues"},
	{7, "GetDataValues"},
	{8, "SetDataValues"},
	{9, "GetDataDirectory"},
	{10, "GetDataDefinition"},
	{11, "GetDataSetValues"},
	{12, "SetDataSetValues"},
	{13, "CreateDataSet"},
	{14, "DeleteDataSet"},
	{15, "GetDataSetDirectory"},
	{16, "SelectActiveSG"},
	{17, "SelectEditSG"},
	{18, "SetEditSGValue"},
	{19, "ConfirmEditSGValues"},
	{20, "GetEditSGValue"},
	{21, "GetSGCBValues"},
	{22, "Report"},
	{23, "GetBRCBValues"},
	{24, "SetBRCBValues"},
	{25, "GetURCBValues"},
	{26, "SetURCBValues"},
	{27, "GetLCBValues"},
	{28, "SetLCBValues"},
	{29, "QueryLogByTime"},
	{30, "QueryLogAfter"},
	{31, "GetLogStatusValues"},
	{32, "SendGOOSEMessage"},
	{33, "GetGoCBValues"},
	{34, "SetGoCBValues"},
	{35, "GetGoReference"},
	{36, "GetGOOSEElementNumber"},
	{37, "SendMSVMessage"},
	{38, "GetMSVCBValues"},
	{39, "SetMSVCBValues"},
	{40, "SendUSVMessage"},
	{41, "GetUSVCBValues"},
	{42, "SetUSVCBValues"},
	{43, "Select"},
	{44, "SelectWithValue"},
	{45, "Cancel"},
	{46, "Operate"},
	{47, "CommandTermination"},
	{48, "TimeActivatedOperate"},
	{49, "GetFile"},
	{50, "SetFile"},
	{51, "DeleteFile"},
	{52, "GetFileAttributeValues"},
	{53, "TimeSynchronization"},
	{54, "InternalChangeUnknown"},
	{0, NULL}
};

static const value_string enum_ServiceError[] = {
	{0, "no-error"},
	{1, "instance-not-available"},
	{2, "instance-in-use"},
	{3, "access-violation"},
	{4, "access-not-allowed-in-current-state"},
	{5, "parameter-value-inappropriate"},
	{6, "parameter-value-inconsistent"},
	{7, "class-not-supported"},
	{8, "instance-locked-by-other-client"},
	{9, "control-must-be-selected"},
	{10, "type-conflict"},
	{11, "failed-due-to-communications-constraint"},
	{12, "failed-due-to-server-constraint"},
	{0, NULL}
};

static const value_string enum_DBPos[] = {
	{0, "intermediate-state"},
	{1, "off"},
	{2, "on"},
	{3, "bad-state"},
	{0, NULL}
};

static const value_string enum_BinaryStep[] = {
	{0, "stop"},
	{1, "lower"},
	{2, "higher"},
	{3, "reserved"},
	{0, NULL}
};

static const value_string enum_dir[] = {
	{0, "unknown"},
	{1, "forward"},
	{2, "backward"},
	{3, "both"},
	{0, NULL}
};

static int32_t * const Quality_bits[] = {
	&hf_iec61850_QualityC0,
	&hf_iec61850_Quality20,
	&hf_iec61850_Quality10,
	&hf_iec61850_Quality8,
	&hf_iec61850_Quality4,
	&hf_iec61850_Quality2,
	&hf_iec61850_Quality1,
	NULL,
	&hf_iec61850_Quality0080,
	&hf_iec61850_Quality0040,
	&hf_iec61850_Quality0020,
	&hf_iec61850_Quality0010,
	&hf_iec61850_Quality0008,
  	NULL
};

static int32_t * const TimeQuality_bits[] = {
	&hf_iec61850_timequality80,
	&hf_iec61850_timequality40,
	&hf_iec61850_timequality20,
	&hf_iec61850_timequality1F,
	NULL
};

static int32_t * const Check_bits[] = {
	&hf_iec61850_Check2,
	&hf_iec61850_Check1,
	NULL
};

static int32_t * const DBPos_bits[] = {
	&hf_iec61850_DBPosC,
	NULL
};

static int32_t * const BinaryStep_bits[] = {
	&hf_iec61850_BinaryStepC,
	NULL
};

void proto_tree_print_tree(proto_node *node, gpointer data)
{
	proto_tree *tree;
	tvbuff_t *tvb;
	proto_item *item = NULL;
	int32_t offset = 0;
	field_info *fi = PNODE_FINFO(node);
	tree_data * pdata = (tree_data *)data;
	g_assert(pdata);
    g_assert(fi);

	tree = pdata->tree;
	tvb = pdata->tvb;

	offset =  fi->start - pdata->offset;

	if(fi != NULL && fi->hfinfo != NULL)
	{
		if(fi->hfinfo->name != NULL)
		{
			//set expert info to display failed requests
			if(g_str_equal(fi->hfinfo->name, "failure"))
			{
				proto_tree_add_expert_format(tree, pdata->actx->pinfo, &ei_iec61850_failed_resp,tvb, offset, -1, 
					"Failed to perform operation on %s", pdata->request );
			}

			switch(fi->hfinfo->type)
			{
				case FT_NONE:
					//ws_message("%*s%s", pdata->level," ", fi->hfinfo->name); 
					//filter out some entries that are redundant
					if(g_str_equal(fi->hfinfo->name, "confirmed-RequestPDU") || 
						g_str_equal(fi->hfinfo->name, "confirmed-ResponsePDU") ||
						g_str_equal(fi->hfinfo->name, "initiate-RequestPDU") ||
						g_str_equal(fi->hfinfo->name, "initiate-ResponsePDU") ||
						g_str_equal(fi->hfinfo->name, "structure") ||
						g_str_equal(fi->hfinfo->name, "read") ||
						g_str_equal(fi->hfinfo->name, "write") 
						)
					{
						break;
					}
					item = proto_tree_add_item(tree, fi->hfinfo->id,tvb, offset, fi->length,  0); 
					break;
				case FT_BOOLEAN:
					//ws_message("%*s%s: %s", pdata->level," ", fi->hfinfo->name, fi->value.value.uinteger? "true" : "false");
					u_int32_t boolean = 0;
					u_int32_t bitmask = 1;
					if(fi->hfinfo->bitmask)// if a bitmask exists, use that value
						bitmask = fi->hfinfo->bitmask;
					if(fi->value.value.uinteger) //if value is non-zero, set bool to bitmask
						boolean = bitmask;

					item = proto_tree_add_boolean(tree, fi->hfinfo->id, tvb, offset, fi->length, boolean ); 
					break;
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT32:
					//TODO, for invokeID, add it to the parent line
					//ws_message("%*s%s: %d", pdata->level," ", fi->hfinfo->name, fi->value.value.uinteger); 
					if(!g_str_equal(fi->hfinfo->name, "Padding"))
					{
						item = proto_tree_add_uint(tree, fi->hfinfo->id,tvb, offset, fi->length,  fi->value.value.uinteger); 
					}
					break;
				case FT_CHAR:
				case FT_INT8:
				case FT_INT16:
				case FT_INT32:
					if(g_str_equal(fi->hfinfo->name, "integer"))
					{
						if(g_str_has_suffix(pdata->request,"$ctlModel"))
						{
							dissect_ber_integer(1, pdata->actx, tree, tvb, offset, hf_iec61850_ctlModel, NULL);
							break;
						}
						if(g_str_has_suffix(pdata->request,"$orCat"))
						{
							dissect_ber_integer(1, pdata->actx, tree, tvb, offset, hf_iec61850_orCat, NULL);
							break;						
						}
						if(g_str_has_suffix(pdata->request,"Beh$stVal"))
						{
							dissect_ber_integer(1, pdata->actx, tree, tvb, offset, hf_iec61850_Beh, NULL);
							break;						
						}
						if(g_str_has_suffix(pdata->request,"Mod$stVal"))
						{
							dissect_ber_integer(1, pdata->actx, tree, tvb, offset, hf_iec61850_Mod, NULL);
							break;						
						}
						if(g_str_has_suffix(pdata->request,"Health$stVal"))
						{
							dissect_ber_integer(1, pdata->actx, tree, tvb, offset, hf_iec61850_Health, NULL);
							break;						
						}
						if( g_str_has_suffix(pdata->request,"$dirGeneral") || 
							g_str_has_suffix(pdata->request,"$dirPhsA") || 
							g_str_has_suffix(pdata->request,"$dirPhsB") ||
							g_str_has_suffix(pdata->request,"$dirPhsC") ||
							g_str_has_suffix(pdata->request,"$dirNeut"))
						{
							dissect_ber_integer(1, pdata->actx, tree, tvb, offset, hf_iec61850_dir, NULL);
							break;						
						}
						//dir
					}
					//ws_message("%*s%s: %i", pdata->level," ", fi->hfinfo->name, fi->value.value.sinteger);
					item = proto_tree_add_int(tree, fi->hfinfo->id,tvb, offset, fi->length,  fi->value.value.sinteger); 
					break;
				case FT_STRING:
					//ws_message("%*s%s: %s", pdata->level," ", fi->hfinfo->name, fi->value.value.string); 
					item = proto_tree_add_string(tree, fi->hfinfo->id,tvb, offset, fi->length,  fi->value.value.string);
					if(g_str_equal(fi->hfinfo->name, "utc-time"))
					{
						proto_tree_add_bitmask_list(tree, tvb, offset+7, 1, TimeQuality_bits, ENC_BIG_ENDIAN);						
					}
					break;
				case FT_BYTES:
				{
					/*wmem_strbuf_t *strbuf;
					strbuf = wmem_strbuf_new(wmem_packet_scope(), "");
					int32_t i;
					for (i = 0; i < fi->value.value.bytes->len; i++){
						wmem_strbuf_append_printf(strbuf, "%02x", fi->value.value.bytes->data[i]);
					}
					ws_message("%*s%s: (%i) %s", pdata->level," ", fi->hfinfo->name, fi->value.value.bytes->len, wmem_strbuf_get_str(strbuf)); 
					*/
					if(g_str_equal(fi->hfinfo->name, "bit-string"))
					{
						if(g_str_has_suffix(pdata->request,"$q"))
						{
							dissect_ber_bitstring(1, pdata->actx, tree, tvb, offset-1, Quality_bits, (fi->length * 8), fi->hfinfo->id, ett_iec61850, NULL);
							break;
						}
						if(g_str_has_suffix(pdata->request,"$Oper$Check") || g_str_has_suffix(pdata->request,"$SBOw$Check"))
						{
							dissect_ber_bitstring(1, pdata->actx, tree, tvb, offset-1, Check_bits, (fi->length * 8), fi->hfinfo->id, ett_iec61850, NULL);
							break;
						}
						if(g_str_has_suffix(pdata->request,"$stVal") || g_str_has_suffix(pdata->request,"$subVal"))
						{
							dissect_ber_bitstring(1, pdata->actx, tree, tvb, offset-1, DBPos_bits, (fi->length * 8), fi->hfinfo->id, ett_iec61850, NULL);
							break;
						}							
						if(g_str_has_suffix(pdata->request,"$ctlVal"))
						{
							dissect_ber_bitstring(1, pdata->actx, tree, tvb, offset-1, BinaryStep_bits, (fi->length * 8), fi->hfinfo->id, ett_iec61850, NULL);
							break;
						}
					}
					if(g_str_equal(fi->hfinfo->name, "floating-point"))
					{
						//snprintf(tmp, BUFFER_SIZE_MORE, "%f", );
						proto_tree_add_bytes_format_value(tree, fi->hfinfo->id,tvb, offset, fi->value.value.bytes->len, fi->value.value.bytes->data, "%f",tvb_get_ieee_float(tvb, 1, ENC_BIG_ENDIAN) );
						break;
					}

					proto_tree_add_bytes(tree, fi->hfinfo->id,tvb, offset, fi->value.value.bytes->len, fi->value.value.bytes->data);//,"%s",wmem_strbuf_get_str(strbuf));
					break;
				}
				default:
					ws_warning("%d, type: %d (UNKNOWN)", pdata->level, fi->hfinfo->type); break;
			}
		}
		else
		{
			ws_warning("l: %i, type: %d", pdata->level, fi->hfinfo->type);
		}
	}
    
	if (node->first_child != NULL ) {
		pdata->level++;
		if(pdata->level < 100){
			if(item != NULL)
			{
				proto_tree *subtree = proto_item_add_subtree(item, ett_iec61850);
				pdata->tree = subtree;
			}
			proto_tree_children_foreach(node, proto_tree_print_tree, data);
			pdata->tree = tree;
		}
		pdata->level--;	
	}
}

int32_t map_iec61850_packet(tvbuff_t *tvb, packet_info *pinfo, asn1_ctx_t *actx, proto_tree *parent_tree, proto_tree *mms_tree, const int32_t proto_iec61850)
{
	u_int32_t offset = 0;
	u_int32_t old_offset;
	int32_t level = 1;
	u_int32_t decoded = 0;
	iec61850_value_req sessiondata;
	iec61850_value_req * sessiondata_request = &sessiondata;
	g_mms_tree = mms_tree;

	if(tvb_reported_length_remaining(tvb, offset) > 0) //while for multiple PDU in 1 packet (may be possible...)
	{
		proto_item *item;
		old_offset=offset;
		
		iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
		g_assert(private_data);

		if(private_data->MMSpdu == 1)//load request data for response
		{
			sessiondata_request = load_invoke_data(pinfo, private_data->invokeID);
		}

		switch(private_data->MMSpdu)
		{
			case 0://confirmed-req
				sessiondata.data = wmem_strbuf_new(wmem_file_scope(),private_data->moreCinfo);
				g_strstrip((gchar *)wmem_strbuf_get_str(sessiondata.data));
			case 1://confirmed-res
			{
				switch(private_data->Service)
				{
					case 1://GetNameList -> GetLogicalNodeDirectory, GetLogicalDeviceDirectory, GetServerDirectory
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						if(private_data->MMSpdu == 0) // request
						{
							if(private_data->objectScope == 0)//VMD-SPECIFIC
							{
								decoded = GetServerDirectory(tvb, offset, item, actx);
								sessiondata_request->serviceName = "GetServerDirectory";
								sessiondata_request->hf_name = hf_iec61850_GetServerDirectory;
							}
							else if(private_data->objectScope == 1)//domainspecific
							{
								if(private_data->objectClass == 0)
								{
									u_int8_t * request = (u_int8_t *)wmem_strbuf_get_str(sessiondata_request->data);
									if(g_strrstr(request,"/") == NULL || g_str_has_suffix(request, "/"))// if the whole device is requested it is a GetLogicalDeviceDirectory
									{
										decoded = GetLogicalDeviceDirectory(tvb, offset, item, actx);
										sessiondata_request->serviceName = "GetLogicalDeviceDirectory";
										sessiondata_request->hf_name = hf_iec61850_GetLogicalDeviceDirectory;
									}
									if(g_strrstr(request,"/") && !g_str_has_suffix(request, "/"))// if a specific logical node is requested, it is a GetLogicalNodeDirecotry
									{
										decoded = GetLogicalNodeDirectory(tvb, offset, item, actx);
										sessiondata_request->serviceName = "GetLogicalNodeDirectory";
										sessiondata_request->hf_name = hf_iec61850_GetLogicalNodeDirectory;										
									}
								}
								if(private_data->objectClass == 2)
								{
									decoded = GetDataSetDirectory(tvb, offset, item, actx, 0);
									sessiondata_request->serviceName = "GetDataSetDirectory";
									sessiondata_request->hf_name = hf_iec61850_GetDataSetDirectory;
								}
								if(private_data->objectClass == 8)
								{
									decoded = GetJournalDirectory(tvb, offset, item, actx);
									sessiondata_request->serviceName = "GetJournalDirectory";
									sessiondata_request->hf_name = hf_iec61850_GetJournalDirectory;
								}
							}
							else // aa-specific
							{
								decoded = GetLogicalDeviceDirectory(tvb, offset, item, actx);
								sessiondata_request->serviceName = "GetLogicalDeviceDirectory";
								sessiondata_request->hf_name = hf_iec61850_GetLogicalDeviceDirectory;
							}
						}
						else // response
						{
							decoded = GetNameList_response(tvb, offset, item, actx, sessiondata_request);
						}
						break;
					case 4://read -> GetDataValue
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetDataValue(tvb, offset, item, actx, private_data->MMSpdu, sessiondata_request);
						break;
					case 5://write -> SetDataValue
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = SetDataValue(tvb, offset, item, actx, private_data->MMSpdu, sessiondata_request);
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
					case 47://GetFile response
						item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
						decoded = GetFile(tvb, offset, item, actx, private_data->MMSpdu);
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
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Error(tvb, offset, item, actx);
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
						//proto_tree_children_foreach(mms_tree, proto_tree_print_node, &level);
					}
				}
				else
				{
					ws_warning("Not an IEC61850 unconfirmed service: %i", private_data->Service);
					//proto_tree_children_foreach(mms_tree, proto_tree_print_node, &level);
				}
				break;
			}
			case 4://rejectPDU
			{
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Reject(tvb, offset, item, actx);
				break;
			}
			case 5://cancel-req
			case 6://cancel-res
			{
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Cancel(tvb, offset, item, actx, private_data->MMSpdu-5);
				break;
			}
			case 7://cancel-Error
			{
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Cancel_Error(tvb, offset, item, actx);
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
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Associate_Error(tvb, offset, item, actx);
				break;
			}
			case 11://Release-req conclude
			case 12://Release-res conclude
			{
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Release(tvb, offset, item, actx, private_data->MMSpdu-11);
				break;
			}
			case 13://Release-Error
			{
				item = get_iec61850_item(tvb,parent_tree,proto_iec61850);
				decoded = Release_Error(tvb, offset, item, actx);
				break;
			}
			default:
				ws_warning("Not an IEC61850 PDU: %i", private_data->MMSpdu);
				//proto_tree_add_item(item, hf_iec61850_null, tvb, offset, -1, ENC_NA);
				//proto_tree_add_expert(tree, pinfo, &ei_iec61850_zero_pdu, tvb, offset, -1);
		}
		if(private_data->MMSpdu == 0)//store request data
		{
			store_invoke_data(pinfo, private_data->invokeID, &sessiondata);
		}
		//if(offset == old_offset)????ERROR??

	}
    return decoded;
}

int32_t Unconfirmed_RPT(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{// TODO Report,(shall have VMD-SPECIFIC)
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Unconfirmed, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s", "Unconfirmed ", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int32_t CommandTerm(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{// TODO CommandTermination + or -
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Unconfirmed, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s", "Unconfirmed-CommandTermination ", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);
	return 1;
}

int32_t Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Error, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s", "Error" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t Reject(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Reject, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s", "Reject" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t Associate(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Associate, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s %s", "Associate", res? "res" : "req" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t Cancel(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{//abort
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Cancel, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s %s", "Cancel", res? "res" : "req" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t Release(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Release, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s %s", "Release", res? "res" : "req" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t Associate_Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Associate, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s", "Associate-Error" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t Cancel_Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Cancel_Error, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s", "Cancel-Error" );
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t Release_Error(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
	proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_Release_Error, tvb, offset, -1, ENC_NA);
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s", "Release-Error");
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetServerDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetServerDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s",	private_data_get_preCinfo(actx), "GetServerDirectory req", 
		private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetLogicalDeviceDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetLogicalDeviceDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s",	private_data_get_preCinfo(actx), "GetLogicalDeviceDirectory req", 
		private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetLogicalNodeDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetLogicalNodeDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s",	private_data_get_preCinfo(actx), "GetLogicalNodeDirectory req", 
		private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetJournalDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetJournalDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s",	private_data_get_preCinfo(actx), "GetJournalDirectory req", 
		private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetNameList_response(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, iec61850_value_req *val)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	u_int8_t * serviceName = NULL;
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	int32_t hf_name;
	if(val != NULL && val->serviceName != NULL)
	{
		serviceName = val->serviceName;
		hf_name = val->hf_name;
	}
	else
	{
		serviceName = "GetNameList";
		hf_name = hf_iec61850_GetNameList_response;
	}

	subitem = proto_tree_add_item(item, hf_name, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s%s %s",	private_data_get_preCinfo(actx), serviceName," res", 
		private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		if(val != NULL)
			data.request = (u_int8_t *)wmem_strbuf_get_str(val->data);
		else
			data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetDataDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{//also GetDataDefinition
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetDataDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetDataDirectory", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetDataValue(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res, iec61850_value_req * val)
{ 
	proto_item *subitem;
    proto_tree *subtree=NULL;
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);

	u_int8_t * fieldName = "GetDataValue";
	u_int8_t * request = "";
	int32_t hf_name = hf_iec61850_GetDataValue;

	if(val != NULL)
		request = (u_int8_t *)wmem_strbuf_get_str(val->data);

	if(g_strrstr(request,"$BR$") || g_strrstr(request,"$RP$"))//GetBRCBValues,GetURCBValues,
	{
		fieldName = "GetRCBValues";
		hf_name = hf_iec61850_GetRCBValues;
	}
	if(g_strrstr(request,"$GO$") )//GetGoCBValues, GetGsCBValues
	{
		fieldName = "GetGCBValues";
		hf_name = hf_iec61850_GetRCBValues;
	}
	if(g_strrstr(request,"$SG$") )//GetEditSGValue,GetSGCBValues,
	{
		fieldName = "GetSGCBValues";
		hf_name = hf_iec61850_GetSGCBValues;
	}
	if(g_strrstr(request,"$LG$") )//GetLCBValues,GetLogStatusValues,
	{
		fieldName = "GetLCBValues";
		hf_name = hf_iec61850_GetLCBValues;
	}
	if(g_str_has_suffix(request,"$SBO") )//Select,
	{
		fieldName = "Select";
		hf_name = hf_iec61850_Select;
		if(g_str_has_suffix(private_data->moreCinfo, "\"\" "))
			private_data->Success = 0; //empty SBO means failure
	}
	/*
	the read request Variable AccessSpecification shall specify alternateAccess. 
	The accessSelection of the alternate access specification shall specify component. 
	The value of the component shall be the value of the functional constraint being specified.
	*/
	if(private_data->AlternateAccess == 1)//GetAllDataValues(alternate access),
	{
		fieldName = "GetAllDataValues";
		hf_name = hf_iec61850_GetAllDataValues;
	}
	/*
	specificationWithResult Shall be TRUE
	variableAccessSpecification Shall be constrained to variableListName
	*/
	if(private_data->VariableAccessSpecification == 1) //GetDataSetValues
	{
		fieldName = "GetDataSetValues";
		hf_name = hf_iec61850_GetDataSetValues;
	}
	val->serviceName = fieldName;

	subitem = proto_tree_add_item(item, hf_name, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s %s",	private_data_get_preCinfo(actx), fieldName, 
		res? "res" : "req", 
		res? (private_data->Success? "Success" : "Failure") : "", 
		private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		if(val != NULL)
			data.request = (u_int8_t *)wmem_strbuf_get_str(val->data);
		else
			data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t SetDataValue(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res, iec61850_value_req * val)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
	u_int8_t * fieldName = "SetDataValue";
	u_int8_t * request = "";
	int32_t hf_name = hf_iec61850_SetDataValue;

	if(val != NULL)
		request = (u_int8_t *)wmem_strbuf_get_str(val->data);

	if(g_strrstr(request,"$BR$") || g_strrstr(request,"$RP$"))//SetBRCBValues,SetURCBValues,
	{
		fieldName = "SetRCBValues";
		hf_name = hf_iec61850_SetRCBValues;
	}
	if(g_strrstr(request,"$GO$") )//SetGoCBValues, SetGsCBValues
	{
		fieldName = "SetGCBValues";
		hf_name = hf_iec61850_SetGCBValues;
	}
	if(g_strrstr(request,"$SG$") )//SelectActiveSG,SelectEditSG,SetEditSGValue,ConfirmEditSGValues
	{
		fieldName = "SetSGCBValues";
		hf_name = hf_iec61850_SetSGCBValues;
	}
	if(g_strrstr(request,"$LG$") )//SetLCBValues
	{
		fieldName = "SetLCBValues";
		hf_name = hf_iec61850_SetLCBValues;
	}
	if(private_data->VariableAccessSpecification == 1) //SetDataSetValues
	{
		fieldName = "SetDataSetValues";
		hf_name = hf_iec61850_SetDataSetValues;
	}
	if(g_strrstr(request,"$SBOw ") )//SelectWithValue, 
	{
		fieldName = "SelectWithValue";
		hf_name = hf_iec61850_SelectWithValue;
	}
	if(g_strrstr(request,"$Cancel ") )//Cancel,
	{
		fieldName = "Cancel";
		hf_name = hf_iec61850_OperCancel;
	}
	if(g_strrstr(request,"$Oper ") )// Operate,TimeActivatedOperate
	{
		fieldName = "Operate";
		hf_name = hf_iec61850_Operate;
	}
	val->serviceName = fieldName;

	subitem = proto_tree_add_item(item, hf_name, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s %s",	private_data_get_preCinfo(actx), fieldName, 
		res? "res" : "req", 
		res? (private_data->Success? "Success" : "Failure") : "", 
		private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		if(val != NULL)
			data.request = (u_int8_t *)wmem_strbuf_get_str(val->data);
		else
			data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetDataSetDirectory(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetDataSetDirectory, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetDataSetDirectory", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t CreateDataSet(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_CreateDataSet, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "CreateDataSet", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t DeleteDataSet(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_DeleteDataSet, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "DeleteDataSet", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t QueryLog(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_QueryLog, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "QueryLog", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t SetFile(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_SetFile, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "SetFile", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetFile(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetFile, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetFile", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t FileRead(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_FileRead, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "FileRead", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t FileClose(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_FileClose, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "FileClose", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t DeleteFile(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_DeleteFile, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "DeleteFile", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

int32_t GetServerDirectory_FILE(tvbuff_t *tvb, int32_t offset, proto_item *item, asn1_ctx_t *actx, int32_t res)
{
	proto_item *subitem;
    proto_tree *subtree=NULL;
	subitem = proto_tree_add_item(item, hf_iec61850_GetServerDirectory_FILE, tvb, offset, -1, ENC_NA);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s %s %s",	private_data_get_preCinfo(actx), "GetServerDirectory(FILE)", 
		res? "res" : "req", private_data_get_moreCinfo(actx));
	subtree = proto_item_add_subtree(subitem, ett_iec61850);

	if(g_mms_tree != NULL)
	{
		tree_data data;
		data.level =1;
		data.tree = subtree;
		data.tvb = tvb;
		data.offset = subtree->finfo->start;
		data.actx = actx;
		data.request = "";
		proto_tree_children_foreach(g_mms_tree, proto_tree_print_tree, &data);			
	}

	return 1;
}

/*
 * Hash Functions
 */
static int32_t iec61850_equal(gconstpointer v, gconstpointer w)
{
	const iec61850_key_req *v1 = (const iec61850_key_req *)v;
	const iec61850_key_req *v2 = (const iec61850_key_req *)w;

	if (v1->conversation == v2->conversation &&
	    v1->invokeID == v2->invokeID ) {
		return 1;
	}
	return 0;
}

static u_int32_t iec61850_hash (gconstpointer v)
{
	const iec61850_key_req *key = (const iec61850_key_req *)v;
	u_int64_t val=0;
	// get values from struct
	u_int64_t conv = (u_int64_t)key->conversation;
	u_int64_t invokeID = (u_int64_t)key->invokeID;
	// combine 2 32 bit values in one 64 bit value 
	val = ((conv<<32)&0xffffffff00000000 || invokeID&0x00000000ffffffff);
	// hash it to an 32 bit int;
	return wmem_int64_hash(&val);
}

/* 
 * create an iec61850 subtree if this is a valid packet 
 */

static proto_item *get_iec61850_item(tvbuff_t *tvb, proto_tree *parent_tree, const int32_t proto_iec61850)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_iec61850, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_iec61850);
	}
	return item;
}

/* 
 * load/store conversation data function 
 */

static void store_invoke_data(packet_info *pinfo, u_int32_t invokeID, iec61850_value_req * data) 
{
	iec61850_key_req key;
	iec61850_value_req *request_val = NULL;

	conversation_t * conversation = find_or_create_conversation(pinfo);
	if (conversation == NULL)
	{
		ws_warning("could not allocate conversation");
		return;
	}
	key.conversation = conversation->conv_index;
	key.invokeID = invokeID;

	request_val = (iec61850_value_req *)wmem_map_lookup(iec61850_request_hash, &key);
	if (!request_val)
	{
		iec61850_key_req *new_key = wmem_alloc(wmem_file_scope(), sizeof(iec61850_key_req));
		if(new_key == NULL)
		{
			ws_warning("could not allocate key");
			return;
		}
		*new_key = key;

		request_val = wmem_alloc(wmem_file_scope(), sizeof(iec61850_value_req));
		if(request_val == NULL)
		{
			ws_warning("could not allocate value");
			return;
		}
		request_val->serviceName = data->serviceName;
		request_val->hf_name = data->hf_name;
		request_val->data = data->data;

		wmem_map_insert(iec61850_request_hash, new_key, request_val);
	}
	else
	{
		request_val->serviceName = data->serviceName;
		request_val->data = data->data;
		request_val->hf_name = data->hf_name;
	}
}

static iec61850_value_req *load_invoke_data(packet_info *pinfo, u_int32_t invokeID) 
{
	iec61850_key_req key;
	iec61850_value_req *request_val = NULL;
	conversation_t * conversation = find_conversation_pinfo(pinfo,0);
	if (conversation == NULL)
	{
		return NULL;
	}
	key.conversation = conversation->conv_index;
	key.invokeID = invokeID;

	return (iec61850_value_req *)wmem_map_lookup(iec61850_request_hash, &key);
}

static void free_invoke_data(packet_info *pinfo, u_int32_t invokeID) 
{
	iec61850_key_req key;
	iec61850_value_req *request_val = NULL;
	iec61850_value_req *value = NULL;
	conversation_t * conversation = find_conversation_pinfo(pinfo,0);
	if (conversation == NULL)
	{
		return;
	}
	key.conversation = conversation->conv_index;
	key.invokeID = invokeID;

	value = wmem_map_lookup(iec61850_request_hash, &key);
	if(value == NULL)
	{
		return;
	}
	wmem_map_remove(iec61850_request_hash, &key);
	wmem_free(wmem_file_scope(),value);
}

/* 
 * mapping/register function 
 */

void register_iec61850_mappings(const int32_t parent, hf_register_info * mms_hf)
{
	g_mms_hf = mms_hf;

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
			&hf_iec61850_Error,
      		{ 
				"Error", 			// name
				"iec61850.Error",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Reject,
      		{ 
				"Reject", 			// name
				"iec61850.Reject",   // abrev
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
			&hf_iec61850_Cancel,
      		{ 
				"Cancel", 			// name
				"iec61850.Cancel",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Release,
      		{ 
				"Release", 			// name
				"iec61850.Release",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Associate_Error,
      		{ 
				"Associate_Error", 			// name
				"iec61850.Associate_Error",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Cancel_Error,
      		{ 
				"Cancel_Error", 			// name
				"iec61850.Cancel_Error",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Release_Error,
      		{ 
				"Release_Error", 			// name
				"iec61850.Release_Error",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetServerDirectory,
      		{ 
				"GetServerDirectory", 			// name
				"iec61850.GetServerDirectory",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetLogicalDeviceDirectory,
      		{ 
				"GetLogicalDeviceDirectory", 			// name
				"iec61850.GetLogicalDeviceDirectory",   // abrev
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
			&hf_iec61850_GetJournalDirectory,
      		{ 
				"GetJournalDirectory", 			// name
				"iec61850.GetJournalDirectory",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetNameList_response,
      		{ 
				"GetNameList-response", 			// name
				"iec61850.GetNameList-response",   // abrev
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
			&hf_iec61850_GetRCBValues,
      		{ 
				"GetRCBValues", 			// name
				"iec61850.GetRCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetGCBValues,
      		{ 
				"GetGCBValues", 			// name
				"iec61850.GetGCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetSGCBValues,
      		{ 
				"GetSGCBValues", 			// name
				"iec61850.GetSGCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetLCBValues,
      		{ 
				"GetLCBValues", 			// name
				"iec61850.GetLCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Select,
      		{ 
				"Select", 			// name
				"iec61850.Select",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetAllDataValues,
      		{ 
				"GetAllDataValues", 			// name
				"iec61850.GetAllDataValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_GetDataSetValues,
      		{ 
				"GetDataSetValues", 			// name
				"iec61850.GetDataSetValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SetRCBValues,
      		{ 
				"SetRCBValues", 			// name
				"iec61850.SetRCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SetGCBValues,
      		{ 
				"SetGCBValues", 			// name
				"iec61850.SetGCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SetSGCBValues,
      		{ 
				"SetSGCBValues", 			// name
				"iec61850.SetSGCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SetLCBValues,
      		{ 
				"SetLCBValues", 			// name
				"iec61850.SetLCBValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SetDataSetValues,
      		{ 
				"SetDataSetValues", 			// name
				"iec61850.SetDataSetValues",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_SelectWithValue,
      		{ 
				"SelectWithValue", 			// name
				"iec61850.SelectWithValue",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_OperCancel,
      		{ 
				"Operate Cancel", 			// name
				"iec61850.OperCancel",   // abrev
        		FT_NONE, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ 
			&hf_iec61850_Operate,
      		{ 
				"Operate", 			// name
				"iec61850.Operate",   // abrev
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
			&hf_iec61850_OpenFile,
      		{ 
				"OpenFile", 			// name
				"iec61850.OpenFile",   // abrev
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
        		FT_STRING, 				// type
				BASE_NONE, 				// display
				NULL, 					// 
				0,						// 
        		NULL, 					// 
				HFILL 					// ref type
			}
		},
		{ &hf_iec61850_QualityC0,
		{ "Validity", "iec61850.Validity",
			FT_UINT8, BASE_HEX, VALS(enum_Validity), 0xC0,
			"Validity", HFILL }},
		{ &hf_iec61850_Quality20,
		{ "Overflow", "iec61850.Overflow",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL }},
		{ &hf_iec61850_Quality10,
		{ "OutofRange", "iec61850.OutofRange",
			FT_BOOLEAN, 8, NULL, 0x10,
			NULL, HFILL }},
		{ &hf_iec61850_Quality8,
		{ "BadReference", "iec61850.BadReference",
			FT_BOOLEAN, 8, NULL, 0x08,
			NULL, HFILL }},
		{ &hf_iec61850_Quality4,
		{ "Oscillatory", "iec61850.Oscillatory",
			FT_BOOLEAN, 8, NULL, 0x04,
			NULL, HFILL }},
		{ &hf_iec61850_Quality2,
		{ "Failure", "iec61850.Failure",
			FT_BOOLEAN, 8, NULL, 0x02,
			NULL, HFILL }},
		{ &hf_iec61850_Quality1,
		{ "OldData", "iec61850.OldData",
			FT_BOOLEAN, 8, NULL, 0x01,
			NULL, HFILL }},
		{ &hf_iec61850_Quality0080,
		{ "Inconsistent", "iec61850.Inconsistent",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }},
		{ &hf_iec61850_Quality0040,
		{ "Inaccurate", "iec61850.Inaccurate",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }},
		{ &hf_iec61850_Quality0020,
		{ "Source", "iec61850.Source",
			FT_UINT8, BASE_HEX, VALS(enum_Source), 0x20,
			NULL, HFILL }},
		{ &hf_iec61850_Quality0010,
		{ "Test", "iec61850.Test",
			FT_BOOLEAN, 8, NULL, 0x10,
			NULL, HFILL }},
		{ &hf_iec61850_Quality0008,
		{ "OperatorBlocked", "iec61850.OperatorBlocked",
			FT_BOOLEAN, 8, NULL, 0x08,
			NULL, HFILL }},
/* timequality
	0 Leap Second Known
	1 ClockFailure
	2 Clock not synchronized
	3-7 Time accuracy
*/
		{ &hf_iec61850_timequality80,
		{ "Leap Second Known", "iec61850.LeapSecondKnown",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }},
		{ &hf_iec61850_timequality40,
		{ "ClockFailure", "iec61850.ClockFailure",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }},
		{ &hf_iec61850_timequality20,
		{ "Clock not synchronized", "iec61850.ClockNotSynchronized",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL }},
		{ &hf_iec61850_timequality1F,
		{ "Time Accuracy", "iec61850.TimeAccuracy",
			FT_UINT8, BASE_HEX, VALS(enum_TimeAccuracy), 0x1F,
			NULL, HFILL }},
/*
check bits (interlock/synchrocheck) - bitstring
	synchrocheck		BOOLEAN	TRUE means perform synchrocheck
	Interlock-check 	BOOLEAN	TRUE means check for interlocking condition
*/
		{ &hf_iec61850_Check2,
		{ "synchrocheck", "iec61850.synchrocheck",
			FT_BOOLEAN, 2, NULL, 0x2,
			NULL, HFILL }},
		{ &hf_iec61850_Check1,
		{ "Interlock-check", "iec61850.InterlockCheck",
			FT_BOOLEAN, 2, NULL, 0x1,
			NULL, HFILL }},
/*
ReasonCode (ReasonForInclusion)/TriggerConditions/TrgOp  - bitstring
	Bit 0 Reserved
	Bit 1 data-change
	Bit 2 quality-change
	Bit 3 data-update
	Bit 4 integrity
	Bit 5 general-interrogation
	Bit 6 application-trigger
*/
		{ &hf_iec61850_ReasonCode80,
		{ "Reserved", "iec61850.Reserved",
			FT_BOOLEAN, 7, NULL, 0x80,
			NULL, HFILL }},
		{ &hf_iec61850_ReasonCode40,
		{ "data-change", "iec61850.DataChange",
			FT_BOOLEAN, 7, NULL, 0x40,
			NULL, HFILL }},
		{ &hf_iec61850_ReasonCode20,
		{ "quality-change", "iec61850.QualityChange",
			FT_BOOLEAN, 7, NULL, 0x20,
			NULL, HFILL }},
		{ &hf_iec61850_ReasonCode10,
		{ "data-update", "iec61850.DataUpdate",
			FT_BOOLEAN, 7, NULL, 0x10,
			NULL, HFILL }},
		{ &hf_iec61850_ReasonCode8,
		{ "integrity", "iec61850.integrity",
			FT_BOOLEAN, 7, NULL, 0x8,
			NULL, HFILL }},
		{ &hf_iec61850_ReasonCode4,
		{ "general-interrogation", "iec61850.GeneralInterrogation",
			FT_BOOLEAN, 7, NULL, 0x4,
			NULL, HFILL }},
		{ &hf_iec61850_ReasonCode2,
		{ "application-trigger", "iec61850.ApplicationTrigger",
			FT_BOOLEAN, 7, NULL, 0x2,
			NULL, HFILL }},
/*
OptFlds - bitstring
	Reserved				0
	sequence-number			1
	report-time-stamp		2
	reason-for-inclusion	3
	data-set-name			4
	data-reference			5
	buffer-overflow			6
	entryID					7
	conf-revision			8
	segmentation			9
*/
		{ &hf_iec61850_OptFlds80,
		{ "Reserved", "iec61850.Reserved",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds40,
		{ "sequence-number", "iec61850.sequence-number",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds20,
		{ "report-time-stamp", "iec61850.report-time-stamp",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds10,
		{ "reason-for-inclusion", "iec61850.reason-for-inclusion",
			FT_BOOLEAN, 8, NULL, 0x10,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds8,
		{ "data-set-name", "iec61850.data-set-name",
			FT_BOOLEAN, 8, NULL, 0x8,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds4,
		{ "data-reference", "iec61850.data-reference",
			FT_BOOLEAN, 8, NULL, 0x4,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds2,
		{ "buffer-overflow", "iec61850.buffer-overflow",
			FT_BOOLEAN, 8, NULL, 0x2,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds1,
		{ "entryID", "iec61850.entryID",
			FT_BOOLEAN, 8, NULL, 0x1,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds0080,
		{ "conf-revision", "iec61850.conf-revision",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }},
		{ &hf_iec61850_OptFlds0040,
		{ "segmentation", "iec61850.segmentation",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }},
/*
DBPos
*/
		{ &hf_iec61850_DBPosC,
		{ "Double Position", "iec61850.DBPos",
			FT_UINT8, BASE_HEX, VALS(enum_DBPos), 0xC0,
			NULL, HFILL }},
/*
hf_iec61850_BinaryStepC
*/
		{ &hf_iec61850_BinaryStepC,
		{ "Step Position", "iec61850.BinaryStep",
			FT_UINT8, BASE_HEX, VALS(enum_BinaryStep), 0xC,
			NULL, HFILL }},

		{ &hf_iec61850_ctlModel,
		{ "ctlModel", "iec61850.ctlModel",
			FT_UINT8, BASE_DEC, VALS(enum_ctlModel), 0,
			NULL, HFILL }},
		{ &hf_iec61850_orCat,
		{ "orCat", "iec61850.orCat",
			FT_UINT8, BASE_DEC, VALS(enum_orCategory), 0,
			NULL, HFILL }},
		{ &hf_iec61850_Beh,
		{ "Beh", "iec61850.Beh",
			FT_UINT8, BASE_DEC, VALS(enum_Beh_Mod), 0,
			NULL, HFILL }},
		{ &hf_iec61850_Mod,
		{ "Mod", "iec61850.Mod",
			FT_UINT8, BASE_DEC, VALS(enum_Beh_Mod), 0,
			NULL, HFILL }},
		{ &hf_iec61850_Health,
		{ "Health", "iec61850.Health",
			FT_UINT8, BASE_DEC, VALS(enum_Health), 0,
			NULL, HFILL }},
		{ &hf_iec61850_dir,
		{ "direction", "iec61850.direction",
			FT_UINT8, BASE_DEC, VALS(enum_dir), 0,
			NULL, HFILL }},
    };

	/* List of subtrees */
	static int32_t *ett_61850[] = {
		&ett_iec61850,
	};

	static ei_register_info ei_61850[] = {
		{ &ei_iec61850_mal_timeofday_encoding, { "iec61850.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
		{ &ei_iec61850_mal_utctime_encoding, { "iec61850.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
		{ &ei_iec61850_zero_pdu, { "iec61850.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte iec61850 PDU", EXPFILL }},
		{ &ei_iec61850_failed_resp, { "iec61850_failed_resp", PI_RESPONSE_CODE, PI_NOTE, "Failed request, the request has not been accepted by the server", EXPFILL} },
	};

	expert_module_t* expert_iec61850;

    proto_register_field_array(parent, hf, array_length(hf));

	proto_register_subtree_array(ett_61850, array_length(ett_61850));
	expert_iec61850 = expert_register_protocol(parent);
	expert_register_field_array(expert_iec61850, ei_61850, array_length(ei_61850));

	iec61850_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), iec61850_hash, iec61850_equal);

}

/*

dissect_iec61850_T_access
dissect_iec61850_T_service
dissect_iec61850_T_file
dissect_iec61850_T_definition
dissect_iec61850_T_initiate
dissect_iec61850_T_conclude
******************************
		fieldName = "GetRCBValues";
		fieldName = "GetGCBValues";
		fieldName = "GetSGCBValues";
		fieldName = "GetLCBValues";
		fieldName = "Select";
		fieldName = "GetAllDataValues";
		fieldName = "GetDataSetValues";
		fieldName = "SetRCBValues";
		fieldName = "SetGCBValues";
		fieldName = "SetSGCBValues";
		fieldName = "SetLCBValues";
		fieldName = "SetDataSetValues";
		fieldName = "SelectWithValue";
		fieldName = "Cancel";
		fieldName = "Operate";

*/