/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-iec61850.c                                                          */
/* asn2wrs.py -b -L -p iec61850 -c ./iec61850.cnf -s ./packet-iec61850-template -D . -O ../src iec61850.asn */

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

static int32_t hf_iec61850_MMSpdu = -1;
static int hf_iec61850_confirmed_RequestPDU;      /* Confirmed_RequestPDU */
static int hf_iec61850_confirmed_ResponsePDU;     /* Confirmed_ResponsePDU */
static int hf_iec61850_confirmed_ErrorPDU;        /* Confirmed_ErrorPDU */
static int hf_iec61850_unconfirmed_PDU;           /* Unconfirmed_PDU */
static int hf_iec61850_rejectPDU;                 /* RejectPDU */
static int hf_iec61850_cancel_RequestPDU;         /* Cancel_RequestPDU */
static int hf_iec61850_cancel_ResponsePDU;        /* Cancel_ResponsePDU */
static int hf_iec61850_cancel_ErrorPDU;           /* Cancel_ErrorPDU */
static int hf_iec61850_initiate_RequestPDU;       /* Initiate_RequestPDU */
static int hf_iec61850_initiate_ResponsePDU;      /* Initiate_ResponsePDU */
static int hf_iec61850_initiate_ErrorPDU;         /* Initiate_ErrorPDU */
static int hf_iec61850_conclude_RequestPDU;       /* Conclude_RequestPDU */
static int hf_iec61850_conclude_ResponsePDU;      /* Conclude_ResponsePDU */
static int hf_iec61850_conclude_ErrorPDU;         /* Conclude_ErrorPDU */
static int hf_iec61850_invokeID;                  /* Unsigned32 */
static int hf_iec61850_listOfModifier;            /* SEQUENCE_OF_Modifier */
static int hf_iec61850_listOfModifier_item;       /* Modifier */
static int hf_iec61850_confirmedServiceRequest;   /* ConfirmedServiceRequest */
static int hf_iec61850_cs_request_detail;         /* CS_Request_Detail */
static int hf_iec61850_unconfirmedService;        /* UnconfirmedService */
static int hf_iec61850_confirmedServiceResponse;  /* ConfirmedServiceResponse */
static int hf_iec61850_modifierPosition;          /* Unsigned32 */
static int hf_iec61850_serviceError;              /* ServiceError */
static int hf_iec61850_informationReport;         /* InformationReport */
static int hf_iec61850_unsolicitedStatus;         /* UnsolicitedStatus */
static int hf_iec61850_eventNotification;         /* EventNotification */
static int hf_iec61850_attach_To_Event_Condition;  /* AttachToEventCondition */
static int hf_iec61850_attach_To_Semaphore;       /* AttachToSemaphore */
static int hf_iec61850_status;                    /* Status_Request */
static int hf_iec61850_getNameList;               /* GetNameList_Request */
static int hf_iec61850_identify;                  /* Identify_Request */
static int hf_iec61850_rename;                    /* Rename_Request */
static int hf_iec61850_read;                      /* Read_Request */
static int hf_iec61850_write;                     /* Write_Request */
static int hf_iec61850_getVariableAccessAttributes;  /* GetVariableAccessAttributes_Request */
static int hf_iec61850_defineNamedVariable;       /* DefineNamedVariable_Request */
static int hf_iec61850_defineScatteredAccess;     /* DefineScatteredAccess_Request */
static int hf_iec61850_getScatteredAccessAttributes;  /* GetScatteredAccessAttributes_Request */
static int hf_iec61850_deleteVariableAccess;      /* DeleteVariableAccess_Request */
static int hf_iec61850_defineNamedVariableList;   /* DefineNamedVariableList_Request */
static int hf_iec61850_getNamedVariableListAttributes;  /* GetNamedVariableListAttributes_Request */
static int hf_iec61850_deleteNamedVariableList;   /* DeleteNamedVariableList_Request */
static int hf_iec61850_defineNamedType;           /* DefineNamedType_Request */
static int hf_iec61850_getNamedTypeAttributes;    /* GetNamedTypeAttributes_Request */
static int hf_iec61850_deleteNamedType;           /* DeleteNamedType_Request */
static int hf_iec61850_input;                     /* Input_Request */
static int hf_iec61850_output;                    /* Output_Request */
static int hf_iec61850_takeControl;               /* TakeControl_Request */
static int hf_iec61850_relinquishControl;         /* RelinquishControl_Request */
static int hf_iec61850_defineSemaphore;           /* DefineSemaphore_Request */
static int hf_iec61850_deleteSemaphore;           /* DeleteSemaphore_Request */
static int hf_iec61850_reportSemaphoreStatus;     /* ReportSemaphoreStatus_Request */
static int hf_iec61850_reportPoolSemaphoreStatus;  /* ReportPoolSemaphoreStatus_Request */
static int hf_iec61850_reportSemaphoreEntryStatus;  /* ReportSemaphoreEntryStatus_Request */
static int hf_iec61850_initiateDownloadSequence;  /* InitiateDownloadSequence_Request */
static int hf_iec61850_downloadSegment;           /* DownloadSegment_Request */
static int hf_iec61850_terminateDownloadSequence;  /* TerminateDownloadSequence_Request */
static int hf_iec61850_initiateUploadSequence;    /* InitiateUploadSequence_Request */
static int hf_iec61850_uploadSegment;             /* UploadSegment_Request */
static int hf_iec61850_terminateUploadSequence;   /* TerminateUploadSequence_Request */
static int hf_iec61850_requestDomainDownload;     /* RequestDomainDownload_Request */
static int hf_iec61850_requestDomainUpload;       /* RequestDomainUpload_Request */
static int hf_iec61850_loadDomainContent;         /* LoadDomainContent_Request */
static int hf_iec61850_storeDomainContent;        /* StoreDomainContent_Request */
static int hf_iec61850_deleteDomain;              /* DeleteDomain_Request */
static int hf_iec61850_getDomainAttributes;       /* GetDomainAttributes_Request */
static int hf_iec61850_createProgramInvocation;   /* CreateProgramInvocation_Request */
static int hf_iec61850_deleteProgramInvocation;   /* DeleteProgramInvocation_Request */
static int hf_iec61850_start;                     /* Start_Request */
static int hf_iec61850_stop;                      /* Stop_Request */
static int hf_iec61850_resume;                    /* Resume_Request */
static int hf_iec61850_reset;                     /* Reset_Request */
static int hf_iec61850_kill;                      /* Kill_Request */
static int hf_iec61850_getProgramInvocationAttributes;  /* GetProgramInvocationAttributes_Request */
static int hf_iec61850_obtainFile;                /* ObtainFile_Request */
static int hf_iec61850_defineEventCondition;      /* DefineEventCondition_Request */
static int hf_iec61850_confirmedServiceRequest_deleteEventCondition;  /* DeleteEventCondition_Request */
static int hf_iec61850_getEventConditionAttributes;  /* GetEventConditionAttributes_Request */
static int hf_iec61850_reportEventConditionStatus;  /* ReportEventConditionStatus_Request */
static int hf_iec61850_alterEventConditionMonitoring;  /* AlterEventConditionMonitoring_Request */
static int hf_iec61850_triggerEvent;              /* TriggerEvent_Request */
static int hf_iec61850_defineEventAction;         /* DefineEventAction_Request */
static int hf_iec61850_confirmedServiceRequest_deleteEventAction;  /* DeleteEventAction_Request */
static int hf_iec61850_getEventActionAttributes;  /* GetEventActionAttributes_Request */
static int hf_iec61850_reportEventActionStatus;   /* ReportEventActionStatus_Request */
static int hf_iec61850_defineEventEnrollment;     /* DefineEventEnrollment_Request */
static int hf_iec61850_confirmedServiceRequest_deleteEventEnrollment;  /* DeleteEventEnrollment_Request */
static int hf_iec61850_alterEventEnrollment;      /* AlterEventEnrollment_Request */
static int hf_iec61850_reportEventEnrollmentStatus;  /* ReportEventEnrollmentStatus_Request */
static int hf_iec61850_getEventEnrollmentAttributes;  /* GetEventEnrollmentAttributes_Request */
static int hf_iec61850_acknowledgeEventNotification;  /* AcknowledgeEventNotification_Request */
static int hf_iec61850_getAlarmSummary;           /* GetAlarmSummary_Request */
static int hf_iec61850_getAlarmEnrollmentSummary;  /* GetAlarmEnrollmentSummary_Request */
static int hf_iec61850_readJournal;               /* ReadJournal_Request */
static int hf_iec61850_writeJournal;              /* WriteJournal_Request */
static int hf_iec61850_initializeJournal;         /* InitializeJournal_Request */
static int hf_iec61850_reportJournalStatus;       /* ReportJournalStatus_Request */
static int hf_iec61850_createJournal;             /* CreateJournal_Request */
static int hf_iec61850_deleteJournal;             /* DeleteJournal_Request */
static int hf_iec61850_getCapabilityList;         /* GetCapabilityList_Request */
static int hf_iec61850_fileOpen;                  /* FileOpen_Request */
static int hf_iec61850_fileRead;                  /* FileRead_Request */
static int hf_iec61850_fileClose;                 /* FileClose_Request */
static int hf_iec61850_fileRename;                /* FileRename_Request */
static int hf_iec61850_fileDelete;                /* FileDelete_Request */
static int hf_iec61850_fileDirectory;             /* FileDirectory_Request */
static int hf_iec61850_foo;                       /* INTEGER */
static int hf_iec61850_status_01;                 /* Status_Response */
static int hf_iec61850_getNameList_01;            /* GetNameList_Response */
static int hf_iec61850_identify_01;               /* Identify_Response */
static int hf_iec61850_rename_01;                 /* Rename_Response */
static int hf_iec61850_read_01;                   /* Read_Response */
static int hf_iec61850_write_01;                  /* Write_Response */
static int hf_iec61850_getVariableAccessAttributes_01;  /* GetVariableAccessAttributes_Response */
static int hf_iec61850_defineNamedVariable_01;    /* DefineNamedVariable_Response */
static int hf_iec61850_defineScatteredAccess_01;  /* DefineScatteredAccess_Response */
static int hf_iec61850_getScatteredAccessAttributes_01;  /* GetScatteredAccessAttributes_Response */
static int hf_iec61850_deleteVariableAccess_01;   /* DeleteVariableAccess_Response */
static int hf_iec61850_defineNamedVariableList_01;  /* DefineNamedVariableList_Response */
static int hf_iec61850_getNamedVariableListAttributes_01;  /* GetNamedVariableListAttributes_Response */
static int hf_iec61850_deleteNamedVariableList_01;  /* DeleteNamedVariableList_Response */
static int hf_iec61850_defineNamedType_01;        /* DefineNamedType_Response */
static int hf_iec61850_getNamedTypeAttributes_01;  /* GetNamedTypeAttributes_Response */
static int hf_iec61850_deleteNamedType_01;        /* DeleteNamedType_Response */
static int hf_iec61850_input_01;                  /* Input_Response */
static int hf_iec61850_output_01;                 /* Output_Response */
static int hf_iec61850_takeControl_01;            /* TakeControl_Response */
static int hf_iec61850_relinquishControl_01;      /* RelinquishControl_Response */
static int hf_iec61850_defineSemaphore_01;        /* DefineSemaphore_Response */
static int hf_iec61850_deleteSemaphore_01;        /* DeleteSemaphore_Response */
static int hf_iec61850_reportSemaphoreStatus_01;  /* ReportSemaphoreStatus_Response */
static int hf_iec61850_reportPoolSemaphoreStatus_01;  /* ReportPoolSemaphoreStatus_Response */
static int hf_iec61850_reportSemaphoreEntryStatus_01;  /* ReportSemaphoreEntryStatus_Response */
static int hf_iec61850_initiateDownloadSequence_01;  /* InitiateDownloadSequence_Response */
static int hf_iec61850_downloadSegment_01;        /* DownloadSegment_Response */
static int hf_iec61850_terminateDownloadSequence_01;  /* TerminateDownloadSequence_Response */
static int hf_iec61850_initiateUploadSequence_01;  /* InitiateUploadSequence_Response */
static int hf_iec61850_uploadSegment_01;          /* UploadSegment_Response */
static int hf_iec61850_terminateUploadSequence_01;  /* TerminateUploadSequence_Response */
static int hf_iec61850_requestDomainDownLoad;     /* RequestDomainDownload_Response */
static int hf_iec61850_requestDomainUpload_01;    /* RequestDomainUpload_Response */
static int hf_iec61850_loadDomainContent_01;      /* LoadDomainContent_Response */
static int hf_iec61850_storeDomainContent_01;     /* StoreDomainContent_Response */
static int hf_iec61850_deleteDomain_01;           /* DeleteDomain_Response */
static int hf_iec61850_getDomainAttributes_01;    /* GetDomainAttributes_Response */
static int hf_iec61850_createProgramInvocation_01;  /* CreateProgramInvocation_Response */
static int hf_iec61850_deleteProgramInvocation_01;  /* DeleteProgramInvocation_Response */
static int hf_iec61850_start_01;                  /* Start_Response */
static int hf_iec61850_stop_01;                   /* Stop_Response */
static int hf_iec61850_resume_01;                 /* Resume_Response */
static int hf_iec61850_reset_01;                  /* Reset_Response */
static int hf_iec61850_kill_01;                   /* Kill_Response */
static int hf_iec61850_getProgramInvocationAttributes_01;  /* GetProgramInvocationAttributes_Response */
static int hf_iec61850_obtainFile_01;             /* ObtainFile_Response */
static int hf_iec61850_fileOpen_01;               /* FileOpen_Response */
static int hf_iec61850_defineEventCondition_01;   /* DefineEventCondition_Response */
static int hf_iec61850_confirmedServiceResponse_deleteEventCondition;  /* DeleteEventCondition_Response */
static int hf_iec61850_getEventConditionAttributes_01;  /* GetEventConditionAttributes_Response */
static int hf_iec61850_reportEventConditionStatus_01;  /* ReportEventConditionStatus_Response */
static int hf_iec61850_alterEventConditionMonitoring_01;  /* AlterEventConditionMonitoring_Response */
static int hf_iec61850_triggerEvent_01;           /* TriggerEvent_Response */
static int hf_iec61850_defineEventAction_01;      /* DefineEventAction_Response */
static int hf_iec61850_deleteEventAction;         /* DeleteEventAction_Response */
static int hf_iec61850_getEventActionAttributes_01;  /* GetEventActionAttributes_Response */
static int hf_iec61850_reportActionStatus;        /* ReportEventActionStatus_Response */
static int hf_iec61850_defineEventEnrollment_01;  /* DefineEventEnrollment_Response */
static int hf_iec61850_confirmedServiceResponse_deleteEventEnrollment;  /* DeleteEventEnrollment_Response */
static int hf_iec61850_alterEventEnrollment_01;   /* AlterEventEnrollment_Response */
static int hf_iec61850_reportEventEnrollmentStatus_01;  /* ReportEventEnrollmentStatus_Response */
static int hf_iec61850_getEventEnrollmentAttributes_01;  /* GetEventEnrollmentAttributes_Response */
static int hf_iec61850_acknowledgeEventNotification_01;  /* AcknowledgeEventNotification_Response */
static int hf_iec61850_getAlarmSummary_01;        /* GetAlarmSummary_Response */
static int hf_iec61850_getAlarmEnrollmentSummary_01;  /* GetAlarmEnrollmentSummary_Response */
static int hf_iec61850_readJournal_01;            /* ReadJournal_Response */
static int hf_iec61850_writeJournal_01;           /* WriteJournal_Response */
static int hf_iec61850_initializeJournal_01;      /* InitializeJournal_Response */
static int hf_iec61850_reportJournalStatus_01;    /* ReportJournalStatus_Response */
static int hf_iec61850_createJournal_01;          /* CreateJournal_Response */
static int hf_iec61850_deleteJournal_01;          /* DeleteJournal_Response */
static int hf_iec61850_getCapabilityList_01;      /* GetCapabilityList_Response */
static int hf_iec61850_fileRead_01;               /* FileRead_Response */
static int hf_iec61850_fileClose_01;              /* FileClose_Response */
static int hf_iec61850_fileRename_01;             /* FileRename_Response */
static int hf_iec61850_fileDelete_01;             /* FileDelete_Response */
static int hf_iec61850_fileDirectory_01;          /* FileDirectory_Response */
static int hf_iec61850_FileName_item;             /* GraphicString */
static int hf_iec61850_vmd_specific;              /* Identifier */
static int hf_iec61850_domain_specific;           /* T_domain_specific */
static int hf_iec61850_domainId;                  /* Identifier */
static int hf_iec61850_itemId;                    /* Identifier */
static int hf_iec61850_aa_specific;               /* Identifier */
static int hf_iec61850_ap_title;                  /* T_ap_title */
static int hf_iec61850_ap_invocation_id;          /* T_ap_invocation_id */
static int hf_iec61850_ae_qualifier;              /* T_ae_qualifier */
static int hf_iec61850_ae_invocation_id;          /* T_ae_invocation_id */
static int hf_iec61850_localDetailCalling;        /* Integer32 */
static int hf_iec61850_proposedMaxServOutstandingCalling;  /* Integer16 */
static int hf_iec61850_proposedMaxServOutstandingCalled;  /* Integer16 */
static int hf_iec61850_proposedDataStructureNestingLevel;  /* Integer8 */
static int hf_iec61850_mmsInitRequestDetail;      /* InitRequestDetail */
static int hf_iec61850_proposedVersionNumber;     /* Integer16 */
static int hf_iec61850_proposedParameterCBB;      /* ParameterSupportOptions */
static int hf_iec61850_servicesSupportedCalling;  /* ServiceSupportOptions */
static int hf_iec61850_localDetailCalled;         /* Integer32 */
static int hf_iec61850_negociatedMaxServOutstandingCalling;  /* Integer16 */
static int hf_iec61850_negociatedMaxServOutstandingCalled;  /* Integer16 */
static int hf_iec61850_negociatedDataStructureNestingLevel;  /* Integer8 */
static int hf_iec61850_mmsInitResponseDetail;     /* InitResponseDetail */
static int hf_iec61850_negociatedVersionNumber;   /* Integer16 */
static int hf_iec61850_negociatedParameterCBB;    /* ParameterSupportOptions */
static int hf_iec61850_servicesSupportedCalled;   /* ServiceSupportOptions */
static int hf_iec61850_originalInvokeID;          /* Unsigned32 */
static int hf_iec61850_errorClass;                /* T_errorClass */
static int hf_iec61850_vmd_state;                 /* T_vmd_state */
static int hf_iec61850_application_reference;     /* T_application_reference */
static int hf_iec61850_definition;                /* T_definition */
static int hf_iec61850_resource;                  /* T_resource */
static int hf_iec61850_service;                   /* T_service */
static int hf_iec61850_service_preempt;           /* T_service_preempt */
static int hf_iec61850_time_resolution;           /* T_time_resolution */
static int hf_iec61850_access;                    /* T_access */
static int hf_iec61850_initiate;                  /* T_initiate */
static int hf_iec61850_conclude;                  /* T_conclude */
static int hf_iec61850_cancel;                    /* T_cancel */
static int hf_iec61850_file;                      /* T_file */
static int hf_iec61850_others;                    /* INTEGER */
static int hf_iec61850_additionalCode;            /* INTEGER */
static int hf_iec61850_additionalDescription;     /* VisibleString */
static int hf_iec61850_serviceSpecificInformation;  /* T_serviceSpecificInformation */
static int hf_iec61850_obtainFile_02;             /* ObtainFile_Error */
static int hf_iec61850_start_02;                  /* Start_Error */
static int hf_iec61850_stop_02;                   /* Stop_Error */
static int hf_iec61850_resume_02;                 /* Resume_Error */
static int hf_iec61850_reset_02;                  /* Reset_Error */
static int hf_iec61850_deleteVariableAccess_02;   /* DeleteVariableAccess_Error */
static int hf_iec61850_deleteNamedVariableList_02;  /* DeleteNamedVariableList_Error */
static int hf_iec61850_deleteNamedType_02;        /* DeleteNamedType_Error */
static int hf_iec61850_defineEventEnrollment_Error;  /* DefineEventEnrollment_Error */
static int hf_iec61850_fileRename_02;             /* FileRename_Error */
static int hf_iec61850_additionalService;         /* AdditionalService_Error */
static int hf_iec61850_changeAccessControl;       /* ChangeAccessControl_Error */
static int hf_iec61850_defineEcl;                 /* DefineEventConditionList_Error */
static int hf_iec61850_addECLReference;           /* AddEventConditionListReference_Error */
static int hf_iec61850_removeECLReference;        /* RemoveEventConditionListReference_Error */
static int hf_iec61850_initiateUC;                /* InitiateUnitControl_Error */
static int hf_iec61850_startUC;                   /* StartUnitControl_Error */
static int hf_iec61850_stopUC;                    /* StopUnitControl_Error */
static int hf_iec61850_deleteUC;                  /* DeleteUnitControl_Error */
static int hf_iec61850_loadUCFromFile;            /* LoadUnitControlFromFile_Error */
static int hf_iec61850_eventCondition;            /* ObjectName */
static int hf_iec61850_eventConditionList;        /* ObjectName */
static int hf_iec61850_domain;                    /* Identifier */
static int hf_iec61850_programInvocation;         /* Identifier */
static int hf_iec61850_programInvocationName;     /* Identifier */
static int hf_iec61850_programInvocationState;    /* ProgramInvocationState */
static int hf_iec61850_none;                      /* NULL */
static int hf_iec61850_rejectReason;              /* T_rejectReason */
static int hf_iec61850_confirmed_requestPDU;      /* T_confirmed_requestPDU */
static int hf_iec61850_confirmed_responsePDU;     /* T_confirmed_responsePDU */
static int hf_iec61850_confirmed_errorPDU;        /* T_confirmed_errorPDU */
static int hf_iec61850_unconfirmedPDU;            /* T_unconfirmedPDU */
static int hf_iec61850_pdu_error;                 /* T_pdu_error */
static int hf_iec61850_cancel_requestPDU;         /* T_cancel_requestPDU */
static int hf_iec61850_cancel_responsePDU;        /* T_cancel_responsePDU */
static int hf_iec61850_cancel_errorPDU;           /* T_cancel_errorPDU */
static int hf_iec61850_conclude_requestPDU;       /* T_conclude_requestPDU */
static int hf_iec61850_conclude_responsePDU;      /* T_conclude_responsePDU */
static int hf_iec61850_conclude_errorPDU;         /* T_conclude_errorPDU */
static int hf_iec61850_vmdLogicalStatus;          /* T_vmdLogicalStatus */
static int hf_iec61850_vmdPhysicalStatus;         /* T_vmdPhysicalStatus */
static int hf_iec61850_localDetail;               /* BIT_STRING_SIZE_0_128 */
static int hf_iec61850_extendedObjectClass;       /* T_extendedObjectClass */
static int hf_iec61850_objectClass;               /* T_objectClass */
static int hf_iec61850_objectScope;               /* T_objectScope */
static int hf_iec61850_vmdSpecific;               /* NULL */
static int hf_iec61850_domainSpecific;            /* Identifier */
static int hf_iec61850_aaSpecific;                /* NULL */
static int hf_iec61850_getNameList_Request_continueAfter;  /* Identifier */
static int hf_iec61850_listOfIdentifier;          /* SEQUENCE_OF_Identifier */
static int hf_iec61850_listOfIdentifier_item;     /* Identifier */
static int hf_iec61850_moreFollows;               /* BOOLEAN */
static int hf_iec61850_vendorName;                /* VisibleString */
static int hf_iec61850_modelName;                 /* VisibleString */
static int hf_iec61850_revision;                  /* VisibleString */
static int hf_iec61850_listOfAbstractSyntaxes;    /* T_listOfAbstractSyntaxes */
static int hf_iec61850_listOfAbstractSyntaxes_item;  /* OBJECT_IDENTIFIER */
static int hf_iec61850_extendedObjectClass_01;    /* T_extendedObjectClass_01 */
static int hf_iec61850_objectClass_01;            /* T_objectClass_01 */
static int hf_iec61850_currentName;               /* ObjectName */
static int hf_iec61850_newIdentifier;             /* Identifier */
static int hf_iec61850_getCapabilityList_Request_continueAfter;  /* VisibleString */
static int hf_iec61850_listOfCapabilities;        /* T_listOfCapabilities */
static int hf_iec61850_listOfCapabilities_item;   /* VisibleString */
static int hf_iec61850_domainName;                /* Identifier */
static int hf_iec61850_listOfCapabilities_01;     /* T_listOfCapabilities_01 */
static int hf_iec61850_sharable;                  /* BOOLEAN */
static int hf_iec61850_loadData;                  /* T_loadData */
static int hf_iec61850_non_coded;                 /* OCTET_STRING */
static int hf_iec61850_coded;                     /* EXTERNALt */
static int hf_iec61850_discard;                   /* ServiceError */
static int hf_iec61850_ulsmID;                    /* Integer32 */
static int hf_iec61850_listOfCapabilities_02;     /* T_listOfCapabilities_02 */
static int hf_iec61850_loadData_01;               /* T_loadData_01 */
static int hf_iec61850_listOfCapabilities_03;     /* T_listOfCapabilities_03 */
static int hf_iec61850_fileName;                  /* FileName */
static int hf_iec61850_listOfCapabilities_04;     /* T_listOfCapabilities_04 */
static int hf_iec61850_thirdParty;                /* ApplicationReference */
static int hf_iec61850_filenName;                 /* FileName */
static int hf_iec61850_listOfCapabilities_05;     /* T_listOfCapabilities_05 */
static int hf_iec61850_getDomainAttributes_Response_state;  /* DomainState */
static int hf_iec61850_mmsDeletable;              /* BOOLEAN */
static int hf_iec61850_listOfProgramInvocations;  /* SEQUENCE_OF_Identifier */
static int hf_iec61850_listOfProgramInvocations_item;  /* Identifier */
static int hf_iec61850_uploadInProgress;          /* Integer8 */
static int hf_iec61850_listOfDomainName;          /* SEQUENCE_OF_Identifier */
static int hf_iec61850_listOfDomainName_item;     /* Identifier */
static int hf_iec61850_reusable;                  /* BOOLEAN */
static int hf_iec61850_monitorType;               /* BOOLEAN */
static int hf_iec61850_executionArgument;         /* T_executionArgument */
static int hf_iec61850_simpleString;              /* VisibleString */
static int hf_iec61850_encodedString;             /* EXTERNALt */
static int hf_iec61850_executionArgument_01;      /* T_executionArgument_01 */
static int hf_iec61850_getProgramInvocationAttributes_Response_state;  /* ProgramInvocationState */
static int hf_iec61850_listOfDomainNames;         /* SEQUENCE_OF_Identifier */
static int hf_iec61850_listOfDomainNames_item;    /* Identifier */
static int hf_iec61850_monitor;                   /* BOOLEAN */
static int hf_iec61850_startArgument;             /* VisibleString */
static int hf_iec61850_executionArgument_02;      /* T_executionArgument_02 */
static int hf_iec61850_typeName;                  /* ObjectName */
static int hf_iec61850_array;                     /* T_array */
static int hf_iec61850_packed;                    /* BOOLEAN */
static int hf_iec61850_numberOfElements;          /* Unsigned32 */
static int hf_iec61850_elementType;               /* TypeSpecification */
static int hf_iec61850_structure;                 /* T_structure */
static int hf_iec61850_components;                /* T_components */
static int hf_iec61850_components_item;           /* T_components_item */
static int hf_iec61850_componentName;             /* Identifier */
static int hf_iec61850_componentType;             /* TypeSpecification */
static int hf_iec61850_boolean;                   /* NULL */
static int hf_iec61850_typeSpecification_bit_string;  /* Integer32 */
static int hf_iec61850_integer;                   /* Unsigned8 */
static int hf_iec61850_unsigned;                  /* Unsigned8 */
static int hf_iec61850_typeSpecification_octet_string;  /* Integer32 */
static int hf_iec61850_typeSpecification_visible_string;  /* Integer32 */
static int hf_iec61850_generalized_time;          /* NULL */
static int hf_iec61850_typeSpecification_binary_time;  /* BOOLEAN */
static int hf_iec61850_bcd;                       /* Unsigned8 */
static int hf_iec61850_objId;                     /* NULL */
static int hf_iec61850_AlternateAccess_item;      /* AlternateAccess_item */
static int hf_iec61850_unnamed;                   /* AlternateAccessSelection */
static int hf_iec61850_named;                     /* T_named */
static int hf_iec61850_accesst;                   /* AlternateAccessSelection */
static int hf_iec61850_selectAlternateAccess;     /* T_selectAlternateAccess */
static int hf_iec61850_accessSelection;           /* T_accessSelection */
static int hf_iec61850_component;                 /* Identifier */
static int hf_iec61850_index;                     /* Unsigned32 */
static int hf_iec61850_indexRange;                /* T_indexRange */
static int hf_iec61850_lowIndex;                  /* Unsigned32 */
static int hf_iec61850_allElements;               /* NULL */
static int hf_iec61850_alternateAccess;           /* AlternateAccess */
static int hf_iec61850_selectAccess;              /* T_selectAccess */
static int hf_iec61850_indexRange_01;             /* T_indexRange_01 */
static int hf_iec61850_nmberOfElements;           /* Unsigned32 */
static int hf_iec61850_specificationWithResult;   /* BOOLEAN */
static int hf_iec61850_variableAccessSpecificatn;  /* VariableAccessSpecification */
static int hf_iec61850_listOfAccessResult;        /* SEQUENCE_OF_AccessResult */
static int hf_iec61850_listOfAccessResult_item;   /* AccessResult */
static int hf_iec61850_listOfData;                /* SEQUENCE_OF_Data */
static int hf_iec61850_listOfData_item;           /* Data */
static int hf_iec61850_Write_Response_item;       /* Write_Response_item */
static int hf_iec61850_failure;                   /* DataAccessError */
static int hf_iec61850_success;                   /* NULL */
static int hf_iec61850_variableAccessSpecification;  /* VariableAccessSpecification */
static int hf_iec61850_name;                      /* ObjectName */
static int hf_iec61850_address;                   /* Address */
static int hf_iec61850_typeSpecification;         /* TypeSpecification */
static int hf_iec61850_variableName;              /* ObjectName */
static int hf_iec61850_scatteredAccessName;       /* ObjectName */
static int hf_iec61850_scatteredAccessDescription;  /* ScatteredAccessDescription */
static int hf_iec61850_scopeOfDelete;             /* T_scopeOfDelete */
static int hf_iec61850_listOfName;                /* SEQUENCE_OF_ObjectName */
static int hf_iec61850_listOfName_item;           /* ObjectName */
static int hf_iec61850_numberMatched;             /* Unsigned32 */
static int hf_iec61850_numberDeleted;             /* Unsigned32 */
static int hf_iec61850_variableListName;          /* ObjectName */
static int hf_iec61850_listOfVariable;            /* T_listOfVariable */
static int hf_iec61850_listOfVariable_item;       /* T_listOfVariable_item */
static int hf_iec61850_variableSpecification;     /* VariableSpecification */
static int hf_iec61850_listOfVariable_01;         /* T_listOfVariable_01 */
static int hf_iec61850_listOfVariable_item_01;    /* T_listOfVariable_item_01 */
static int hf_iec61850_scopeOfDelete_01;          /* T_scopeOfDelete_01 */
static int hf_iec61850_listOfVariableListName;    /* SEQUENCE_OF_ObjectName */
static int hf_iec61850_listOfVariableListName_item;  /* ObjectName */
static int hf_iec61850_scopeOfDelete_02;          /* T_scopeOfDelete_02 */
static int hf_iec61850_listOfTypeName;            /* SEQUENCE_OF_ObjectName */
static int hf_iec61850_listOfTypeName_item;       /* ObjectName */
static int hf_iec61850_success_01;                /* Data */
static int hf_iec61850_array_01;                  /* T_array_01 */
static int hf_iec61850_array_item;                /* Data */
static int hf_iec61850_structure_01;              /* T_structure_01 */
static int hf_iec61850_structure_item;            /* Data */
static int hf_iec61850_boolean_01;                /* T_boolean */
static int hf_iec61850_data_bit_string;           /* T_data_bit_string */
static int hf_iec61850_integer_01;                /* T_integer */
static int hf_iec61850_unsigned_01;               /* T_unsigned */
static int hf_iec61850_floating_point;            /* FloatingPoint */
static int hf_iec61850_data_octet_string;         /* T_data_octet_string */
static int hf_iec61850_data_visible_string;       /* T_data_visible_string */
static int hf_iec61850_data_binary_time;          /* TimeOfDay */
static int hf_iec61850_bcd_01;                    /* T_bcd */
static int hf_iec61850_booleanArray;              /* BIT_STRING */
static int hf_iec61850_objId_01;                  /* OBJECT_IDENTIFIER */
static int hf_iec61850_mMSString;                 /* MMSString */
static int hf_iec61850_utc_time;                  /* UtcTime */
static int hf_iec61850_listOfVariable_02;         /* T_listOfVariable_02 */
static int hf_iec61850_listOfVariable_item_02;    /* T_listOfVariable_item_02 */
static int hf_iec61850_ScatteredAccessDescription_item;  /* ScatteredAccessDescription_item */
static int hf_iec61850_variableDescription;       /* T_variableDescription */
static int hf_iec61850_invalidated;               /* NULL */
static int hf_iec61850_numericAddress;            /* Unsigned32 */
static int hf_iec61850_symbolicAddress;           /* VisibleString */
static int hf_iec61850_unconstrainedAddress;      /* OCTET_STRING */
static int hf_iec61850_semaphoreName;             /* ObjectName */
static int hf_iec61850_namedToken;                /* Identifier */
static int hf_iec61850_priority;                  /* Priority */
static int hf_iec61850_acceptableDelay;           /* Unsigned32 */
static int hf_iec61850_controlTimeOut;            /* Unsigned32 */
static int hf_iec61850_abortOnTimeOut;            /* BOOLEAN */
static int hf_iec61850_relinquishIfConnectionLost;  /* BOOLEAN */
static int hf_iec61850_applicationToPreempt;      /* ApplicationReference */
static int hf_iec61850_noResult;                  /* NULL */
static int hf_iec61850_numbersOfTokens;           /* Unsigned16 */
static int hf_iec61850_class;                     /* T_class */
static int hf_iec61850_numberOfTokens;            /* Unsigned16 */
static int hf_iec61850_numberOfOwnedTokens;       /* Unsigned16 */
static int hf_iec61850_numberOfHungTokens;        /* Unsigned16 */
static int hf_iec61850_nameToStartAfter;          /* Identifier */
static int hf_iec61850_listOfNamedTokens;         /* T_listOfNamedTokens */
static int hf_iec61850_listOfNamedTokens_item;    /* T_listOfNamedTokens_item */
static int hf_iec61850_freeNamedToken;            /* Identifier */
static int hf_iec61850_ownedNamedToken;           /* Identifier */
static int hf_iec61850_hungNamedToken;            /* Identifier */
static int hf_iec61850_reportSemaphoreEntryStatus_Request_state;  /* T_reportSemaphoreEntryStatus_Request_state */
static int hf_iec61850_entryIdToStartAfter;       /* OCTET_STRING */
static int hf_iec61850_listOfSemaphoreEntry;      /* SEQUENCE_OF_SemaphoreEntry */
static int hf_iec61850_listOfSemaphoreEntry_item;  /* SemaphoreEntry */
static int hf_iec61850_entryId;                   /* OCTET_STRING */
static int hf_iec61850_entryClass;                /* T_entryClass */
static int hf_iec61850_applicationReference;      /* ApplicationReference */
static int hf_iec61850_remainingTimeOut;          /* Unsigned32 */
static int hf_iec61850_operatorStationName;       /* Identifier */
static int hf_iec61850_echo;                      /* BOOLEAN */
static int hf_iec61850_listOfPromptData;          /* T_listOfPromptData */
static int hf_iec61850_listOfPromptData_item;     /* VisibleString */
static int hf_iec61850_inputTimeOut;              /* Unsigned32 */
static int hf_iec61850_listOfOutputData;          /* T_listOfOutputData */
static int hf_iec61850_listOfOutputData_item;     /* VisibleString */
static int hf_iec61850_eventConditionName;        /* ObjectName */
static int hf_iec61850_class_01;                  /* EC_Class */
static int hf_iec61850_prio_rity;                 /* Priority */
static int hf_iec61850_severity;                  /* Unsigned8 */
static int hf_iec61850_alarmSummaryReports;       /* BOOLEAN */
static int hf_iec61850_monitoredVariable;         /* VariableSpecification */
static int hf_iec61850_evaluationInterval;        /* Unsigned32 */
static int hf_iec61850_specific;                  /* SEQUENCE_OF_ObjectName */
static int hf_iec61850_specific_item;             /* ObjectName */
static int hf_iec61850_aa_specific_01;            /* NULL */
static int hf_iec61850_vmd;                       /* NULL */
static int hf_iec61850_monitoredVariable_01;      /* T_monitoredVariable */
static int hf_iec61850_variableReference;         /* VariableSpecification */
static int hf_iec61850_undefined;                 /* NULL */
static int hf_iec61850_currentState;              /* EC_State */
static int hf_iec61850_numberOfEventEnrollments;  /* Unsigned32 */
static int hf_iec61850_enabled;                   /* BOOLEAN */
static int hf_iec61850_timeOfLastTransitionToActive;  /* EventTime */
static int hf_iec61850_timeOfLastTransitionToIdle;  /* EventTime */
static int hf_iec61850_eventActionName;           /* ObjectName */
static int hf_iec61850_eventEnrollmentName;       /* ObjectName */
static int hf_iec61850_eventConditionTransition;  /* Transitions */
static int hf_iec61850_alarmAcknowledgementRule;  /* AlarmAckRule */
static int hf_iec61850_clientApplication;         /* ApplicationReference */
static int hf_iec61850_ec;                        /* ObjectName */
static int hf_iec61850_ea;                        /* ObjectName */
static int hf_iec61850_scopeOfRequest;            /* T_scopeOfRequest */
static int hf_iec61850_eventEnrollmentNames;      /* SEQUENCE_OF_ObjectName */
static int hf_iec61850_eventEnrollmentNames_item;  /* ObjectName */
static int hf_iec61850_getEventEnrollmentAttributes_Request_continueAfter;  /* ObjectName */
static int hf_iec61850_eventConditionName_01;     /* T_eventConditionName */
static int hf_iec61850_eventActionName_01;        /* T_eventActionName */
static int hf_iec61850_eventAction;               /* ObjectName */
static int hf_iec61850_enrollmentClass;           /* EE_Class */
static int hf_iec61850_duration;                  /* EE_Duration */
static int hf_iec61850_remainingAcceptableDelay;  /* Unsigned32 */
static int hf_iec61850_listOfEventEnrollment;     /* SEQUENCE_OF_EventEnrollment */
static int hf_iec61850_listOfEventEnrollment_item;  /* EventEnrollment */
static int hf_iec61850_eventConditionTransitions;  /* Transitions */
static int hf_iec61850_notificationLost;          /* BOOLEAN */
static int hf_iec61850_alarmAcknowledgmentRule;   /* AlarmAckRule */
static int hf_iec61850_currentState_01;           /* EE_State */
static int hf_iec61850_currentState_02;           /* T_currentState */
static int hf_iec61850_alterEventEnrollment_Response_currentState_state;  /* EE_State */
static int hf_iec61850_transitionTime;            /* EventTime */
static int hf_iec61850_acknowledgedState;         /* EC_State */
static int hf_iec61850_timeOfAcknowledgedTransition;  /* EventTime */
static int hf_iec61850_enrollmentsOnly;           /* BOOLEAN */
static int hf_iec61850_activeAlarmsOnly;          /* BOOLEAN */
static int hf_iec61850_acknowledgmentFilter;      /* T_acknowledgmentFilter */
static int hf_iec61850_severityFilter;            /* T_severityFilter */
static int hf_iec61850_mostSevere;                /* Unsigned8 */
static int hf_iec61850_leastSevere;               /* Unsigned8 */
static int hf_iec61850_continueAfter;             /* ObjectName */
static int hf_iec61850_listOfAlarmSummary;        /* SEQUENCE_OF_AlarmSummary */
static int hf_iec61850_listOfAlarmSummary_item;   /* AlarmSummary */
static int hf_iec61850_unacknowledgedState;       /* T_unacknowledgedState */
static int hf_iec61850_acknowledgmentFilter_01;   /* T_acknowledgmentFilter_01 */
static int hf_iec61850_severityFilter_01;         /* T_severityFilter_01 */
static int hf_iec61850_getAlarmEnrollmentSummary_Request_continueAfter;  /* ObjectName */
static int hf_iec61850_listOfAlarmEnrollmentSummary;  /* SEQUENCE_OF_AlarmEnrollmentSummary */
static int hf_iec61850_listOfAlarmEnrollmentSummary_item;  /* AlarmEnrollmentSummary */
static int hf_iec61850_enrollementState;          /* EE_State */
static int hf_iec61850_timeActiveAcknowledged;    /* EventTime */
static int hf_iec61850_timeIdleAcknowledged;      /* EventTime */
static int hf_iec61850_eventConditionName_02;     /* T_eventConditionName_01 */
static int hf_iec61850_actionResult;              /* T_actionResult */
static int hf_iec61850_eventActioName;            /* ObjectName */
static int hf_iec61850_eventActionResult;         /* T_eventActionResult */
static int hf_iec61850_success_02;                /* ConfirmedServiceResponse */
static int hf_iec61850_failure_01;                /* ServiceError */
static int hf_iec61850_causingTransitions;        /* Transitions */
static int hf_iec61850_timeOfDayT;                /* TimeOfDay */
static int hf_iec61850_timeSequenceIdentifier;    /* Unsigned32 */
static int hf_iec61850_journalName;               /* ObjectName */
static int hf_iec61850_rangeStartSpecification;   /* T_rangeStartSpecification */
static int hf_iec61850_startingTime;              /* TimeOfDay */
static int hf_iec61850_startingEntry;             /* OCTET_STRING */
static int hf_iec61850_rangeStopSpecification;    /* T_rangeStopSpecification */
static int hf_iec61850_endingTime;                /* TimeOfDay */
static int hf_iec61850_numberOfEntries;           /* Integer32 */
static int hf_iec61850_listOfVariables;           /* T_listOfVariables */
static int hf_iec61850_listOfVariables_item;      /* VisibleString */
static int hf_iec61850_entryToStartAfter;         /* T_entryToStartAfter */
static int hf_iec61850_timeSpecification;         /* TimeOfDay */
static int hf_iec61850_entrySpecification;        /* OCTET_STRING */
static int hf_iec61850_listOfJournalEntry;        /* SEQUENCE_OF_JournalEntry */
static int hf_iec61850_listOfJournalEntry_item;   /* JournalEntry */
static int hf_iec61850_entryIdentifier;           /* OCTET_STRING */
static int hf_iec61850_originatingApplication;    /* ApplicationReference */
static int hf_iec61850_entryContent;              /* EntryContent */
static int hf_iec61850_listOfJournalEntry_01;     /* SEQUENCE_OF_EntryContent */
static int hf_iec61850_listOfJournalEntry_item_01;  /* EntryContent */
static int hf_iec61850_limitSpecification;        /* T_limitSpecification */
static int hf_iec61850_limitingTime;              /* TimeOfDay */
static int hf_iec61850_limitingEntry;             /* OCTET_STRING */
static int hf_iec61850_currentEntries;            /* Unsigned32 */
static int hf_iec61850_occurenceTime;             /* TimeOfDay */
static int hf_iec61850_additionalDetail;          /* JOU_Additional_Detail */
static int hf_iec61850_entryForm;                 /* T_entryForm */
static int hf_iec61850_data;                      /* T_data */
static int hf_iec61850_event;                     /* T_event */
static int hf_iec61850_listOfVariables_01;        /* T_listOfVariables_01 */
static int hf_iec61850_listOfVariables_item_01;   /* T_listOfVariables_item */
static int hf_iec61850_variableTag;               /* VisibleString */
static int hf_iec61850_valueSpecification;        /* Data */
static int hf_iec61850_annotation;                /* VisibleString */
static int hf_iec61850_sourceFileServer;          /* ApplicationReference */
static int hf_iec61850_sourceFile;                /* FileName */
static int hf_iec61850_destinationFile;           /* FileName */
static int hf_iec61850_initialPosition;           /* Unsigned32 */
static int hf_iec61850_frsmID;                    /* Integer32 */
static int hf_iec61850_fileAttributes;            /* FileAttributes */
static int hf_iec61850_fileData;                  /* OCTET_STRING */
static int hf_iec61850_currentFileName;           /* FileName */
static int hf_iec61850_newFileName;               /* FileName */
static int hf_iec61850_fileSpecification;         /* FileName */
static int hf_iec61850_fileDirectory_Request_continueAfter;  /* FileName */
static int hf_iec61850_listOfDirectoryEntry;      /* SEQUENCE_OF_DirectoryEntry */
static int hf_iec61850_listOfDirectoryEntry_item;  /* DirectoryEntry */
static int hf_iec61850_filename;                  /* FileName */
static int hf_iec61850_sizeOfFile;                /* Unsigned32 */
static int hf_iec61850_lastModified;              /* GeneralizedTime */
/* named bits */
static int hf_iec61850_ParameterSupportOptions_str1;
static int hf_iec61850_ParameterSupportOptions_str2;
static int hf_iec61850_ParameterSupportOptions_vnam;
static int hf_iec61850_ParameterSupportOptions_valt;
static int hf_iec61850_ParameterSupportOptions_vadr;
static int hf_iec61850_ParameterSupportOptions_vsca;
static int hf_iec61850_ParameterSupportOptions_tpy;
static int hf_iec61850_ParameterSupportOptions_vlis;
static int hf_iec61850_ParameterSupportOptions_real;
static int hf_iec61850_ParameterSupportOptions_spare_bit9;
static int hf_iec61850_ParameterSupportOptions_cei;
static int hf_iec61850_ServiceSupportOptions_status;
static int hf_iec61850_ServiceSupportOptions_getNameList;
static int hf_iec61850_ServiceSupportOptions_identify;
static int hf_iec61850_ServiceSupportOptions_rename;
static int hf_iec61850_ServiceSupportOptions_read;
static int hf_iec61850_ServiceSupportOptions_write;
static int hf_iec61850_ServiceSupportOptions_getVariableAccessAttributes;
static int hf_iec61850_ServiceSupportOptions_defineNamedVariable;
static int hf_iec61850_ServiceSupportOptions_defineScatteredAccess;
static int hf_iec61850_ServiceSupportOptions_getScatteredAccessAttributes;
static int hf_iec61850_ServiceSupportOptions_deleteVariableAccess;
static int hf_iec61850_ServiceSupportOptions_defineNamedVariableList;
static int hf_iec61850_ServiceSupportOptions_getNamedVariableListAttributes;
static int hf_iec61850_ServiceSupportOptions_deleteNamedVariableList;
static int hf_iec61850_ServiceSupportOptions_defineNamedType;
static int hf_iec61850_ServiceSupportOptions_getNamedTypeAttributes;
static int hf_iec61850_ServiceSupportOptions_deleteNamedType;
static int hf_iec61850_ServiceSupportOptions_input;
static int hf_iec61850_ServiceSupportOptions_output;
static int hf_iec61850_ServiceSupportOptions_takeControl;
static int hf_iec61850_ServiceSupportOptions_relinquishControl;
static int hf_iec61850_ServiceSupportOptions_defineSemaphore;
static int hf_iec61850_ServiceSupportOptions_deleteSemaphore;
static int hf_iec61850_ServiceSupportOptions_reportSemaphoreStatus;
static int hf_iec61850_ServiceSupportOptions_reportPoolSemaphoreStatus;
static int hf_iec61850_ServiceSupportOptions_reportSemaphoreEntryStatus;
static int hf_iec61850_ServiceSupportOptions_initiateDownloadSequence;
static int hf_iec61850_ServiceSupportOptions_downloadSegment;
static int hf_iec61850_ServiceSupportOptions_terminateDownloadSequence;
static int hf_iec61850_ServiceSupportOptions_initiateUploadSequence;
static int hf_iec61850_ServiceSupportOptions_uploadSegment;
static int hf_iec61850_ServiceSupportOptions_terminateUploadSequence;
static int hf_iec61850_ServiceSupportOptions_requestDomainDownload;
static int hf_iec61850_ServiceSupportOptions_requestDomainUpload;
static int hf_iec61850_ServiceSupportOptions_loadDomainContent;
static int hf_iec61850_ServiceSupportOptions_storeDomainContent;
static int hf_iec61850_ServiceSupportOptions_deleteDomain;
static int hf_iec61850_ServiceSupportOptions_getDomainAttributes;
static int hf_iec61850_ServiceSupportOptions_createProgramInvocation;
static int hf_iec61850_ServiceSupportOptions_deleteProgramInvocation;
static int hf_iec61850_ServiceSupportOptions_start;
static int hf_iec61850_ServiceSupportOptions_stop;
static int hf_iec61850_ServiceSupportOptions_resume;
static int hf_iec61850_ServiceSupportOptions_reset;
static int hf_iec61850_ServiceSupportOptions_kill;
static int hf_iec61850_ServiceSupportOptions_getProgramInvocationAttributes;
static int hf_iec61850_ServiceSupportOptions_obtainFile;
static int hf_iec61850_ServiceSupportOptions_defineEventCondition;
static int hf_iec61850_ServiceSupportOptions_deleteEventCondition;
static int hf_iec61850_ServiceSupportOptions_getEventConditionAttributes;
static int hf_iec61850_ServiceSupportOptions_reportEventConditionStatus;
static int hf_iec61850_ServiceSupportOptions_alterEventConditionMonitoring;
static int hf_iec61850_ServiceSupportOptions_triggerEvent;
static int hf_iec61850_ServiceSupportOptions_defineEventAction;
static int hf_iec61850_ServiceSupportOptions_deleteEventAction;
static int hf_iec61850_ServiceSupportOptions_getEventActionAttributes;
static int hf_iec61850_ServiceSupportOptions_reportActionStatus;
static int hf_iec61850_ServiceSupportOptions_defineEventEnrollment;
static int hf_iec61850_ServiceSupportOptions_deleteEventEnrollment;
static int hf_iec61850_ServiceSupportOptions_alterEventEnrollment;
static int hf_iec61850_ServiceSupportOptions_reportEventEnrollmentStatus;
static int hf_iec61850_ServiceSupportOptions_getEventEnrollmentAttributes;
static int hf_iec61850_ServiceSupportOptions_acknowledgeEventNotification;
static int hf_iec61850_ServiceSupportOptions_getAlarmSummary;
static int hf_iec61850_ServiceSupportOptions_getAlarmEnrollmentSummary;
static int hf_iec61850_ServiceSupportOptions_readJournal;
static int hf_iec61850_ServiceSupportOptions_writeJournal;
static int hf_iec61850_ServiceSupportOptions_initializeJournal;
static int hf_iec61850_ServiceSupportOptions_reportJournalStatus;
static int hf_iec61850_ServiceSupportOptions_createJournal;
static int hf_iec61850_ServiceSupportOptions_deleteJournal;
static int hf_iec61850_ServiceSupportOptions_getCapabilityList;
static int hf_iec61850_ServiceSupportOptions_fileOpen;
static int hf_iec61850_ServiceSupportOptions_fileRead;
static int hf_iec61850_ServiceSupportOptions_fileClose;
static int hf_iec61850_ServiceSupportOptions_fileRename;
static int hf_iec61850_ServiceSupportOptions_fileDelete;
static int hf_iec61850_ServiceSupportOptions_fileDirectory;
static int hf_iec61850_ServiceSupportOptions_unsolicitedStatus;
static int hf_iec61850_ServiceSupportOptions_informationReport;
static int hf_iec61850_ServiceSupportOptions_eventNotification;
static int hf_iec61850_ServiceSupportOptions_attachToEventCondition;
static int hf_iec61850_ServiceSupportOptions_attachToSemaphore;
static int hf_iec61850_ServiceSupportOptions_conclude;
static int hf_iec61850_ServiceSupportOptions_cancel;
static int hf_iec61850_Transitions_idle_to_disabled;
static int hf_iec61850_Transitions_active_to_disabled;
static int hf_iec61850_Transitions_disabled_to_idle;
static int hf_iec61850_Transitions_active_to_idle;
static int hf_iec61850_Transitions_disabled_to_active;
static int hf_iec61850_Transitions_idle_to_active;
static int hf_iec61850_Transitions_any_to_deleted;

/* Initialize the subtree pointers */
static gint ettmms = -1;
static gint ett_iec61850_MMSpdu;
static gint ett_iec61850_Confirmed_RequestPDU;
static gint ett_iec61850_SEQUENCE_OF_Modifier;
static gint ett_iec61850_Unconfirmed_PDU;
static gint ett_iec61850_Confirmed_ResponsePDU;
static gint ett_iec61850_Confirmed_ErrorPDU;
static gint ett_iec61850_UnconfirmedService;
static gint ett_iec61850_Modifier;
static gint ett_iec61850_ConfirmedServiceRequest;
static gint ett_iec61850_CS_Request_Detail;
static gint ett_iec61850_ConfirmedServiceResponse;
static gint ett_iec61850_FileName;
static gint ett_iec61850_ObjectName;
static gint ett_iec61850_T_domain_specific;
static gint ett_iec61850_ApplicationReference;
static gint ett_iec61850_Initiate_RequestPDU;
static gint ett_iec61850_InitRequestDetail;
static gint ett_iec61850_Initiate_ResponsePDU;
static gint ett_iec61850_InitResponseDetail;
static gint ett_iec61850_ParameterSupportOptions;
static gint ett_iec61850_ServiceSupportOptions;
static gint ett_iec61850_Cancel_ErrorPDU;
static gint ett_iec61850_ServiceError;
static gint ett_iec61850_T_errorClass;
static gint ett_iec61850_T_serviceSpecificInformation;
static gint ett_iec61850_AdditionalService_Error;
static gint ett_iec61850_RemoveEventConditionListReference_Error;
static gint ett_iec61850_InitiateUnitControl_Error;
static gint ett_iec61850_StartUnitControl_Error;
static gint ett_iec61850_StopUnitControl_Error;
static gint ett_iec61850_DeleteUnitControl_Error;
static gint ett_iec61850_LoadUnitControlFromFile_Error;
static gint ett_iec61850_RejectPDU;
static gint ett_iec61850_T_rejectReason;
static gint ett_iec61850_Status_Response;
static gint ett_iec61850_GetNameList_Request;
static gint ett_iec61850_T_extendedObjectClass;
static gint ett_iec61850_T_objectScope;
static gint ett_iec61850_GetNameList_Response;
static gint ett_iec61850_SEQUENCE_OF_Identifier;
static gint ett_iec61850_Identify_Response;
static gint ett_iec61850_T_listOfAbstractSyntaxes;
static gint ett_iec61850_Rename_Request;
static gint ett_iec61850_T_extendedObjectClass_01;
static gint ett_iec61850_GetCapabilityList_Request;
static gint ett_iec61850_GetCapabilityList_Response;
static gint ett_iec61850_T_listOfCapabilities;
static gint ett_iec61850_InitiateDownloadSequence_Request;
static gint ett_iec61850_T_listOfCapabilities_01;
static gint ett_iec61850_DownloadSegment_Response;
static gint ett_iec61850_T_loadData;
static gint ett_iec61850_TerminateDownloadSequence_Request;
static gint ett_iec61850_InitiateUploadSequence_Response;
static gint ett_iec61850_T_listOfCapabilities_02;
static gint ett_iec61850_UploadSegment_Response;
static gint ett_iec61850_T_loadData_01;
static gint ett_iec61850_RequestDomainDownload_Request;
static gint ett_iec61850_T_listOfCapabilities_03;
static gint ett_iec61850_RequestDomainUpload_Request;
static gint ett_iec61850_LoadDomainContent_Request;
static gint ett_iec61850_T_listOfCapabilities_04;
static gint ett_iec61850_StoreDomainContent_Request;
static gint ett_iec61850_GetDomainAttributes_Response;
static gint ett_iec61850_T_listOfCapabilities_05;
static gint ett_iec61850_CreateProgramInvocation_Request;
static gint ett_iec61850_Start_Request;
static gint ett_iec61850_T_executionArgument;
static gint ett_iec61850_Stop_Request;
static gint ett_iec61850_Resume_Request;
static gint ett_iec61850_T_executionArgument_01;
static gint ett_iec61850_Reset_Request;
static gint ett_iec61850_Kill_Request;
static gint ett_iec61850_GetProgramInvocationAttributes_Response;
static gint ett_iec61850_T_executionArgument_02;
static gint ett_iec61850_TypeSpecification;
static gint ett_iec61850_T_array;
static gint ett_iec61850_T_structure;
static gint ett_iec61850_T_components;
static gint ett_iec61850_T_components_item;
static gint ett_iec61850_AlternateAccess;
static gint ett_iec61850_AlternateAccess_item;
static gint ett_iec61850_T_named;
static gint ett_iec61850_AlternateAccessSelection;
static gint ett_iec61850_T_selectAlternateAccess;
static gint ett_iec61850_T_accessSelection;
static gint ett_iec61850_T_indexRange;
static gint ett_iec61850_T_selectAccess;
static gint ett_iec61850_T_indexRange_01;
static gint ett_iec61850_Read_Request;
static gint ett_iec61850_Read_Response;
static gint ett_iec61850_SEQUENCE_OF_AccessResult;
static gint ett_iec61850_Write_Request;
static gint ett_iec61850_SEQUENCE_OF_Data;
static gint ett_iec61850_Write_Response;
static gint ett_iec61850_Write_Response_item;
static gint ett_iec61850_InformationReport;
static gint ett_iec61850_GetVariableAccessAttributes_Request;
static gint ett_iec61850_GetVariableAccessAttributes_Response;
static gint ett_iec61850_DefineNamedVariable_Request;
static gint ett_iec61850_DefineScatteredAccess_Request;
static gint ett_iec61850_GetScatteredAccessAttributes_Response;
static gint ett_iec61850_DeleteVariableAccess_Request;
static gint ett_iec61850_SEQUENCE_OF_ObjectName;
static gint ett_iec61850_DeleteVariableAccess_Response;
static gint ett_iec61850_DefineNamedVariableList_Request;
static gint ett_iec61850_T_listOfVariable;
static gint ett_iec61850_T_listOfVariable_item;
static gint ett_iec61850_GetNamedVariableListAttributes_Response;
static gint ett_iec61850_T_listOfVariable_01;
static gint ett_iec61850_T_listOfVariable_item_01;
static gint ett_iec61850_DeleteNamedVariableList_Request;
static gint ett_iec61850_DeleteNamedVariableList_Response;
static gint ett_iec61850_DefineNamedType_Request;
static gint ett_iec61850_GetNamedTypeAttributes_Response;
static gint ett_iec61850_DeleteNamedType_Request;
static gint ett_iec61850_DeleteNamedType_Response;
static gint ett_iec61850_AccessResult;
static gint ett_iec61850_Data;
static gint ett_iec61850_T_array_01;
static gint ett_iec61850_T_structure_01;
static gint ett_iec61850_VariableAccessSpecification;
static gint ett_iec61850_T_listOfVariable_02;
static gint ett_iec61850_T_listOfVariable_item_02;
static gint ett_iec61850_ScatteredAccessDescription;
static gint ett_iec61850_ScatteredAccessDescription_item;
static gint ett_iec61850_VariableSpecification;
static gint ett_iec61850_T_variableDescription;
static gint ett_iec61850_Address;
static gint ett_iec61850_TakeControl_Request;
static gint ett_iec61850_TakeControl_Response;
static gint ett_iec61850_RelinquishControl_Request;
static gint ett_iec61850_DefineSemaphore_Request;
static gint ett_iec61850_ReportSemaphoreStatus_Response;
static gint ett_iec61850_ReportPoolSemaphoreStatus_Request;
static gint ett_iec61850_ReportPoolSemaphoreStatus_Response;
static gint ett_iec61850_T_listOfNamedTokens;
static gint ett_iec61850_T_listOfNamedTokens_item;
static gint ett_iec61850_ReportSemaphoreEntryStatus_Request;
static gint ett_iec61850_ReportSemaphoreEntryStatus_Response;
static gint ett_iec61850_SEQUENCE_OF_SemaphoreEntry;
static gint ett_iec61850_AttachToSemaphore;
static gint ett_iec61850_SemaphoreEntry;
static gint ett_iec61850_Input_Request;
static gint ett_iec61850_T_listOfPromptData;
static gint ett_iec61850_Output_Request;
static gint ett_iec61850_T_listOfOutputData;
static gint ett_iec61850_DefineEventCondition_Request;
static gint ett_iec61850_DeleteEventCondition_Request;
static gint ett_iec61850_GetEventConditionAttributes_Response;
static gint ett_iec61850_T_monitoredVariable;
static gint ett_iec61850_ReportEventConditionStatus_Response;
static gint ett_iec61850_AlterEventConditionMonitoring_Request;
static gint ett_iec61850_TriggerEvent_Request;
static gint ett_iec61850_DefineEventAction_Request;
static gint ett_iec61850_DeleteEventAction_Request;
static gint ett_iec61850_GetEventActionAttributes_Response;
static gint ett_iec61850_DefineEventEnrollment_Request;
static gint ett_iec61850_DeleteEventEnrollment_Request;
static gint ett_iec61850_GetEventEnrollmentAttributes_Request;
static gint ett_iec61850_EventEnrollment;
static gint ett_iec61850_T_eventConditionName;
static gint ett_iec61850_T_eventActionName;
static gint ett_iec61850_GetEventEnrollmentAttributes_Response;
static gint ett_iec61850_SEQUENCE_OF_EventEnrollment;
static gint ett_iec61850_ReportEventEnrollmentStatus_Response;
static gint ett_iec61850_AlterEventEnrollment_Request;
static gint ett_iec61850_AlterEventEnrollment_Response;
static gint ett_iec61850_T_currentState;
static gint ett_iec61850_AcknowledgeEventNotification_Request;
static gint ett_iec61850_GetAlarmSummary_Request;
static gint ett_iec61850_T_severityFilter;
static gint ett_iec61850_GetAlarmSummary_Response;
static gint ett_iec61850_SEQUENCE_OF_AlarmSummary;
static gint ett_iec61850_AlarmSummary;
static gint ett_iec61850_GetAlarmEnrollmentSummary_Request;
static gint ett_iec61850_T_severityFilter_01;
static gint ett_iec61850_GetAlarmEnrollmentSummary_Response;
static gint ett_iec61850_SEQUENCE_OF_AlarmEnrollmentSummary;
static gint ett_iec61850_AlarmEnrollmentSummary;
static gint ett_iec61850_EventNotification;
static gint ett_iec61850_T_eventConditionName_01;
static gint ett_iec61850_T_actionResult;
static gint ett_iec61850_T_eventActionResult;
static gint ett_iec61850_AttachToEventCondition;
static gint ett_iec61850_EventTime;
static gint ett_iec61850_Transitions;
static gint ett_iec61850_ReadJournal_Request;
static gint ett_iec61850_T_rangeStartSpecification;
static gint ett_iec61850_T_rangeStopSpecification;
static gint ett_iec61850_T_listOfVariables;
static gint ett_iec61850_T_entryToStartAfter;
static gint ett_iec61850_ReadJournal_Response;
static gint ett_iec61850_SEQUENCE_OF_JournalEntry;
static gint ett_iec61850_JournalEntry;
static gint ett_iec61850_WriteJournal_Request;
static gint ett_iec61850_SEQUENCE_OF_EntryContent;
static gint ett_iec61850_InitializeJournal_Request;
static gint ett_iec61850_T_limitSpecification;
static gint ett_iec61850_ReportJournalStatus_Response;
static gint ett_iec61850_CreateJournal_Request;
static gint ett_iec61850_DeleteJournal_Request;
static gint ett_iec61850_EntryContent;
static gint ett_iec61850_T_entryForm;
static gint ett_iec61850_T_data;
static gint ett_iec61850_T_event;
static gint ett_iec61850_T_listOfVariables_01;
static gint ett_iec61850_T_listOfVariables_item;
static gint ett_iec61850_ObtainFile_Request;
static gint ett_iec61850_FileOpen_Request;
static gint ett_iec61850_FileOpen_Response;
static gint ett_iec61850_FileRead_Response;
static gint ett_iec61850_FileRename_Request;
static gint ett_iec61850_FileDirectory_Request;
static gint ett_iec61850_FileDirectory_Response;
static gint ett_iec61850_SEQUENCE_OF_DirectoryEntry;
static gint ett_iec61850_DirectoryEntry;
static gint ett_iec61850_FileAttributes;

static expert_field ei_iec61850_mal_timeofday_encoding = EI_INIT;
static expert_field ei_iec61850_mal_utctime_encoding = EI_INIT;
static expert_field ei_mms_zero_pdu = EI_INIT;

static int32_t use_iec61850_mapping = TRUE;

static void proto_update_iec61850_settings(void);
static int32_t dissect_acse_EXTERNALt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int32_t offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int32_t hf_index _U_) {  return offset; }
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
private_data_add_preCinfo(asn1_ctx_t *actx, uint32_t val)
{
    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    snprintf(private_data->preCinfo, IEC61850_BUFFER_SIZE_PRE, "%02d ", val);
    private_data->invokeID = val;
}

uint8_t*
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
    uint8_t *tmp = wmem_alloc0(pinfo->pool, IEC61850_BUFFER_SIZE_MORE );

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    snprintf(tmp, IEC61850_BUFFER_SIZE_MORE, "%f", tvb_get_ieee_float(tvb, 1, ENC_BIG_ENDIAN));

    (void) g_strlcat(private_data->moreCinfo, tmp, IEC61850_BUFFER_SIZE_MORE);
    (void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_int(asn1_ctx_t *actx, int32_t val)
{
    packet_info *pinfo = actx->pinfo;
    uint8_t *tmp = wmem_alloc0(pinfo->pool, IEC61850_BUFFER_SIZE_MORE );

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    snprintf(tmp, IEC61850_BUFFER_SIZE_MORE,"%i", val);
    (void) g_strlcat(private_data->moreCinfo, tmp, IEC61850_BUFFER_SIZE_MORE);			
    (void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_str(asn1_ctx_t *actx, uint8_t* str)
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

int32_t iec61850_octetstring_is_text(uint8_t * str)
{
    size_t i;
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
    size_t i;
    uint8_t temp[4] = "";
    uint8_t * ostr = NULL;
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

        if(iec61850_octetstring_is_text(ostr) == TRUE)
        {
            (void) g_strlcat(private_data->moreCinfo, "( ", IEC61850_BUFFER_SIZE_MORE);
            (void) g_strlcat(private_data->moreCinfo, ostr, IEC61850_BUFFER_SIZE_MORE);
            (void) g_strlcat(private_data->moreCinfo, " )", IEC61850_BUFFER_SIZE_MORE);
        }
        (void) g_strlcat(private_data->moreCinfo, " ", IEC61850_BUFFER_SIZE_MORE);
    }
    else
    {
        (void) g_strlcat(private_data->moreCinfo, "'' ", IEC61850_BUFFER_SIZE_MORE);
    }
}

uint32_t iec61850_print_bytes(wmem_strbuf_t *strbuf, const uint8_t *bitstring, size_t bytelen, uint32_t padding)
{
    uint32_t count = 0;
    uint8_t byte;
    int32_t j, end;
    size_t i;

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
private_data_add_moreCinfo_bstr(asn1_ctx_t *actx,tvbuff_t * tvb, int32_t offset _U_)
{
    wmem_strbuf_t *strbuf;
    uint8_t *bitstring;
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
    uint32_t padding = tvb_get_guint8(tvb, 0);
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


uint8_t*
iec61850_private_data_get_moreCinfo(asn1_ctx_t *actx)
{
    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    return private_data->moreCinfo;
}

/*****************************************************************************/


/*--- Cyclic dependencies ---*/

/* TypeSpecification -> TypeSpecification/array -> TypeSpecification */
/* TypeSpecification -> TypeSpecification/structure -> TypeSpecification/structure/components -> TypeSpecification/structure/components/_item -> TypeSpecification */
static int dissect_iec61850_TypeSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* VariableSpecification -> ScatteredAccessDescription -> ScatteredAccessDescription/_item -> VariableSpecification */
static int dissect_iec61850_VariableSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* AlternateAccess -> AlternateAccess/_item -> AlternateAccessSelection -> AlternateAccessSelection/selectAlternateAccess -> AlternateAccess */
static int dissect_iec61850_AlternateAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* Data -> Data/array -> Data */
/* Data -> Data/structure -> Data */
static int dissect_iec61850_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


#define MAX_RECURSION_DEPTH 100 // Arbitrarily chosen.


static int
dissect_iec61850_Unsigned32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t val;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &val);

    if (hf_index == hf_iec61850_invokeID)
    {
        private_data_add_preCinfo(actx, val);
    }


  return offset;
}



static int
dissect_iec61850_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t offset_id = offset;
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                              actx, tree, tvb, offset, hf_index,
                                              NULL);

    if (tvb_get_guint8(tvb, offset_id) == 0x1a)
    {
        if (hf_index == hf_iec61850_domainId) 
        {
            private_data_add_moreCinfo_domainid(actx,tvb);
        }
        else /* if (hf_index == hf_iec61850_itemId) */
        {
            private_data_add_moreCinfo_itemid(actx,tvb);
        }
    }
    else if (hf_index == hf_iec61850_vmd_specific)
    {
        private_data_add_moreCinfo_vmd(actx,tvb);
    }
    else
    {
        private_data_add_moreCinfo_domain(actx,tvb);
    }


  return offset;
}


static const ber_sequence_t T_domain_specific_sequence[] = {
  { &hf_iec61850_domainId   , BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_itemId     , BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_domain_specific(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_domain_specific_sequence, hf_index, ett_iec61850_T_domain_specific);

  return offset;
}


static const value_string iec61850_ObjectName_vals[] = {
  {   0, "vmd-specific" },
  {   1, "domain-specific" },
  {   2, "aa-specific" },
  { 0, NULL }
};

static const ber_choice_t ObjectName_choice[] = {
  {   0, &hf_iec61850_vmd_specific, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   1, &hf_iec61850_domain_specific, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_domain_specific },
  {   2, &hf_iec61850_aa_specific, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ObjectName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   ObjectName_choice, hf_index, ett_iec61850_ObjectName,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->ObjectName = branch_taken;


  return offset;
}


static int * const Transitions_bits[] = {
  &hf_iec61850_Transitions_idle_to_disabled,
  &hf_iec61850_Transitions_active_to_disabled,
  &hf_iec61850_Transitions_disabled_to_idle,
  &hf_iec61850_Transitions_active_to_idle,
  &hf_iec61850_Transitions_disabled_to_active,
  &hf_iec61850_Transitions_idle_to_active,
  &hf_iec61850_Transitions_any_to_deleted,
  NULL
};

static int
dissect_iec61850_Transitions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                      Transitions_bits, 7, hf_index, ett_iec61850_Transitions,
                                      NULL);

  return offset;
}


static const ber_sequence_t AttachToEventCondition_sequence[] = {
  { &hf_iec61850_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_causingTransitions, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Transitions },
  { &hf_iec61850_acceptableDelay, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AttachToEventCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AttachToEventCondition_sequence, hf_index, ett_iec61850_AttachToEventCondition);

  return offset;
}



static int
dissect_iec61850_Unsigned8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}



static int
dissect_iec61850_Priority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned8(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t AttachToSemaphore_sequence[] = {
  { &hf_iec61850_semaphoreName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_namedToken , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_priority   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Priority },
  { &hf_iec61850_acceptableDelay, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_controlTimeOut, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_abortOnTimeOut, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_relinquishIfConnectionLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AttachToSemaphore(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AttachToSemaphore_sequence, hf_index, ett_iec61850_AttachToSemaphore);

  return offset;
}


static const value_string iec61850_Modifier_vals[] = {
  {   0, "attach-To-Event-Condition" },
  {   1, "attach-To-Semaphore" },
  { 0, NULL }
};

static const ber_choice_t Modifier_choice[] = {
  {   0, &hf_iec61850_attach_To_Event_Condition, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_AttachToEventCondition },
  {   1, &hf_iec61850_attach_To_Semaphore, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_AttachToSemaphore },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Modifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   Modifier_choice, hf_index, ett_iec61850_Modifier,
                                   NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Modifier_sequence_of[1] = {
  { &hf_iec61850_listOfModifier_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_Modifier },
};

static int
dissect_iec61850_SEQUENCE_OF_Modifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_Modifier_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_Modifier);

  return offset;
}



static int
dissect_iec61850_Status_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string iec61850_T_objectClass_vals[] = {
  {   0, "namedVariable" },
  {   1, "scatteredAccess" },
  {   2, "namedVariableList" },
  {   3, "namedType" },
  {   4, "semaphore" },
  {   5, "eventCondition" },
  {   6, "eventAction" },
  {   7, "eventEnrollment" },
  {   8, "journal" },
  {   9, "domain" },
  {  10, "programInvocation" },
  {  11, "operatorStation" },
  { 0, NULL }
};


static int
dissect_iec61850_T_objectClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->objectClass = branch_taken;


  return offset;
}


static const value_string iec61850_T_extendedObjectClass_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass_choice[] = {
  {   0, &hf_iec61850_objectClass, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_objectClass },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_extendedObjectClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_extendedObjectClass_choice, hf_index, ett_iec61850_T_extendedObjectClass,
                                   NULL);

  return offset;
}



static int
dissect_iec61850_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_T_objectScope_vals[] = {
  {   0, "vmdSpecific" },
  {   1, "domainSpecific" },
  {   2, "aaSpecific" },
  { 0, NULL }
};

static const ber_choice_t T_objectScope_choice[] = {
  {   0, &hf_iec61850_vmdSpecific, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  {   1, &hf_iec61850_domainSpecific, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   2, &hf_iec61850_aaSpecific , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_objectScope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_objectScope_choice, hf_index, ett_iec61850_T_objectScope,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->objectScope = branch_taken;


  return offset;
}


static const ber_sequence_t GetNameList_Request_sequence[] = {
  { &hf_iec61850_extendedObjectClass, BER_CLASS_CON, 0, 0, dissect_iec61850_T_extendedObjectClass },
  { &hf_iec61850_objectScope, BER_CLASS_CON, 1, 0, dissect_iec61850_T_objectScope },
  { &hf_iec61850_getNameList_Request_continueAfter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetNameList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetNameList_Request_sequence, hf_index, ett_iec61850_GetNameList_Request);

  return offset;
}



static int
dissect_iec61850_Identify_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_T_objectClass_01_vals[] = {
  {   0, "namedVariable" },
  {   1, "scatteredAccess" },
  {   2, "namedVariableList" },
  {   3, "namedType" },
  {   4, "semaphore" },
  {   5, "eventCondition" },
  {   6, "eventAction" },
  {   7, "eventEnrollment" },
  {   8, "journal" },
  {   9, "domain" },
  {  10, "programInvocation" },
  {  11, "operatorStation" },
  { 0, NULL }
};


static int
dissect_iec61850_T_objectClass_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_extendedObjectClass_01_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass_01_choice[] = {
  {   0, &hf_iec61850_objectClass_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_objectClass_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_extendedObjectClass_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_extendedObjectClass_01_choice, hf_index, ett_iec61850_T_extendedObjectClass_01,
                                   NULL);

  return offset;
}


static const ber_sequence_t Rename_Request_sequence[] = {
  { &hf_iec61850_extendedObjectClass_01, BER_CLASS_CON, 0, 0, dissect_iec61850_T_extendedObjectClass_01 },
  { &hf_iec61850_currentName, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_newIdentifier, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Rename_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Rename_Request_sequence, hf_index, ett_iec61850_Rename_Request);

  return offset;
}



static int
dissect_iec61850_VisibleString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                              actx, tree, tvb, offset, hf_index,
                                              NULL);

  return offset;
}



static int
dissect_iec61850_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static const value_string iec61850_Address_vals[] = {
  {   0, "numericAddress" },
  {   1, "symbolicAddress" },
  {   2, "unconstrainedAddress" },
  { 0, NULL }
};

static const ber_choice_t Address_choice[] = {
  {   0, &hf_iec61850_numericAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  {   1, &hf_iec61850_symbolicAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  {   2, &hf_iec61850_unconstrainedAddress, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   Address_choice, hf_index, ett_iec61850_Address,
                                   NULL);

  return offset;
}


static const ber_sequence_t T_array_sequence[] = {
  { &hf_iec61850_packed     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_numberOfElements, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_elementType, BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_iec61850_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_array(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_array_sequence, hf_index, ett_iec61850_T_array);

  return offset;
}


static const ber_sequence_t T_components_item_sequence[] = {
  { &hf_iec61850_componentName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_componentType, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_components_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_components_item_sequence, hf_index, ett_iec61850_T_components_item);

  return offset;
}


static const ber_sequence_t T_components_sequence_of[1] = {
  { &hf_iec61850_components_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_T_components_item },
};

static int
dissect_iec61850_T_components(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_components_sequence_of, hf_index, ett_iec61850_T_components);

  return offset;
}


static const ber_sequence_t T_structure_sequence[] = {
  { &hf_iec61850_packed     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_components , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_components },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_structure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_structure_sequence, hf_index, ett_iec61850_T_structure);

  return offset;
}



static int
dissect_iec61850_Integer32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_TypeSpecification_vals[] = {
  {   0, "typeName" },
  {   1, "array" },
  {   2, "structure" },
  {   3, "boolean" },
  {   4, "bit-string" },
  {   5, "integer" },
  {   6, "unsigned" },
  {   9, "octet-string" },
  {  10, "visible-string" },
  {  11, "generalized-time" },
  {  12, "binary-time" },
  {  13, "bcd" },
  {  15, "objId" },
  { 0, NULL }
};

static const ber_choice_t TypeSpecification_choice[] = {
  {   0, &hf_iec61850_typeName   , BER_CLASS_CON, 0, 0, dissect_iec61850_ObjectName },
  {   1, &hf_iec61850_array      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_array },
  {   2, &hf_iec61850_structure  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_T_structure },
  {   3, &hf_iec61850_boolean    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  {   4, &hf_iec61850_typeSpecification_bit_string, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  {   5, &hf_iec61850_integer    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  {   6, &hf_iec61850_unsigned   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  {   9, &hf_iec61850_typeSpecification_octet_string, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  {  10, &hf_iec61850_typeSpecification_visible_string, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  {  11, &hf_iec61850_generalized_time, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  {  12, &hf_iec61850_typeSpecification_binary_time, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  {  13, &hf_iec61850_bcd        , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  {  15, &hf_iec61850_objId      , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_TypeSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_tail(actx->pinfo->layers)));
  const unsigned cycle_size = 3;
  unsigned recursion_depth = p_get_proto_depth(actx->pinfo, proto_id);

  DISSECTOR_ASSERT(recursion_depth <= MAX_RECURSION_DEPTH);
  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth + cycle_size);

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   TypeSpecification_choice, hf_index, ett_iec61850_TypeSpecification,
                                   NULL);

  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth);
  return offset;
}


static const ber_sequence_t T_variableDescription_sequence[] = {
  { &hf_iec61850_address    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_Address },
  { &hf_iec61850_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_variableDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_variableDescription_sequence, hf_index, ett_iec61850_T_variableDescription);

  return offset;
}


static const ber_sequence_t T_indexRange_sequence[] = {
  { &hf_iec61850_lowIndex   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_numberOfElements, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_indexRange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_indexRange_sequence, hf_index, ett_iec61850_T_indexRange);

  return offset;
}


static const value_string iec61850_T_accessSelection_vals[] = {
  {   0, "component" },
  {   1, "index" },
  {   2, "indexRange" },
  {   3, "allElements" },
  { 0, NULL }
};

static const ber_choice_t T_accessSelection_choice[] = {
  {   0, &hf_iec61850_component  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   1, &hf_iec61850_index      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  {   2, &hf_iec61850_indexRange , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_T_indexRange },
  {   3, &hf_iec61850_allElements, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_accessSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_accessSelection_choice, hf_index, ett_iec61850_T_accessSelection,
                                   NULL);

  return offset;
}


static const ber_sequence_t T_selectAlternateAccess_sequence[] = {
  { &hf_iec61850_accessSelection, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_accessSelection },
  { &hf_iec61850_alternateAccess, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_selectAlternateAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_selectAlternateAccess_sequence, hf_index, ett_iec61850_T_selectAlternateAccess);

  return offset;
}


static const ber_sequence_t T_indexRange_01_sequence[] = {
  { &hf_iec61850_lowIndex   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_nmberOfElements, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_indexRange_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_indexRange_01_sequence, hf_index, ett_iec61850_T_indexRange_01);

  return offset;
}


static const value_string iec61850_T_selectAccess_vals[] = {
  {   1, "component" },
  {   2, "index" },
  {   3, "indexRange" },
  {   4, "allElements" },
  { 0, NULL }
};

static const ber_choice_t T_selectAccess_choice[] = {
  {   1, &hf_iec61850_component  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   2, &hf_iec61850_index      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  {   3, &hf_iec61850_indexRange_01, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_T_indexRange_01 },
  {   4, &hf_iec61850_allElements, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_selectAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_selectAccess_choice, hf_index, ett_iec61850_T_selectAccess,
                                   NULL);

  return offset;
}


static const value_string iec61850_AlternateAccessSelection_vals[] = {
  {   0, "selectAlternateAccess" },
  {   1, "selectAccess" },
  { 0, NULL }
};

static const ber_choice_t AlternateAccessSelection_choice[] = {
  {   0, &hf_iec61850_selectAlternateAccess, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_selectAlternateAccess },
  {   1, &hf_iec61850_selectAccess, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_iec61850_T_selectAccess },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AlternateAccessSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   AlternateAccessSelection_choice, hf_index, ett_iec61850_AlternateAccessSelection,
                                   NULL);

  return offset;
}


static const ber_sequence_t T_named_sequence[] = {
  { &hf_iec61850_componentName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_accesst    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_AlternateAccessSelection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_named(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_named_sequence, hf_index, ett_iec61850_T_named);

  return offset;
}


static const value_string iec61850_AlternateAccess_item_vals[] = {
  {   0, "unnamed" },
  {   1, "named" },
  { 0, NULL }
};

static const ber_choice_t AlternateAccess_item_choice[] = {
  {   0, &hf_iec61850_unnamed    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_iec61850_AlternateAccessSelection },
  {   1, &hf_iec61850_named      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_T_named },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AlternateAccess_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   AlternateAccess_item_choice, hf_index, ett_iec61850_AlternateAccess_item,
                                   NULL);

  return offset;
}


static const ber_sequence_t AlternateAccess_sequence_of[1] = {
  { &hf_iec61850_AlternateAccess_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_AlternateAccess_item },
};

static int
dissect_iec61850_AlternateAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_tail(actx->pinfo->layers)));
  const unsigned cycle_size = 5;
  unsigned recursion_depth = p_get_proto_depth(actx->pinfo, proto_id);

  DISSECTOR_ASSERT(recursion_depth <= MAX_RECURSION_DEPTH);
  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth + cycle_size);

    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        AlternateAccess_sequence_of, hf_index, ett_iec61850_AlternateAccess);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->AlternateAccess = 1;


  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth);
  return offset;
}


static const ber_sequence_t ScatteredAccessDescription_item_sequence[] = {
  { &hf_iec61850_componentName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_variableSpecification, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableSpecification },
  { &hf_iec61850_alternateAccess, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ScatteredAccessDescription_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ScatteredAccessDescription_item_sequence, hf_index, ett_iec61850_ScatteredAccessDescription_item);

  return offset;
}


static const ber_sequence_t ScatteredAccessDescription_sequence_of[1] = {
  { &hf_iec61850_ScatteredAccessDescription_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_ScatteredAccessDescription_item },
};

static int
dissect_iec61850_ScatteredAccessDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        ScatteredAccessDescription_sequence_of, hf_index, ett_iec61850_ScatteredAccessDescription);

  return offset;
}


static const value_string iec61850_VariableSpecification_vals[] = {
  {   0, "name" },
  {   1, "address" },
  {   2, "variableDescription" },
  {   3, "scatteredAccessDescription" },
  {   4, "invalidated" },
  { 0, NULL }
};

static const ber_choice_t VariableSpecification_choice[] = {
  {   0, &hf_iec61850_name       , BER_CLASS_CON, 0, 0, dissect_iec61850_ObjectName },
  {   1, &hf_iec61850_address    , BER_CLASS_CON, 1, 0, dissect_iec61850_Address },
  {   2, &hf_iec61850_variableDescription, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_T_variableDescription },
  {   3, &hf_iec61850_scatteredAccessDescription, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_ScatteredAccessDescription },
  {   4, &hf_iec61850_invalidated, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_VariableSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_tail(actx->pinfo->layers)));
  const unsigned cycle_size = 4;
  unsigned recursion_depth = p_get_proto_depth(actx->pinfo, proto_id);

  DISSECTOR_ASSERT(recursion_depth <= MAX_RECURSION_DEPTH);
  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth + cycle_size);

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   VariableSpecification_choice, hf_index, ett_iec61850_VariableSpecification,
                                   NULL);

  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth);
  return offset;
}


static const ber_sequence_t T_listOfVariable_item_02_sequence[] = {
  { &hf_iec61850_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableSpecification },
  { &hf_iec61850_alternateAccess, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_listOfVariable_item_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_listOfVariable_item_02_sequence, hf_index, ett_iec61850_T_listOfVariable_item_02);

  return offset;
}


static const ber_sequence_t T_listOfVariable_02_sequence_of[1] = {
  { &hf_iec61850_listOfVariable_item_02, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_T_listOfVariable_item_02 },
};

static int
dissect_iec61850_T_listOfVariable_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfVariable_02_sequence_of, hf_index, ett_iec61850_T_listOfVariable_02);

  return offset;
}


static const value_string iec61850_VariableAccessSpecification_vals[] = {
  {   0, "listOfVariable" },
  {   1, "variableListName" },
  { 0, NULL }
};

static const ber_choice_t VariableAccessSpecification_choice[] = {
  {   0, &hf_iec61850_listOfVariable_02, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfVariable_02 },
  {   1, &hf_iec61850_variableListName, BER_CLASS_CON, 1, 0, dissect_iec61850_ObjectName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_VariableAccessSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   VariableAccessSpecification_choice, hf_index, ett_iec61850_VariableAccessSpecification,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->VariableAccessSpecification = branch_taken;


  return offset;
}


static const ber_sequence_t Read_Request_sequence[] = {
  { &hf_iec61850_specificationWithResult, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_variableAccessSpecificatn, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableAccessSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Read_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Read_Request_sequence, hf_index, ett_iec61850_Read_Request);

  return offset;
}


static const ber_sequence_t T_array_01_sequence_of[1] = {
  { &hf_iec61850_array_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_Data },
};

static int
dissect_iec61850_T_array_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    private_data_add_moreCinfo_array(actx, 1);
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_array_01_sequence_of, hf_index, ett_iec61850_T_array_01);

    private_data_add_moreCinfo_array(actx, 0);


  return offset;
}


static const ber_sequence_t T_structure_01_sequence_of[1] = {
  { &hf_iec61850_structure_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_Data },
};

static int
dissect_iec61850_T_structure_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    private_data_add_moreCinfo_structure(actx, 1);
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_structure_01_sequence_of, hf_index, ett_iec61850_T_structure_01);

    private_data_add_moreCinfo_structure(actx, 0);


  return offset;
}



static int
dissect_iec61850_T_boolean(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    bool val; /*int32_t val;*/
    offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, &val);


    private_data_add_moreCinfo_bool(actx, val);


  return offset;
}



static int
dissect_iec61850_T_data_bit_string(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t old_offset = offset;
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                      NULL, 0, hf_index, -1,
                                      NULL);

    private_data_add_moreCinfo_bstr(actx, tvb, old_offset);


  return offset;
}



static int
dissect_iec61850_T_integer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t val;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &val);


    private_data_add_moreCinfo_int(actx, val);


  return offset;
}



static int
dissect_iec61850_T_unsigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t val;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &val);


    private_data_add_moreCinfo_int(actx, val);


  return offset;
}



static int
dissect_iec61850_FloatingPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                         NULL);

    private_data_add_moreCinfo_float(actx, tvb);


  return offset;
}



static int
dissect_iec61850_T_data_octet_string(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t old_offset = offset;
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                         NULL);

    private_data_add_moreCinfo_ostr(actx, tvb, old_offset);


  return offset;
}



static int
dissect_iec61850_T_data_visible_string(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t old_offset = offset;
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                              actx, tree, tvb, offset, hf_index,
                                              NULL);

    private_data_add_moreCinfo_vstr(actx, tvb, old_offset);


  return offset;
}



static int
dissect_iec61850_TimeOfDay(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    uint32_t len;
    uint32_t milliseconds;
    uint16_t days;
    uint8_t *	ptime;
    nstime_t ts;

    len = tvb_reported_length_remaining(tvb, offset);

    if(len == 4)
    {
        milliseconds = tvb_get_ntohl(tvb, offset);
        ptime = signed_time_msecs_to_str(actx->pinfo->pool, milliseconds);

        if(hf_index > 0)
        {
            proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
        }
        return offset;
    }

    if(len == 6)
    {
        milliseconds = tvb_get_ntohl(tvb, offset);
        days = tvb_get_ntohs(tvb, offset+4);

        /* 5113 days between 01-01-1970 and 01-01-1984 */
        /* 86400 seconds in one day */

        ts.secs = (days + 5113) * 86400 + milliseconds / 1000;
        ts.nsecs = (milliseconds % 1000) * 1000000U;

        ptime = abs_time_to_str(actx->pinfo->pool, &ts, ABSOLUTE_TIME_UTC, TRUE);
        if(hf_index > 0)
        {
            proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
        }
        private_data_add_moreCinfo_str(actx, ptime);
        return offset;
    }

    proto_tree_add_expert_format(tree, actx->pinfo, &ei_iec61850_mal_timeofday_encoding,
            tvb, offset, len, "BER Error: malformed TimeOfDay encoding, length must be 4 or 6 bytes");
    if(hf_index > 0)
    {
        proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
    }


  return offset;
}



static int
dissect_iec61850_T_bcd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t val;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &val);


    private_data_add_moreCinfo_int(actx, val);


  return offset;
}



static int
dissect_iec61850_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                      NULL, 0, hf_index, -1,
                                      NULL);

  return offset;
}



static int
dissect_iec61850_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_iec61850_MMSString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                              actx, tree, tvb, offset, hf_index,
                                              NULL);

  return offset;
}



static int
dissect_iec61850_UtcTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    uint8_t quality;
    uint32_t len;
    uint32_t seconds;
    uint32_t	fraction;
    uint32_t nanoseconds;
    nstime_t ts;
    uint8_t *	ptime;
    uint8_t * timestring;

    ws_assert(actx->pinfo->pool);
    timestring = wmem_alloc0(actx->pinfo->pool, IEC61850_BUFFER_SIZE_MORE );
    ws_assert(timestring);

    len = tvb_reported_length_remaining(tvb, offset);

    if(len != 8)
    {
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_iec61850_mal_utctime_encoding,
                tvb, offset, len, "BER Error: malformed IEC61850 UTCTime encoding, length must be 8 bytes");
        if(hf_index > 0)
        {
            proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
        }
        return offset;
    }

    seconds = tvb_get_ntohl(tvb, offset);
    fraction = tvb_get_ntoh24(tvb, offset+4) * 0x100; /* Only 3 bytes are recommended */
    nanoseconds = (uint32_t)( ((uint64_t)fraction * G_GUINT64_CONSTANT(1000000000)) / G_GUINT64_CONSTANT(0x100000000) ) ;

    ts.secs = seconds;
    ts.nsecs = nanoseconds;

    ptime = abs_time_to_str(actx->pinfo->pool, &ts, ABSOLUTE_TIME_UTC, TRUE);

    quality = tvb_get_guint8(tvb, offset+7);
    snprintf(timestring, IEC61850_BUFFER_SIZE_MORE, "%s,q:%02x", ptime, quality);

    if(hf_index > 0)
    {
        proto_tree_add_string(tree, hf_index, tvb, offset, len, timestring);
    }
    private_data_add_moreCinfo_str(actx, timestring);



  return offset;
}


static const value_string iec61850_Data_vals[] = {
  {   1, "array" },
  {   2, "structure" },
  {   3, "boolean" },
  {   4, "bit-string" },
  {   5, "integer" },
  {   6, "unsigned" },
  {   7, "floating-point" },
  {   9, "octet-string" },
  {  10, "visible-string" },
  {  12, "binary-time" },
  {  13, "bcd" },
  {  14, "booleanArray" },
  {  15, "objId" },
  {  16, "mMSString" },
  {  17, "utc-time" },
  { 0, NULL }
};

static const ber_choice_t Data_choice[] = {
  {   1, &hf_iec61850_array_01   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_array_01 },
  {   2, &hf_iec61850_structure_01, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_T_structure_01 },
  {   3, &hf_iec61850_boolean_01 , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_T_boolean },
  {   4, &hf_iec61850_data_bit_string, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_T_data_bit_string },
  {   5, &hf_iec61850_integer_01 , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_T_integer },
  {   6, &hf_iec61850_unsigned_01, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_iec61850_T_unsigned },
  {   7, &hf_iec61850_floating_point, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_FloatingPoint },
  {   9, &hf_iec61850_data_octet_string, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_T_data_octet_string },
  {  10, &hf_iec61850_data_visible_string, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_iec61850_T_data_visible_string },
  {  12, &hf_iec61850_data_binary_time, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_iec61850_TimeOfDay },
  {  13, &hf_iec61850_bcd_01     , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_iec61850_T_bcd },
  {  14, &hf_iec61850_booleanArray, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_iec61850_BIT_STRING },
  {  15, &hf_iec61850_objId_01   , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_iec61850_OBJECT_IDENTIFIER },
  {  16, &hf_iec61850_mMSString  , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_iec61850_MMSString },
  {  17, &hf_iec61850_utc_time   , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_iec61850_UtcTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_tail(actx->pinfo->layers)));
  const unsigned cycle_size = 3;
  unsigned recursion_depth = p_get_proto_depth(actx->pinfo, proto_id);

  DISSECTOR_ASSERT(recursion_depth <= MAX_RECURSION_DEPTH);
  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth + cycle_size);

    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   Data_choice, hf_index, ett_iec61850_Data,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->DataType = branch_taken;


  p_set_proto_depth(actx->pinfo, proto_id, recursion_depth);
  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Data_sequence_of[1] = {
  { &hf_iec61850_listOfData_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_Data },
};

static int
dissect_iec61850_SEQUENCE_OF_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_Data_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_Data);

  return offset;
}


static const ber_sequence_t Write_Request_sequence[] = {
  { &hf_iec61850_variableAccessSpecificatn, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableAccessSpecification },
  { &hf_iec61850_listOfData , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_Data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Write_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Write_Request_sequence, hf_index, ett_iec61850_Write_Request);

  return offset;
}


static const value_string iec61850_GetVariableAccessAttributes_Request_vals[] = {
  {   0, "name" },
  {   1, "address" },
  { 0, NULL }
};

static const ber_choice_t GetVariableAccessAttributes_Request_choice[] = {
  {   0, &hf_iec61850_name       , BER_CLASS_CON, 0, 0, dissect_iec61850_ObjectName },
  {   1, &hf_iec61850_address    , BER_CLASS_CON, 1, 0, dissect_iec61850_Address },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetVariableAccessAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   GetVariableAccessAttributes_Request_choice, hf_index, ett_iec61850_GetVariableAccessAttributes_Request,
                                   NULL);

  return offset;
}


static const ber_sequence_t DefineNamedVariable_Request_sequence[] = {
  { &hf_iec61850_variableName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_address    , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_Address },
  { &hf_iec61850_typeSpecification, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineNamedVariable_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineNamedVariable_Request_sequence, hf_index, ett_iec61850_DefineNamedVariable_Request);

  return offset;
}


static const ber_sequence_t DefineScatteredAccess_Request_sequence[] = {
  { &hf_iec61850_scatteredAccessName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_scatteredAccessDescription, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ScatteredAccessDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineScatteredAccess_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineScatteredAccess_Request_sequence, hf_index, ett_iec61850_DefineScatteredAccess_Request);

  return offset;
}



static int
dissect_iec61850_GetScatteredAccessAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_scopeOfDelete_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_iec61850_T_scopeOfDelete(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ObjectName_sequence_of[1] = {
  { &hf_iec61850_listOfName_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
};

static int
dissect_iec61850_SEQUENCE_OF_ObjectName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_ObjectName_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_ObjectName);

  return offset;
}


static const ber_sequence_t DeleteVariableAccess_Request_sequence[] = {
  { &hf_iec61850_scopeOfDelete, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_scopeOfDelete },
  { &hf_iec61850_listOfName , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_ObjectName },
  { &hf_iec61850_domainName , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteVariableAccess_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DeleteVariableAccess_Request_sequence, hf_index, ett_iec61850_DeleteVariableAccess_Request);

  return offset;
}


static const ber_sequence_t T_listOfVariable_item_sequence[] = {
  { &hf_iec61850_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableSpecification },
  { &hf_iec61850_alternateAccess, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_listOfVariable_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_listOfVariable_item_sequence, hf_index, ett_iec61850_T_listOfVariable_item);

  return offset;
}


static const ber_sequence_t T_listOfVariable_sequence_of[1] = {
  { &hf_iec61850_listOfVariable_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_T_listOfVariable_item },
};

static int
dissect_iec61850_T_listOfVariable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfVariable_sequence_of, hf_index, ett_iec61850_T_listOfVariable);

  return offset;
}


static const ber_sequence_t DefineNamedVariableList_Request_sequence[] = {
  { &hf_iec61850_variableListName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_listOfVariable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfVariable },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineNamedVariableList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineNamedVariableList_Request_sequence, hf_index, ett_iec61850_DefineNamedVariableList_Request);

  return offset;
}



static int
dissect_iec61850_GetNamedVariableListAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_scopeOfDelete_01_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_iec61850_T_scopeOfDelete_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t DeleteNamedVariableList_Request_sequence[] = {
  { &hf_iec61850_scopeOfDelete_01, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_scopeOfDelete_01 },
  { &hf_iec61850_listOfVariableListName, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_ObjectName },
  { &hf_iec61850_domainName , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteNamedVariableList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DeleteNamedVariableList_Request_sequence, hf_index, ett_iec61850_DeleteNamedVariableList_Request);

  return offset;
}


static const ber_sequence_t DefineNamedType_Request_sequence[] = {
  { &hf_iec61850_typeName   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineNamedType_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineNamedType_Request_sequence, hf_index, ett_iec61850_DefineNamedType_Request);

  return offset;
}



static int
dissect_iec61850_GetNamedTypeAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_scopeOfDelete_02_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_iec61850_T_scopeOfDelete_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t DeleteNamedType_Request_sequence[] = {
  { &hf_iec61850_scopeOfDelete_02, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_scopeOfDelete_02 },
  { &hf_iec61850_listOfTypeName, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_ObjectName },
  { &hf_iec61850_domainName , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteNamedType_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DeleteNamedType_Request_sequence, hf_index, ett_iec61850_DeleteNamedType_Request);

  return offset;
}


static const ber_sequence_t T_listOfPromptData_sequence_of[1] = {
  { &hf_iec61850_listOfPromptData_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfPromptData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfPromptData_sequence_of, hf_index, ett_iec61850_T_listOfPromptData);

  return offset;
}


static const ber_sequence_t Input_Request_sequence[] = {
  { &hf_iec61850_operatorStationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_echo       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_listOfPromptData, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfPromptData },
  { &hf_iec61850_inputTimeOut, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Input_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Input_Request_sequence, hf_index, ett_iec61850_Input_Request);

  return offset;
}


static const ber_sequence_t T_listOfOutputData_sequence_of[1] = {
  { &hf_iec61850_listOfOutputData_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfOutputData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfOutputData_sequence_of, hf_index, ett_iec61850_T_listOfOutputData);

  return offset;
}


static const ber_sequence_t Output_Request_sequence[] = {
  { &hf_iec61850_operatorStationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_listOfOutputData, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfOutputData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Output_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Output_Request_sequence, hf_index, ett_iec61850_Output_Request);

  return offset;
}



static int
dissect_iec61850_T_ap_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset=dissect_acse_AP_title_stub(FALSE, tvb, offset, actx, tree, hf_iec61850_ap_title);


  return offset;
}



static int
dissect_iec61850_T_ap_invocation_id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset=dissect_acse_AP_invocation_identifier_stub(FALSE, tvb, offset, actx, tree, hf_iec61850_ap_invocation_id);


  return offset;
}



static int
dissect_iec61850_T_ae_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset=dissect_acse_AE_qualifier_stub(FALSE, tvb, offset, actx, tree, hf_iec61850_ae_qualifier);


  return offset;
}



static int
dissect_iec61850_T_ae_invocation_id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset=dissect_acse_AE_invocation_identifier_stub(FALSE, tvb, offset, actx, tree, hf_iec61850_ae_invocation_id);


  return offset;
}


static const ber_sequence_t ApplicationReference_sequence[] = {
  { &hf_iec61850_ap_title   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_iec61850_T_ap_title },
  { &hf_iec61850_ap_invocation_id, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_iec61850_T_ap_invocation_id },
  { &hf_iec61850_ae_qualifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_iec61850_T_ae_qualifier },
  { &hf_iec61850_ae_invocation_id, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_iec61850_T_ae_invocation_id },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ApplicationReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ApplicationReference_sequence, hf_index, ett_iec61850_ApplicationReference);

  return offset;
}


static const ber_sequence_t TakeControl_Request_sequence[] = {
  { &hf_iec61850_semaphoreName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_namedToken , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_priority   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Priority },
  { &hf_iec61850_acceptableDelay, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_controlTimeOut, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_abortOnTimeOut, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_relinquishIfConnectionLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_applicationToPreempt, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_TakeControl_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     TakeControl_Request_sequence, hf_index, ett_iec61850_TakeControl_Request);

  return offset;
}


static const ber_sequence_t RelinquishControl_Request_sequence[] = {
  { &hf_iec61850_semaphoreName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_namedToken , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_RelinquishControl_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     RelinquishControl_Request_sequence, hf_index, ett_iec61850_RelinquishControl_Request);

  return offset;
}



static int
dissect_iec61850_Unsigned16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t DefineSemaphore_Request_sequence[] = {
  { &hf_iec61850_semaphoreName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_numbersOfTokens, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned16 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineSemaphore_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineSemaphore_Request_sequence, hf_index, ett_iec61850_DefineSemaphore_Request);

  return offset;
}



static int
dissect_iec61850_DeleteSemaphore_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_ReportSemaphoreStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportPoolSemaphoreStatus_Request_sequence[] = {
  { &hf_iec61850_semaphoreName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_nameToStartAfter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportPoolSemaphoreStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportPoolSemaphoreStatus_Request_sequence, hf_index, ett_iec61850_ReportPoolSemaphoreStatus_Request);

  return offset;
}


static const value_string iec61850_T_reportSemaphoreEntryStatus_Request_state_vals[] = {
  {   0, "queued" },
  {   1, "owner" },
  {   2, "hung" },
  { 0, NULL }
};


static int
dissect_iec61850_T_reportSemaphoreEntryStatus_Request_state(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t ReportSemaphoreEntryStatus_Request_sequence[] = {
  { &hf_iec61850_semaphoreName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_reportSemaphoreEntryStatus_Request_state, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_reportSemaphoreEntryStatus_Request_state },
  { &hf_iec61850_entryIdToStartAfter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportSemaphoreEntryStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportSemaphoreEntryStatus_Request_sequence, hf_index, ett_iec61850_ReportSemaphoreEntryStatus_Request);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_01_sequence_of[1] = {
  { &hf_iec61850_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfCapabilities_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfCapabilities_01_sequence_of, hf_index, ett_iec61850_T_listOfCapabilities_01);

  return offset;
}


static const ber_sequence_t InitiateDownloadSequence_Request_sequence[] = {
  { &hf_iec61850_domainName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_listOfCapabilities_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfCapabilities_01 },
  { &hf_iec61850_sharable   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_InitiateDownloadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     InitiateDownloadSequence_Request_sequence, hf_index, ett_iec61850_InitiateDownloadSequence_Request);

  return offset;
}



static int
dissect_iec61850_DownloadSegment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_vmd_state_vals[] = {
  {   0, "other" },
  {   1, "vmd-state-conflict" },
  {   2, "vmd-operational-problem" },
  {   3, "domain-transfer-problem" },
  {   4, "state-machine-id-invalid" },
  { 0, NULL }
};


static int
dissect_iec61850_T_vmd_state(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_application_reference_vals[] = {
  {   0, "other" },
  {   1, "aplication-unreachable" },
  {   2, "connection-lost" },
  {   3, "application-reference-invalid" },
  {   4, "context-unsupported" },
  { 0, NULL }
};


static int
dissect_iec61850_T_application_reference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_definition_vals[] = {
  {   0, "other" },
  {   1, "object-undefined" },
  {   2, "invalid-address" },
  {   3, "type-unsupported" },
  {   4, "type-inconsistent" },
  {   5, "object-exists" },
  {   6, "object-attribute-inconsistent" },
  { 0, NULL }
};


static int
dissect_iec61850_T_definition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    private_data_add_moreCinfo_enum(actx, branch_taken, iec61850_T_definition_vals);


  return offset;
}


static const value_string iec61850_T_resource_vals[] = {
  {   0, "other" },
  {   1, "memory-unavailable" },
  {   2, "processor-resource-unavailable" },
  {   3, "mass-storage-unavailable" },
  {   4, "capability-unavailable" },
  {   5, "capability-unknown" },
  { 0, NULL }
};


static int
dissect_iec61850_T_resource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_service_vals[] = {
  {   0, "other" },
  {   1, "primitives-out-of-sequence" },
  {   2, "object-sate-conflict" },
  {   3, "pdu-size" },
  {   4, "continuation-invalid" },
  {   5, "object-constraint-conflict" },
  { 0, NULL }
};


static int
dissect_iec61850_T_service(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    private_data_add_moreCinfo_enum(actx, branch_taken, iec61850_T_service_vals);


  return offset;
}


static const value_string iec61850_T_service_preempt_vals[] = {
  {   0, "other" },
  {   1, "timeout" },
  {   2, "deadlock" },
  {   3, "cancel" },
  { 0, NULL }
};


static int
dissect_iec61850_T_service_preempt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_time_resolution_vals[] = {
  {   0, "other" },
  {   1, "unsupportable-time-resolution" },
  { 0, NULL }
};


static int
dissect_iec61850_T_time_resolution(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_access_vals[] = {
  {   0, "other" },
  {   1, "object-access-unsupported" },
  {   2, "object-non-existent" },
  {   3, "object-access-denied" },
  {   4, "object-invalidated" },
  { 0, NULL }
};


static int
dissect_iec61850_T_access(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    private_data_add_moreCinfo_enum(actx, branch_taken, iec61850_T_access_vals);


  return offset;
}


static const value_string iec61850_T_initiate_vals[] = {
  {   0, "other" },
  {   1, "version-incompatible" },
  {   2, "max-segment-insufficient" },
  {   3, "max-services-outstanding-calling-insufficient" },
  {   4, "max-services-outstanding-called-insufficient" },
  {   5, "service-CBB-insufficient" },
  {   6, "parameter-CBB-insufficient" },
  {   7, "nesting-level-insufficient" },
  { 0, NULL }
};


static int
dissect_iec61850_T_initiate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    private_data_add_moreCinfo_enum(actx, branch_taken, iec61850_T_initiate_vals);


  return offset;
}


static const value_string iec61850_T_conclude_vals[] = {
  {   0, "other" },
  {   1, "further-communication-required" },
  { 0, NULL }
};


static int
dissect_iec61850_T_conclude(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    private_data_add_moreCinfo_enum(actx, branch_taken, iec61850_T_conclude_vals);

  return offset;
}


static const value_string iec61850_T_cancel_vals[] = {
  {   0, "other" },
  {   1, "invoke-id-unknown" },
  {   2, "cancel-not-possible" },
  { 0, NULL }
};


static int
dissect_iec61850_T_cancel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_file_vals[] = {
  {   0, "other" },
  {   1, "filename-ambiguous" },
  {   2, "file-busy" },
  {   3, "filename-syntax-error" },
  {   4, "content-type-invalid" },
  {   5, "position-invalid" },
  {   6, "file-acces-denied" },
  {   7, "file-non-existent" },
  {   8, "duplicate-filename" },
  {   9, "insufficient-space-in-filestore" },
  { 0, NULL }
};


static int
dissect_iec61850_T_file(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    private_data_add_moreCinfo_enum(actx, branch_taken, iec61850_T_file_vals);


  return offset;
}



static int
dissect_iec61850_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_errorClass_vals[] = {
  {   0, "vmd-state" },
  {   1, "application-reference" },
  {   2, "definition" },
  {   3, "resource" },
  {   4, "service" },
  {   5, "service-preempt" },
  {   6, "time-resolution" },
  {   7, "access" },
  {   8, "initiate" },
  {   9, "conclude" },
  {  10, "cancel" },
  {  11, "file" },
  {  12, "others" },
  { 0, NULL }
};

static const ber_choice_t T_errorClass_choice[] = {
  {   0, &hf_iec61850_vmd_state  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_vmd_state },
  {   1, &hf_iec61850_application_reference, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_application_reference },
  {   2, &hf_iec61850_definition , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_T_definition },
  {   3, &hf_iec61850_resource   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_T_resource },
  {   4, &hf_iec61850_service    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_T_service },
  {   5, &hf_iec61850_service_preempt, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_T_service_preempt },
  {   6, &hf_iec61850_time_resolution, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_iec61850_T_time_resolution },
  {   7, &hf_iec61850_access     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_T_access },
  {   8, &hf_iec61850_initiate   , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_iec61850_T_initiate },
  {   9, &hf_iec61850_conclude   , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_T_conclude },
  {  10, &hf_iec61850_cancel     , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_iec61850_T_cancel },
  {  11, &hf_iec61850_file       , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_iec61850_T_file },
  {  12, &hf_iec61850_others     , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_iec61850_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_errorClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_errorClass_choice, hf_index, ett_iec61850_T_errorClass,
                                   NULL);

  return offset;
}


static const value_string iec61850_ObtainFile_Error_vals[] = {
  {   0, "source-file" },
  {   1, "destination-file" },
  { 0, NULL }
};


static int
dissect_iec61850_ObtainFile_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_ProgramInvocationState_vals[] = {
  {   0, "non-existent" },
  {   1, "unrunable" },
  {   2, "idle" },
  {   3, "running" },
  {   4, "stopped" },
  {   5, "starting" },
  {   6, "stopping" },
  {   7, "resuming" },
  {   8, "resetting" },
  { 0, NULL }
};


static int
dissect_iec61850_ProgramInvocationState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}



static int
dissect_iec61850_Start_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_Stop_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_Resume_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_Reset_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteVariableAccess_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteNamedVariableList_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteNamedType_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_DefineEventEnrollment_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_FileRename_Error_vals[] = {
  {   0, "source-file" },
  {   1, "destination-file" },
  { 0, NULL }
};


static int
dissect_iec61850_FileRename_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}



static int
dissect_iec61850_DefineEventConditionList_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_AddEventConditionListReference_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_RemoveEventConditionListReference_Error_vals[] = {
  {   0, "eventCondition" },
  {   1, "eventConditionList" },
  { 0, NULL }
};

static const ber_choice_t RemoveEventConditionListReference_Error_choice[] = {
  {   0, &hf_iec61850_eventCondition, BER_CLASS_CON, 0, 0, dissect_iec61850_ObjectName },
  {   1, &hf_iec61850_eventConditionList, BER_CLASS_CON, 1, 0, dissect_iec61850_ObjectName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_RemoveEventConditionListReference_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   RemoveEventConditionListReference_Error_choice, hf_index, ett_iec61850_RemoveEventConditionListReference_Error,
                                   NULL);

  return offset;
}


static const value_string iec61850_InitiateUnitControl_Error_vals[] = {
  {   0, "domain" },
  {   1, "programInvocation" },
  { 0, NULL }
};

static const ber_choice_t InitiateUnitControl_Error_choice[] = {
  {   0, &hf_iec61850_domain     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   1, &hf_iec61850_programInvocation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_InitiateUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   InitiateUnitControl_Error_choice, hf_index, ett_iec61850_InitiateUnitControl_Error,
                                   NULL);

  return offset;
}


static const ber_sequence_t StartUnitControl_Error_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_programInvocationState, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ProgramInvocationState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_StartUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     StartUnitControl_Error_sequence, hf_index, ett_iec61850_StartUnitControl_Error);

  return offset;
}


static const ber_sequence_t StopUnitControl_Error_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_programInvocationState, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ProgramInvocationState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_StopUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     StopUnitControl_Error_sequence, hf_index, ett_iec61850_StopUnitControl_Error);

  return offset;
}


static const value_string iec61850_DeleteUnitControl_Error_vals[] = {
  {   0, "domain" },
  {   1, "programInvocation" },
  { 0, NULL }
};

static const ber_choice_t DeleteUnitControl_Error_choice[] = {
  {   0, &hf_iec61850_domain     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   1, &hf_iec61850_programInvocation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   DeleteUnitControl_Error_choice, hf_index, ett_iec61850_DeleteUnitControl_Error,
                                   NULL);

  return offset;
}


static const value_string iec61850_LoadUnitControlFromFile_Error_vals[] = {
  {   0, "none" },
  {   1, "domain" },
  {   2, "programInvocation" },
  { 0, NULL }
};

static const ber_choice_t LoadUnitControlFromFile_Error_choice[] = {
  {   0, &hf_iec61850_none       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  {   1, &hf_iec61850_domain     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   2, &hf_iec61850_programInvocation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_LoadUnitControlFromFile_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   LoadUnitControlFromFile_Error_choice, hf_index, ett_iec61850_LoadUnitControlFromFile_Error,
                                   NULL);

  return offset;
}


static const value_string iec61850_AdditionalService_Error_vals[] = {
  {   0, "defineEcl" },
  {   1, "addECLReference" },
  {   2, "removeECLReference" },
  {   3, "initiateUC" },
  {   4, "startUC" },
  {   5, "stopUC" },
  {   6, "deleteUC" },
  {   7, "loadUCFromFile" },
  { 0, NULL }
};

static const ber_choice_t AdditionalService_Error_choice[] = {
  {   0, &hf_iec61850_defineEcl  , BER_CLASS_CON, 0, 0, dissect_iec61850_DefineEventConditionList_Error },
  {   1, &hf_iec61850_addECLReference, BER_CLASS_CON, 1, 0, dissect_iec61850_AddEventConditionListReference_Error },
  {   2, &hf_iec61850_removeECLReference, BER_CLASS_CON, 2, 0, dissect_iec61850_RemoveEventConditionListReference_Error },
  {   3, &hf_iec61850_initiateUC , BER_CLASS_CON, 3, 0, dissect_iec61850_InitiateUnitControl_Error },
  {   4, &hf_iec61850_startUC    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_StartUnitControl_Error },
  {   5, &hf_iec61850_stopUC     , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_StopUnitControl_Error },
  {   6, &hf_iec61850_deleteUC   , BER_CLASS_CON, 6, 0, dissect_iec61850_DeleteUnitControl_Error },
  {   7, &hf_iec61850_loadUCFromFile, BER_CLASS_CON, 7, 0, dissect_iec61850_LoadUnitControlFromFile_Error },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AdditionalService_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   AdditionalService_Error_choice, hf_index, ett_iec61850_AdditionalService_Error,
                                   NULL);

  return offset;
}



static int
dissect_iec61850_ChangeAccessControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_serviceSpecificInformation_vals[] = {
  {   0, "obtainFile" },
  {   1, "start" },
  {   2, "stop" },
  {   3, "resume" },
  {   4, "reset" },
  {   5, "deleteVariableAccess" },
  {   6, "deleteNamedVariableList" },
  {   7, "deleteNamedType" },
  {   8, "defineEventEnrollment-Error" },
  {   9, "fileRename" },
  {  10, "additionalService" },
  {  11, "changeAccessControl" },
  { 0, NULL }
};

static const ber_choice_t T_serviceSpecificInformation_choice[] = {
  {   0, &hf_iec61850_obtainFile_02, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_ObtainFile_Error },
  {   1, &hf_iec61850_start_02   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Start_Error },
  {   2, &hf_iec61850_stop_02    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Stop_Error },
  {   3, &hf_iec61850_resume_02  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_Resume_Error },
  {   4, &hf_iec61850_reset_02   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_Reset_Error },
  {   5, &hf_iec61850_deleteVariableAccess_02, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteVariableAccess_Error },
  {   6, &hf_iec61850_deleteNamedVariableList_02, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteNamedVariableList_Error },
  {   7, &hf_iec61850_deleteNamedType_02, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteNamedType_Error },
  {   8, &hf_iec61850_defineEventEnrollment_Error, BER_CLASS_CON, 8, 0, dissect_iec61850_DefineEventEnrollment_Error },
  {   9, &hf_iec61850_fileRename_02, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_FileRename_Error },
  {  10, &hf_iec61850_additionalService, BER_CLASS_CON, 10, 0, dissect_iec61850_AdditionalService_Error },
  {  11, &hf_iec61850_changeAccessControl, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_iec61850_ChangeAccessControl_Error },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_serviceSpecificInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_serviceSpecificInformation_choice, hf_index, ett_iec61850_T_serviceSpecificInformation,
                                   NULL);

  return offset;
}


static const ber_sequence_t ServiceError_sequence[] = {
  { &hf_iec61850_errorClass , BER_CLASS_CON, 0, 0, dissect_iec61850_T_errorClass },
  { &hf_iec61850_additionalCode, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_INTEGER },
  { &hf_iec61850_additionalDescription, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  { &hf_iec61850_serviceSpecificInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_iec61850_T_serviceSpecificInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ServiceError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ServiceError_sequence, hf_index, ett_iec61850_ServiceError);

  return offset;
}


static const ber_sequence_t TerminateDownloadSequence_Request_sequence[] = {
  { &hf_iec61850_domainName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_discard    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_TerminateDownloadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     TerminateDownloadSequence_Request_sequence, hf_index, ett_iec61850_TerminateDownloadSequence_Request);

  return offset;
}



static int
dissect_iec61850_InitiateUploadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_UploadSegment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_TerminateUploadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_03_sequence_of[1] = {
  { &hf_iec61850_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfCapabilities_03(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfCapabilities_03_sequence_of, hf_index, ett_iec61850_T_listOfCapabilities_03);

  return offset;
}



static int
dissect_iec61850_GraphicString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                              actx, tree, tvb, offset, hf_index,
                                              NULL);

  return offset;
}


static const ber_sequence_t FileName_sequence_of[1] = {
  { &hf_iec61850_FileName_item, BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_iec61850_GraphicString },
};

static int
dissect_iec61850_FileName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        FileName_sequence_of, hf_index, ett_iec61850_FileName);

  return offset;
}


static const ber_sequence_t RequestDomainDownload_Request_sequence[] = {
  { &hf_iec61850_domainName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_listOfCapabilities_03, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfCapabilities_03 },
  { &hf_iec61850_sharable   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_fileName   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_RequestDomainDownload_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     RequestDomainDownload_Request_sequence, hf_index, ett_iec61850_RequestDomainDownload_Request);

  return offset;
}


static const ber_sequence_t RequestDomainUpload_Request_sequence[] = {
  { &hf_iec61850_domainName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_fileName   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_RequestDomainUpload_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     RequestDomainUpload_Request_sequence, hf_index, ett_iec61850_RequestDomainUpload_Request);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_04_sequence_of[1] = {
  { &hf_iec61850_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfCapabilities_04(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfCapabilities_04_sequence_of, hf_index, ett_iec61850_T_listOfCapabilities_04);

  return offset;
}


static const ber_sequence_t LoadDomainContent_Request_sequence[] = {
  { &hf_iec61850_domainName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_listOfCapabilities_04, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfCapabilities_04 },
  { &hf_iec61850_sharable   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_fileName   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { &hf_iec61850_thirdParty , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_LoadDomainContent_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     LoadDomainContent_Request_sequence, hf_index, ett_iec61850_LoadDomainContent_Request);

  return offset;
}


static const ber_sequence_t StoreDomainContent_Request_sequence[] = {
  { &hf_iec61850_domainName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_filenName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { &hf_iec61850_thirdParty , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_StoreDomainContent_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     StoreDomainContent_Request_sequence, hf_index, ett_iec61850_StoreDomainContent_Request);

  return offset;
}



static int
dissect_iec61850_DeleteDomain_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_GetDomainAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Identifier_sequence_of[1] = {
  { &hf_iec61850_listOfIdentifier_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_Identifier },
};

static int
dissect_iec61850_SEQUENCE_OF_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_Identifier_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_Identifier);

  return offset;
}


static const ber_sequence_t CreateProgramInvocation_Request_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_listOfDomainName, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_Identifier },
  { &hf_iec61850_reusable   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_monitorType, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_CreateProgramInvocation_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     CreateProgramInvocation_Request_sequence, hf_index, ett_iec61850_CreateProgramInvocation_Request);

  return offset;
}



static int
dissect_iec61850_DeleteProgramInvocation_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_executionArgument_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument_choice[] = {
  {   0, &hf_iec61850_simpleString, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  {   1, &hf_iec61850_encodedString, -1/*imported*/, -1/*imported*/, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_executionArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_executionArgument_choice, hf_index, ett_iec61850_T_executionArgument,
                                   NULL);

  return offset;
}


static const ber_sequence_t Start_Request_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_executionArgument, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_executionArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Start_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Start_Request_sequence, hf_index, ett_iec61850_Start_Request);

  return offset;
}


static const ber_sequence_t Stop_Request_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Stop_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Stop_Request_sequence, hf_index, ett_iec61850_Stop_Request);

  return offset;
}


static const value_string iec61850_T_executionArgument_01_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument_01_choice[] = {
  {   0, &hf_iec61850_simpleString, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  {   1, &hf_iec61850_encodedString, -1/*imported*/, -1/*imported*/, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_executionArgument_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_executionArgument_01_choice, hf_index, ett_iec61850_T_executionArgument_01,
                                   NULL);

  return offset;
}


static const ber_sequence_t Resume_Request_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_executionArgument_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_executionArgument_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Resume_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Resume_Request_sequence, hf_index, ett_iec61850_Resume_Request);

  return offset;
}


static const ber_sequence_t Reset_Request_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Reset_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Reset_Request_sequence, hf_index, ett_iec61850_Reset_Request);

  return offset;
}


static const ber_sequence_t Kill_Request_sequence[] = {
  { &hf_iec61850_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Kill_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Kill_Request_sequence, hf_index, ett_iec61850_Kill_Request);

  return offset;
}



static int
dissect_iec61850_GetProgramInvocationAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ObtainFile_Request_sequence[] = {
  { &hf_iec61850_sourceFileServer, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_ApplicationReference },
  { &hf_iec61850_sourceFile , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { &hf_iec61850_destinationFile, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ObtainFile_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ObtainFile_Request_sequence, hf_index, ett_iec61850_ObtainFile_Request);

  return offset;
}


static const value_string iec61850_EC_Class_vals[] = {
  {   0, "network-triggered" },
  {   1, "monitored" },
  { 0, NULL }
};


static int
dissect_iec61850_EC_Class(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t DefineEventCondition_Request_sequence[] = {
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_class_01   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_EC_Class },
  { &hf_iec61850_prio_rity  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Priority },
  { &hf_iec61850_severity   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { &hf_iec61850_alarmSummaryReports, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_monitoredVariable, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableSpecification },
  { &hf_iec61850_evaluationInterval, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineEventCondition_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineEventCondition_Request_sequence, hf_index, ett_iec61850_DefineEventCondition_Request);

  return offset;
}


static const value_string iec61850_DeleteEventCondition_Request_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventCondition_Request_choice[] = {
  {   0, &hf_iec61850_specific   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_ObjectName },
  {   1, &hf_iec61850_aa_specific_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  {   2, &hf_iec61850_domain     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   3, &hf_iec61850_vmd        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteEventCondition_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   DeleteEventCondition_Request_choice, hf_index, ett_iec61850_DeleteEventCondition_Request,
                                   NULL);

  return offset;
}



static int
dissect_iec61850_GetEventConditionAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_ReportEventConditionStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AlterEventConditionMonitoring_Request_sequence[] = {
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_enabled    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_priority   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Priority },
  { &hf_iec61850_alarmSummaryReports, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_evaluationInterval, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AlterEventConditionMonitoring_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AlterEventConditionMonitoring_Request_sequence, hf_index, ett_iec61850_AlterEventConditionMonitoring_Request);

  return offset;
}


static const ber_sequence_t TriggerEvent_Request_sequence[] = {
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_priority   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Priority },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_TriggerEvent_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     TriggerEvent_Request_sequence, hf_index, ett_iec61850_TriggerEvent_Request);

  return offset;
}


static const ber_sequence_t DefineEventAction_Request_sequence[] = {
  { &hf_iec61850_eventActionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_listOfModifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_Modifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineEventAction_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineEventAction_Request_sequence, hf_index, ett_iec61850_DefineEventAction_Request);

  return offset;
}


static const value_string iec61850_DeleteEventAction_Request_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   3, "domain" },
  {   4, "vmd" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventAction_Request_choice[] = {
  {   0, &hf_iec61850_specific   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_ObjectName },
  {   1, &hf_iec61850_aa_specific_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  {   3, &hf_iec61850_domain     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   4, &hf_iec61850_vmd        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteEventAction_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   DeleteEventAction_Request_choice, hf_index, ett_iec61850_DeleteEventAction_Request,
                                   NULL);

  return offset;
}



static int
dissect_iec61850_GetEventActionAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_ReportEventActionStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_AlarmAckRule_vals[] = {
  {   0, "none" },
  {   1, "simple" },
  {   2, "ack-active" },
  {   3, "ack-all" },
  { 0, NULL }
};


static int
dissect_iec61850_AlarmAckRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t DefineEventEnrollment_Request_sequence[] = {
  { &hf_iec61850_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventConditionTransition, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Transitions },
  { &hf_iec61850_alarmAcknowledgementRule, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_AlarmAckRule },
  { &hf_iec61850_eventActionName, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_clientApplication, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_iec61850_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DefineEventEnrollment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DefineEventEnrollment_Request_sequence, hf_index, ett_iec61850_DefineEventEnrollment_Request);

  return offset;
}


static const value_string iec61850_DeleteEventEnrollment_Request_vals[] = {
  {   0, "specific" },
  {   1, "ec" },
  {   2, "ea" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventEnrollment_Request_choice[] = {
  {   0, &hf_iec61850_specific   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_ObjectName },
  {   1, &hf_iec61850_ec         , BER_CLASS_CON, 1, 0, dissect_iec61850_ObjectName },
  {   2, &hf_iec61850_ea         , BER_CLASS_CON, 2, 0, dissect_iec61850_ObjectName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteEventEnrollment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   DeleteEventEnrollment_Request_choice, hf_index, ett_iec61850_DeleteEventEnrollment_Request,
                                   NULL);

  return offset;
}


static const ber_sequence_t AlterEventEnrollment_Request_sequence[] = {
  { &hf_iec61850_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventConditionTransitions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Transitions },
  { &hf_iec61850_alarmAcknowledgmentRule, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlarmAckRule },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AlterEventEnrollment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AlterEventEnrollment_Request_sequence, hf_index, ett_iec61850_AlterEventEnrollment_Request);

  return offset;
}



static int
dissect_iec61850_ReportEventEnrollmentStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_scopeOfRequest_vals[] = {
  {   0, "specific" },
  {   1, "client" },
  {   2, "ec" },
  {   3, "ea" },
  { 0, NULL }
};


static int
dissect_iec61850_T_scopeOfRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t GetEventEnrollmentAttributes_Request_sequence[] = {
  { &hf_iec61850_scopeOfRequest, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_scopeOfRequest },
  { &hf_iec61850_eventEnrollmentNames, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_ObjectName },
  { &hf_iec61850_clientApplication, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_iec61850_ApplicationReference },
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventActionName, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_getEventEnrollmentAttributes_Request_continueAfter, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetEventEnrollmentAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetEventEnrollmentAttributes_Request_sequence, hf_index, ett_iec61850_GetEventEnrollmentAttributes_Request);

  return offset;
}


static const value_string iec61850_EC_State_vals[] = {
  {   0, "disabled" },
  {   1, "idle" },
  {   2, "active" },
  { 0, NULL }
};


static int
dissect_iec61850_EC_State(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_EventTime_vals[] = {
  {   0, "timeOfDayT" },
  {   1, "timeSequenceIdentifier" },
  { 0, NULL }
};

static const ber_choice_t EventTime_choice[] = {
  {   0, &hf_iec61850_timeOfDayT , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_TimeOfDay },
  {   1, &hf_iec61850_timeSequenceIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_EventTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   EventTime_choice, hf_index, ett_iec61850_EventTime,
                                   NULL);

  return offset;
}


static const ber_sequence_t AcknowledgeEventNotification_Request_sequence[] = {
  { &hf_iec61850_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_acknowledgedState, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_EC_State },
  { &hf_iec61850_timeOfAcknowledgedTransition, BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AcknowledgeEventNotification_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AcknowledgeEventNotification_Request_sequence, hf_index, ett_iec61850_AcknowledgeEventNotification_Request);

  return offset;
}


static const value_string iec61850_T_acknowledgmentFilter_vals[] = {
  {   0, "not-acked" },
  {   1, "acked" },
  {   2, "all" },
  { 0, NULL }
};


static int
dissect_iec61850_T_acknowledgmentFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t T_severityFilter_sequence[] = {
  { &hf_iec61850_mostSevere , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { &hf_iec61850_leastSevere, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_severityFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_severityFilter_sequence, hf_index, ett_iec61850_T_severityFilter);

  return offset;
}


static const ber_sequence_t GetAlarmSummary_Request_sequence[] = {
  { &hf_iec61850_enrollmentsOnly, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_activeAlarmsOnly, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_acknowledgmentFilter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_acknowledgmentFilter },
  { &hf_iec61850_severityFilter, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_severityFilter },
  { &hf_iec61850_continueAfter, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetAlarmSummary_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetAlarmSummary_Request_sequence, hf_index, ett_iec61850_GetAlarmSummary_Request);

  return offset;
}


static const value_string iec61850_T_acknowledgmentFilter_01_vals[] = {
  {   0, "not-acked" },
  {   1, "acked" },
  {   2, "all" },
  { 0, NULL }
};


static int
dissect_iec61850_T_acknowledgmentFilter_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t T_severityFilter_01_sequence[] = {
  { &hf_iec61850_mostSevere , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { &hf_iec61850_leastSevere, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_severityFilter_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_severityFilter_01_sequence, hf_index, ett_iec61850_T_severityFilter_01);

  return offset;
}


static const ber_sequence_t GetAlarmEnrollmentSummary_Request_sequence[] = {
  { &hf_iec61850_enrollmentsOnly, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_activeAlarmsOnly, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_acknowledgmentFilter_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_acknowledgmentFilter_01 },
  { &hf_iec61850_severityFilter_01, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_severityFilter_01 },
  { &hf_iec61850_getAlarmEnrollmentSummary_Request_continueAfter, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetAlarmEnrollmentSummary_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetAlarmEnrollmentSummary_Request_sequence, hf_index, ett_iec61850_GetAlarmEnrollmentSummary_Request);

  return offset;
}


static const value_string iec61850_T_rangeStartSpecification_vals[] = {
  {   0, "startingTime" },
  {   1, "startingEntry" },
  { 0, NULL }
};

static const ber_choice_t T_rangeStartSpecification_choice[] = {
  {   0, &hf_iec61850_startingTime, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_TimeOfDay },
  {   1, &hf_iec61850_startingEntry, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_rangeStartSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_rangeStartSpecification_choice, hf_index, ett_iec61850_T_rangeStartSpecification,
                                   NULL);

  return offset;
}


static const value_string iec61850_T_rangeStopSpecification_vals[] = {
  {   0, "endingTime" },
  {   1, "numberOfEntries" },
  { 0, NULL }
};

static const ber_choice_t T_rangeStopSpecification_choice[] = {
  {   0, &hf_iec61850_endingTime , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_TimeOfDay },
  {   1, &hf_iec61850_numberOfEntries, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_rangeStopSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_rangeStopSpecification_choice, hf_index, ett_iec61850_T_rangeStopSpecification,
                                   NULL);

  return offset;
}


static const ber_sequence_t T_listOfVariables_sequence_of[1] = {
  { &hf_iec61850_listOfVariables_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfVariables(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfVariables_sequence_of, hf_index, ett_iec61850_T_listOfVariables);

  return offset;
}


static const ber_sequence_t T_entryToStartAfter_sequence[] = {
  { &hf_iec61850_timeSpecification, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_TimeOfDay },
  { &hf_iec61850_entrySpecification, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_entryToStartAfter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_entryToStartAfter_sequence, hf_index, ett_iec61850_T_entryToStartAfter);

  return offset;
}


static const ber_sequence_t ReadJournal_Request_sequence[] = {
  { &hf_iec61850_journalName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_rangeStartSpecification, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_iec61850_T_rangeStartSpecification },
  { &hf_iec61850_rangeStopSpecification, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_iec61850_T_rangeStopSpecification },
  { &hf_iec61850_listOfVariables, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfVariables },
  { &hf_iec61850_entryToStartAfter, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_T_entryToStartAfter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReadJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReadJournal_Request_sequence, hf_index, ett_iec61850_ReadJournal_Request);

  return offset;
}



static int
dissect_iec61850_JOU_Additional_Detail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_event_sequence[] = {
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_currentState, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_EC_State },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_event(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_event_sequence, hf_index, ett_iec61850_T_event);

  return offset;
}


static const ber_sequence_t T_listOfVariables_item_sequence[] = {
  { &hf_iec61850_variableTag, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  { &hf_iec61850_valueSpecification, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_Data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_listOfVariables_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_listOfVariables_item_sequence, hf_index, ett_iec61850_T_listOfVariables_item);

  return offset;
}


static const ber_sequence_t T_listOfVariables_01_sequence_of[1] = {
  { &hf_iec61850_listOfVariables_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_T_listOfVariables_item },
};

static int
dissect_iec61850_T_listOfVariables_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfVariables_01_sequence_of, hf_index, ett_iec61850_T_listOfVariables_01);

  return offset;
}


static const ber_sequence_t T_data_sequence[] = {
  { &hf_iec61850_event      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_event },
  { &hf_iec61850_listOfVariables_01, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfVariables_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_data_sequence, hf_index, ett_iec61850_T_data);

  return offset;
}


static const value_string iec61850_T_entryForm_vals[] = {
  {   2, "data" },
  {   3, "annotation" },
  { 0, NULL }
};

static const ber_choice_t T_entryForm_choice[] = {
  {   2, &hf_iec61850_data       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_T_data },
  {   3, &hf_iec61850_annotation , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_entryForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_entryForm_choice, hf_index, ett_iec61850_T_entryForm,
                                   NULL);

  return offset;
}


static const ber_sequence_t EntryContent_sequence[] = {
  { &hf_iec61850_occurenceTime, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_TimeOfDay },
  { &hf_iec61850_additionalDetail, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_iec61850_JOU_Additional_Detail },
  { &hf_iec61850_entryForm  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_entryForm },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_EntryContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     EntryContent_sequence, hf_index, ett_iec61850_EntryContent);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EntryContent_sequence_of[1] = {
  { &hf_iec61850_listOfJournalEntry_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_EntryContent },
};

static int
dissect_iec61850_SEQUENCE_OF_EntryContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_EntryContent_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_EntryContent);

  return offset;
}


static const ber_sequence_t WriteJournal_Request_sequence[] = {
  { &hf_iec61850_journalName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_listOfJournalEntry_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_EntryContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_WriteJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     WriteJournal_Request_sequence, hf_index, ett_iec61850_WriteJournal_Request);

  return offset;
}


static const ber_sequence_t T_limitSpecification_sequence[] = {
  { &hf_iec61850_limitingTime, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_TimeOfDay },
  { &hf_iec61850_limitingEntry, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_limitSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_limitSpecification_sequence, hf_index, ett_iec61850_T_limitSpecification);

  return offset;
}


static const ber_sequence_t InitializeJournal_Request_sequence[] = {
  { &hf_iec61850_journalName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_limitSpecification, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_limitSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_InitializeJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     InitializeJournal_Request_sequence, hf_index, ett_iec61850_InitializeJournal_Request);

  return offset;
}



static int
dissect_iec61850_ReportJournalStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CreateJournal_Request_sequence[] = {
  { &hf_iec61850_journalName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_CreateJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     CreateJournal_Request_sequence, hf_index, ett_iec61850_CreateJournal_Request);

  return offset;
}


static const ber_sequence_t DeleteJournal_Request_sequence[] = {
  { &hf_iec61850_journalName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DeleteJournal_Request_sequence, hf_index, ett_iec61850_DeleteJournal_Request);

  return offset;
}


static const ber_sequence_t GetCapabilityList_Request_sequence[] = {
  { &hf_iec61850_getCapabilityList_Request_continueAfter, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetCapabilityList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetCapabilityList_Request_sequence, hf_index, ett_iec61850_GetCapabilityList_Request);

  return offset;
}


static const ber_sequence_t FileOpen_Request_sequence[] = {
  { &hf_iec61850_fileName   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { &hf_iec61850_initialPosition, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_FileOpen_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     FileOpen_Request_sequence, hf_index, ett_iec61850_FileOpen_Request);

  return offset;
}



static int
dissect_iec61850_FileRead_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_FileClose_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t FileRename_Request_sequence[] = {
  { &hf_iec61850_currentFileName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { &hf_iec61850_newFileName, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_FileRename_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     FileRename_Request_sequence, hf_index, ett_iec61850_FileRename_Request);

  return offset;
}



static int
dissect_iec61850_FileDelete_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_FileName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t FileDirectory_Request_sequence[] = {
  { &hf_iec61850_fileSpecification, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { &hf_iec61850_fileDirectory_Request_continueAfter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_FileDirectory_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     FileDirectory_Request_sequence, hf_index, ett_iec61850_FileDirectory_Request);

  return offset;
}


static const value_string iec61850_ConfirmedServiceRequest_vals[] = {
  {   0, "status" },
  {   1, "getNameList" },
  {   2, "identify" },
  {   3, "rename" },
  {   4, "read" },
  {   5, "write" },
  {   6, "getVariableAccessAttributes" },
  {   7, "defineNamedVariable" },
  {   8, "defineScatteredAccess" },
  {   9, "getScatteredAccessAttributes" },
  {  10, "deleteVariableAccess" },
  {  11, "defineNamedVariableList" },
  {  12, "getNamedVariableListAttributes" },
  {  13, "deleteNamedVariableList" },
  {  14, "defineNamedType" },
  {  15, "getNamedTypeAttributes" },
  {  16, "deleteNamedType" },
  {  17, "input" },
  {  18, "output" },
  {  19, "takeControl" },
  {  20, "relinquishControl" },
  {  21, "defineSemaphore" },
  {  22, "deleteSemaphore" },
  {  23, "reportSemaphoreStatus" },
  {  24, "reportPoolSemaphoreStatus" },
  {  25, "reportSemaphoreEntryStatus" },
  {  26, "initiateDownloadSequence" },
  {  27, "downloadSegment" },
  {  28, "terminateDownloadSequence" },
  {  29, "initiateUploadSequence" },
  {  30, "uploadSegment" },
  {  31, "terminateUploadSequence" },
  {  32, "requestDomainDownload" },
  {  33, "requestDomainUpload" },
  {  34, "loadDomainContent" },
  {  35, "storeDomainContent" },
  {  36, "deleteDomain" },
  {  37, "getDomainAttributes" },
  {  38, "createProgramInvocation" },
  {  39, "deleteProgramInvocation" },
  {  40, "start" },
  {  41, "stop" },
  {  42, "resume" },
  {  43, "reset" },
  {  44, "kill" },
  {  45, "getProgramInvocationAttributes" },
  {  46, "obtainFile" },
  {  47, "defineEventCondition" },
  {  48, "deleteEventCondition" },
  {  49, "getEventConditionAttributes" },
  {  50, "reportEventConditionStatus" },
  {  51, "alterEventConditionMonitoring" },
  {  52, "triggerEvent" },
  {  53, "defineEventAction" },
  {  54, "deleteEventAction" },
  {  55, "getEventActionAttributes" },
  {  56, "reportEventActionStatus" },
  {  57, "defineEventEnrollment" },
  {  58, "deleteEventEnrollment" },
  {  59, "alterEventEnrollment" },
  {  60, "reportEventEnrollmentStatus" },
  {  61, "getEventEnrollmentAttributes" },
  {  62, "acknowledgeEventNotification" },
  {  63, "getAlarmSummary" },
  {  64, "getAlarmEnrollmentSummary" },
  {  65, "readJournal" },
  {  66, "writeJournal" },
  {  67, "initializeJournal" },
  {  68, "reportJournalStatus" },
  {  69, "createJournal" },
  {  70, "deleteJournal" },
  {  71, "getCapabilityList" },
  {  72, "fileOpen" },
  {  73, "fileRead" },
  {  74, "fileClose" },
  {  75, "fileRename" },
  {  76, "fileDelete" },
  {  77, "fileDirectory" },
  { 0, NULL }
};

static const ber_choice_t ConfirmedServiceRequest_choice[] = {
  {   0, &hf_iec61850_status     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Status_Request },
  {   1, &hf_iec61850_getNameList, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_GetNameList_Request },
  {   2, &hf_iec61850_identify   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Identify_Request },
  {   3, &hf_iec61850_rename     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_Rename_Request },
  {   4, &hf_iec61850_read       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_Read_Request },
  {   5, &hf_iec61850_write      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_Write_Request },
  {   6, &hf_iec61850_getVariableAccessAttributes, BER_CLASS_CON, 6, 0, dissect_iec61850_GetVariableAccessAttributes_Request },
  {   7, &hf_iec61850_defineNamedVariable, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineNamedVariable_Request },
  {   8, &hf_iec61850_defineScatteredAccess, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineScatteredAccess_Request },
  {   9, &hf_iec61850_getScatteredAccessAttributes, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_GetScatteredAccessAttributes_Request },
  {  10, &hf_iec61850_deleteVariableAccess, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteVariableAccess_Request },
  {  11, &hf_iec61850_defineNamedVariableList, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineNamedVariableList_Request },
  {  12, &hf_iec61850_getNamedVariableListAttributes, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_iec61850_GetNamedVariableListAttributes_Request },
  {  13, &hf_iec61850_deleteNamedVariableList, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteNamedVariableList_Request },
  {  14, &hf_iec61850_defineNamedType, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineNamedType_Request },
  {  15, &hf_iec61850_getNamedTypeAttributes, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_iec61850_GetNamedTypeAttributes_Request },
  {  16, &hf_iec61850_deleteNamedType, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteNamedType_Request },
  {  17, &hf_iec61850_input      , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_iec61850_Input_Request },
  {  18, &hf_iec61850_output     , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_iec61850_Output_Request },
  {  19, &hf_iec61850_takeControl, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_iec61850_TakeControl_Request },
  {  20, &hf_iec61850_relinquishControl, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_iec61850_RelinquishControl_Request },
  {  21, &hf_iec61850_defineSemaphore, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineSemaphore_Request },
  {  22, &hf_iec61850_deleteSemaphore, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteSemaphore_Request },
  {  23, &hf_iec61850_reportSemaphoreStatus, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportSemaphoreStatus_Request },
  {  24, &hf_iec61850_reportPoolSemaphoreStatus, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportPoolSemaphoreStatus_Request },
  {  25, &hf_iec61850_reportSemaphoreEntryStatus, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportSemaphoreEntryStatus_Request },
  {  26, &hf_iec61850_initiateDownloadSequence, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_iec61850_InitiateDownloadSequence_Request },
  {  27, &hf_iec61850_downloadSegment, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_iec61850_DownloadSegment_Request },
  {  28, &hf_iec61850_terminateDownloadSequence, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_iec61850_TerminateDownloadSequence_Request },
  {  29, &hf_iec61850_initiateUploadSequence, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_iec61850_InitiateUploadSequence_Request },
  {  30, &hf_iec61850_uploadSegment, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_iec61850_UploadSegment_Request },
  {  31, &hf_iec61850_terminateUploadSequence, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_iec61850_TerminateUploadSequence_Request },
  {  32, &hf_iec61850_requestDomainDownload, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_iec61850_RequestDomainDownload_Request },
  {  33, &hf_iec61850_requestDomainUpload, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_iec61850_RequestDomainUpload_Request },
  {  34, &hf_iec61850_loadDomainContent, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_iec61850_LoadDomainContent_Request },
  {  35, &hf_iec61850_storeDomainContent, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_iec61850_StoreDomainContent_Request },
  {  36, &hf_iec61850_deleteDomain, BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteDomain_Request },
  {  37, &hf_iec61850_getDomainAttributes, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_iec61850_GetDomainAttributes_Request },
  {  38, &hf_iec61850_createProgramInvocation, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_iec61850_CreateProgramInvocation_Request },
  {  39, &hf_iec61850_deleteProgramInvocation, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteProgramInvocation_Request },
  {  40, &hf_iec61850_start      , BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_iec61850_Start_Request },
  {  41, &hf_iec61850_stop       , BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_iec61850_Stop_Request },
  {  42, &hf_iec61850_resume     , BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_iec61850_Resume_Request },
  {  43, &hf_iec61850_reset      , BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_iec61850_Reset_Request },
  {  44, &hf_iec61850_kill       , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_iec61850_Kill_Request },
  {  45, &hf_iec61850_getProgramInvocationAttributes, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_iec61850_GetProgramInvocationAttributes_Request },
  {  46, &hf_iec61850_obtainFile , BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_iec61850_ObtainFile_Request },
  {  47, &hf_iec61850_defineEventCondition, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineEventCondition_Request },
  {  48, &hf_iec61850_confirmedServiceRequest_deleteEventCondition, BER_CLASS_CON, 48, 0, dissect_iec61850_DeleteEventCondition_Request },
  {  49, &hf_iec61850_getEventConditionAttributes, BER_CLASS_CON, 49, 0, dissect_iec61850_GetEventConditionAttributes_Request },
  {  50, &hf_iec61850_reportEventConditionStatus, BER_CLASS_CON, 50, 0, dissect_iec61850_ReportEventConditionStatus_Request },
  {  51, &hf_iec61850_alterEventConditionMonitoring, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_iec61850_AlterEventConditionMonitoring_Request },
  {  52, &hf_iec61850_triggerEvent, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_iec61850_TriggerEvent_Request },
  {  53, &hf_iec61850_defineEventAction, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineEventAction_Request },
  {  54, &hf_iec61850_confirmedServiceRequest_deleteEventAction, BER_CLASS_CON, 54, 0, dissect_iec61850_DeleteEventAction_Request },
  {  55, &hf_iec61850_getEventActionAttributes, BER_CLASS_CON, 55, 0, dissect_iec61850_GetEventActionAttributes_Request },
  {  56, &hf_iec61850_reportEventActionStatus, BER_CLASS_CON, 56, 0, dissect_iec61850_ReportEventActionStatus_Request },
  {  57, &hf_iec61850_defineEventEnrollment, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineEventEnrollment_Request },
  {  58, &hf_iec61850_confirmedServiceRequest_deleteEventEnrollment, BER_CLASS_CON, 58, 0, dissect_iec61850_DeleteEventEnrollment_Request },
  {  59, &hf_iec61850_alterEventEnrollment, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_iec61850_AlterEventEnrollment_Request },
  {  60, &hf_iec61850_reportEventEnrollmentStatus, BER_CLASS_CON, 60, 0, dissect_iec61850_ReportEventEnrollmentStatus_Request },
  {  61, &hf_iec61850_getEventEnrollmentAttributes, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_iec61850_GetEventEnrollmentAttributes_Request },
  {  62, &hf_iec61850_acknowledgeEventNotification, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_iec61850_AcknowledgeEventNotification_Request },
  {  63, &hf_iec61850_getAlarmSummary, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_iec61850_GetAlarmSummary_Request },
  {  64, &hf_iec61850_getAlarmEnrollmentSummary, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_iec61850_GetAlarmEnrollmentSummary_Request },
  {  65, &hf_iec61850_readJournal, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_iec61850_ReadJournal_Request },
  {  66, &hf_iec61850_writeJournal, BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_iec61850_WriteJournal_Request },
  {  67, &hf_iec61850_initializeJournal, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_iec61850_InitializeJournal_Request },
  {  68, &hf_iec61850_reportJournalStatus, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportJournalStatus_Request },
  {  69, &hf_iec61850_createJournal, BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_iec61850_CreateJournal_Request },
  {  70, &hf_iec61850_deleteJournal, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteJournal_Request },
  {  71, &hf_iec61850_getCapabilityList, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_iec61850_GetCapabilityList_Request },
  {  72, &hf_iec61850_fileOpen   , BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_iec61850_FileOpen_Request },
  {  73, &hf_iec61850_fileRead   , BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_iec61850_FileRead_Request },
  {  74, &hf_iec61850_fileClose  , BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_iec61850_FileClose_Request },
  {  75, &hf_iec61850_fileRename , BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_iec61850_FileRename_Request },
  {  76, &hf_iec61850_fileDelete , BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_iec61850_FileDelete_Request },
  {  77, &hf_iec61850_fileDirectory, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_iec61850_FileDirectory_Request },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ConfirmedServiceRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   ConfirmedServiceRequest_choice, hf_index, ett_iec61850_ConfirmedServiceRequest,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->Service = branch_taken;


  return offset;
}


static const value_string iec61850_CS_Request_Detail_vals[] = {
  {   0, "foo" },
  { 0, NULL }
};

static const ber_choice_t CS_Request_Detail_choice[] = {
  {   0, &hf_iec61850_foo        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iec61850_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_CS_Request_Detail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   CS_Request_Detail_choice, hf_index, ett_iec61850_CS_Request_Detail,
                                   NULL);

  return offset;
}


static const ber_sequence_t Confirmed_RequestPDU_sequence[] = {
  { &hf_iec61850_invokeID   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_listOfModifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_iec61850_SEQUENCE_OF_Modifier },
  { &hf_iec61850_confirmedServiceRequest, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ConfirmedServiceRequest },
  { &hf_iec61850_cs_request_detail, BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_CS_Request_Detail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Confirmed_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Confirmed_RequestPDU_sequence, hf_index, ett_iec61850_Confirmed_RequestPDU);

  return offset;
}


static const value_string iec61850_T_vmdLogicalStatus_vals[] = {
  {   0, "state-changes-allowed" },
  {   1, "no-state-changes-allowed" },
  {   2, "limited-services-allowed" },
  {   3, "support-services-allowed" },
  { 0, NULL }
};


static int
dissect_iec61850_T_vmdLogicalStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_vmdPhysicalStatus_vals[] = {
  {   0, "operational" },
  {   1, "partially-operational" },
  {   2, "inoperable" },
  {   3, "needs-commissioning" },
  { 0, NULL }
};


static int
dissect_iec61850_T_vmdPhysicalStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}



static int
dissect_iec61850_BIT_STRING_SIZE_0_128(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                      NULL, 0, hf_index, -1,
                                      NULL);

  return offset;
}


static const ber_sequence_t Status_Response_sequence[] = {
  { &hf_iec61850_vmdLogicalStatus, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_vmdLogicalStatus },
  { &hf_iec61850_vmdPhysicalStatus, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_vmdPhysicalStatus },
  { &hf_iec61850_localDetail, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BIT_STRING_SIZE_0_128 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Status_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Status_Response_sequence, hf_index, ett_iec61850_Status_Response);

  return offset;
}


static const ber_sequence_t GetNameList_Response_sequence[] = {
  { &hf_iec61850_listOfIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_Identifier },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetNameList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetNameList_Response_sequence, hf_index, ett_iec61850_GetNameList_Response);

  return offset;
}


static const ber_sequence_t T_listOfAbstractSyntaxes_sequence_of[1] = {
  { &hf_iec61850_listOfAbstractSyntaxes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_iec61850_OBJECT_IDENTIFIER },
};

static int
dissect_iec61850_T_listOfAbstractSyntaxes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfAbstractSyntaxes_sequence_of, hf_index, ett_iec61850_T_listOfAbstractSyntaxes);

  return offset;
}


static const ber_sequence_t Identify_Response_sequence[] = {
  { &hf_iec61850_vendorName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  { &hf_iec61850_modelName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  { &hf_iec61850_revision   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  { &hf_iec61850_listOfAbstractSyntaxes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfAbstractSyntaxes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Identify_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Identify_Response_sequence, hf_index, ett_iec61850_Identify_Response);

  return offset;
}



static int
dissect_iec61850_Rename_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_DataAccessError_vals[] = {
  {   0, "object-invalidated" },
  {   1, "hardware-fault" },
  {   2, "temporarily-unavailable" },
  {   3, "object-access-denied" },
  {   4, "object-undefined" },
  {   5, "invalid-address" },
  {   6, "type-unsupported" },
  {   7, "type-inconsistent" },
  {   8, "object-attribute-inconsistent" },
  {   9, "object-access-unsupported" },
  {  10, "object-non-existent" },
  {  11, "object-value-invalid" },
  { 0, NULL }
};


static int
dissect_iec61850_DataAccessError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->DataAccessError = branch_taken;
    private_data_add_moreCinfo_enum(actx, branch_taken, iec61850_DataAccessError_vals);


  return offset;
}


static const value_string iec61850_AccessResult_vals[] = {
  {   0, "failure" },
  {   1, "success" },
  { 0, NULL }
};

static const ber_choice_t AccessResult_choice[] = {
  {   0, &hf_iec61850_failure    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_DataAccessError },
  {   1, &hf_iec61850_success_01 , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_iec61850_Data },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AccessResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   AccessResult_choice, hf_index, ett_iec61850_AccessResult,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->Success = branch_taken;


  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AccessResult_sequence_of[1] = {
  { &hf_iec61850_listOfAccessResult_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_AccessResult },
};

static int
dissect_iec61850_SEQUENCE_OF_AccessResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_AccessResult_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_AccessResult);

  return offset;
}


static const ber_sequence_t Read_Response_sequence[] = {
  { &hf_iec61850_variableAccessSpecificatn, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableAccessSpecification },
  { &hf_iec61850_listOfAccessResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_AccessResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Read_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Read_Response_sequence, hf_index, ett_iec61850_Read_Response);

  return offset;
}


static const value_string iec61850_Write_Response_item_vals[] = {
  {   0, "failure" },
  {   1, "success" },
  { 0, NULL }
};

static const ber_choice_t Write_Response_item_choice[] = {
  {   0, &hf_iec61850_failure    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_DataAccessError },
  {   1, &hf_iec61850_success    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Write_Response_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   Write_Response_item_choice, hf_index, ett_iec61850_Write_Response_item,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->Success = branch_taken;


  return offset;
}


static const ber_sequence_t Write_Response_sequence_of[1] = {
  { &hf_iec61850_Write_Response_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_Write_Response_item },
};

static int
dissect_iec61850_Write_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        Write_Response_sequence_of, hf_index, ett_iec61850_Write_Response);

  return offset;
}


static const ber_sequence_t GetVariableAccessAttributes_Response_sequence[] = {
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_address    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_Address },
  { &hf_iec61850_typeSpecification, BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_iec61850_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetVariableAccessAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetVariableAccessAttributes_Response_sequence, hf_index, ett_iec61850_GetVariableAccessAttributes_Response);

  return offset;
}



static int
dissect_iec61850_DefineNamedVariable_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DefineScatteredAccess_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t GetScatteredAccessAttributes_Response_sequence[] = {
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_scatteredAccessDescription, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ScatteredAccessDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetScatteredAccessAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetScatteredAccessAttributes_Response_sequence, hf_index, ett_iec61850_GetScatteredAccessAttributes_Response);

  return offset;
}


static const ber_sequence_t DeleteVariableAccess_Response_sequence[] = {
  { &hf_iec61850_numberMatched, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_numberDeleted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteVariableAccess_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DeleteVariableAccess_Response_sequence, hf_index, ett_iec61850_DeleteVariableAccess_Response);

  return offset;
}



static int
dissect_iec61850_DefineNamedVariableList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfVariable_item_01_sequence[] = {
  { &hf_iec61850_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableSpecification },
  { &hf_iec61850_alternateAccess, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_listOfVariable_item_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_listOfVariable_item_01_sequence, hf_index, ett_iec61850_T_listOfVariable_item_01);

  return offset;
}


static const ber_sequence_t T_listOfVariable_01_sequence_of[1] = {
  { &hf_iec61850_listOfVariable_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_T_listOfVariable_item_01 },
};

static int
dissect_iec61850_T_listOfVariable_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfVariable_01_sequence_of, hf_index, ett_iec61850_T_listOfVariable_01);

  return offset;
}


static const ber_sequence_t GetNamedVariableListAttributes_Response_sequence[] = {
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_listOfVariable_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfVariable_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetNamedVariableListAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetNamedVariableListAttributes_Response_sequence, hf_index, ett_iec61850_GetNamedVariableListAttributes_Response);

  return offset;
}


static const ber_sequence_t DeleteNamedVariableList_Response_sequence[] = {
  { &hf_iec61850_numberMatched, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_numberDeleted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteNamedVariableList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DeleteNamedVariableList_Response_sequence, hf_index, ett_iec61850_DeleteNamedVariableList_Response);

  return offset;
}



static int
dissect_iec61850_DefineNamedType_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t GetNamedTypeAttributes_Response_sequence[] = {
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetNamedTypeAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetNamedTypeAttributes_Response_sequence, hf_index, ett_iec61850_GetNamedTypeAttributes_Response);

  return offset;
}


static const ber_sequence_t DeleteNamedType_Response_sequence[] = {
  { &hf_iec61850_numberMatched, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_numberDeleted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DeleteNamedType_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DeleteNamedType_Response_sequence, hf_index, ett_iec61850_DeleteNamedType_Response);

  return offset;
}



static int
dissect_iec61850_Input_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                              actx, tree, tvb, offset, hf_index,
                                              NULL);

  return offset;
}



static int
dissect_iec61850_Output_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_TakeControl_Response_vals[] = {
  {   0, "noResult" },
  {   1, "namedToken" },
  { 0, NULL }
};

static const ber_choice_t TakeControl_Response_choice[] = {
  {   0, &hf_iec61850_noResult   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  {   1, &hf_iec61850_namedToken , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_TakeControl_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   TakeControl_Response_choice, hf_index, ett_iec61850_TakeControl_Response,
                                   NULL);

  return offset;
}



static int
dissect_iec61850_RelinquishControl_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DefineSemaphore_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteSemaphore_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_T_class_vals[] = {
  {   0, "token" },
  {   1, "pool" },
  { 0, NULL }
};


static int
dissect_iec61850_T_class(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t ReportSemaphoreStatus_Response_sequence[] = {
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_class      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_class },
  { &hf_iec61850_numberOfTokens, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned16 },
  { &hf_iec61850_numberOfOwnedTokens, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned16 },
  { &hf_iec61850_numberOfHungTokens, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned16 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportSemaphoreStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportSemaphoreStatus_Response_sequence, hf_index, ett_iec61850_ReportSemaphoreStatus_Response);

  return offset;
}


static const value_string iec61850_T_listOfNamedTokens_item_vals[] = {
  {   0, "freeNamedToken" },
  {   1, "ownedNamedToken" },
  {   2, "hungNamedToken" },
  { 0, NULL }
};

static const ber_choice_t T_listOfNamedTokens_item_choice[] = {
  {   0, &hf_iec61850_freeNamedToken, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   1, &hf_iec61850_ownedNamedToken, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  {   2, &hf_iec61850_hungNamedToken, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_listOfNamedTokens_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_listOfNamedTokens_item_choice, hf_index, ett_iec61850_T_listOfNamedTokens_item,
                                   NULL);

  return offset;
}


static const ber_sequence_t T_listOfNamedTokens_sequence_of[1] = {
  { &hf_iec61850_listOfNamedTokens_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_listOfNamedTokens_item },
};

static int
dissect_iec61850_T_listOfNamedTokens(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfNamedTokens_sequence_of, hf_index, ett_iec61850_T_listOfNamedTokens);

  return offset;
}


static const ber_sequence_t ReportPoolSemaphoreStatus_Response_sequence[] = {
  { &hf_iec61850_listOfNamedTokens, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfNamedTokens },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportPoolSemaphoreStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportPoolSemaphoreStatus_Response_sequence, hf_index, ett_iec61850_ReportPoolSemaphoreStatus_Response);

  return offset;
}


static const value_string iec61850_T_entryClass_vals[] = {
  {   0, "simple" },
  {   1, "modifier" },
  { 0, NULL }
};


static int
dissect_iec61850_T_entryClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t SemaphoreEntry_sequence[] = {
  { &hf_iec61850_entryId    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { &hf_iec61850_entryClass , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_entryClass },
  { &hf_iec61850_applicationReference, BER_CLASS_CON, 2, 0, dissect_iec61850_ApplicationReference },
  { &hf_iec61850_namedToken , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Identifier },
  { &hf_iec61850_priority   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Priority },
  { &hf_iec61850_remainingTimeOut, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_abortOnTimeOut, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_relinquishIfConnectionLost, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_SemaphoreEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     SemaphoreEntry_sequence, hf_index, ett_iec61850_SemaphoreEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SemaphoreEntry_sequence_of[1] = {
  { &hf_iec61850_listOfSemaphoreEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_SemaphoreEntry },
};

static int
dissect_iec61850_SEQUENCE_OF_SemaphoreEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_SemaphoreEntry_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_SemaphoreEntry);

  return offset;
}


static const ber_sequence_t ReportSemaphoreEntryStatus_Response_sequence[] = {
  { &hf_iec61850_listOfSemaphoreEntry, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_SemaphoreEntry },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportSemaphoreEntryStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportSemaphoreEntryStatus_Response_sequence, hf_index, ett_iec61850_ReportSemaphoreEntryStatus_Response);

  return offset;
}



static int
dissect_iec61850_InitiateDownloadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_T_loadData_vals[] = {
  {   0, "non-coded" },
  {   1, "coded" },
  { 0, NULL }
};

static const ber_choice_t T_loadData_choice[] = {
  {   0, &hf_iec61850_non_coded  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  {   1, &hf_iec61850_coded      , -1/*imported*/, -1/*imported*/, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_loadData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_loadData_choice, hf_index, ett_iec61850_T_loadData,
                                   NULL);

  return offset;
}


static const ber_sequence_t DownloadSegment_Response_sequence[] = {
  { &hf_iec61850_loadData   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_loadData },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DownloadSegment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DownloadSegment_Response_sequence, hf_index, ett_iec61850_DownloadSegment_Response);

  return offset;
}



static int
dissect_iec61850_TerminateDownloadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_02_sequence_of[1] = {
  { &hf_iec61850_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfCapabilities_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfCapabilities_02_sequence_of, hf_index, ett_iec61850_T_listOfCapabilities_02);

  return offset;
}


static const ber_sequence_t InitiateUploadSequence_Response_sequence[] = {
  { &hf_iec61850_ulsmID     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  { &hf_iec61850_listOfCapabilities_02, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfCapabilities_02 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_InitiateUploadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     InitiateUploadSequence_Response_sequence, hf_index, ett_iec61850_InitiateUploadSequence_Response);

  return offset;
}


static const value_string iec61850_T_loadData_01_vals[] = {
  {   0, "non-coded" },
  {   1, "coded" },
  { 0, NULL }
};

static const ber_choice_t T_loadData_01_choice[] = {
  {   0, &hf_iec61850_non_coded  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  {   1, &hf_iec61850_coded      , -1/*imported*/, -1/*imported*/, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_loadData_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_loadData_01_choice, hf_index, ett_iec61850_T_loadData_01,
                                   NULL);

  return offset;
}


static const ber_sequence_t UploadSegment_Response_sequence[] = {
  { &hf_iec61850_loadData_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_loadData_01 },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_UploadSegment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     UploadSegment_Response_sequence, hf_index, ett_iec61850_UploadSegment_Response);

  return offset;
}



static int
dissect_iec61850_TerminateUploadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_RequestDomainDownload_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_RequestDomainUpload_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_LoadDomainContent_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_StoreDomainContent_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteDomain_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_05_sequence_of[1] = {
  { &hf_iec61850_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfCapabilities_05(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfCapabilities_05_sequence_of, hf_index, ett_iec61850_T_listOfCapabilities_05);

  return offset;
}


static const value_string iec61850_DomainState_vals[] = {
  {   0, "non-existent" },
  {   1, "loading" },
  {   2, "ready" },
  {   3, "in-use" },
  {   4, "complete" },
  {   5, "incomplete" },
  {   7, "d1" },
  {   8, "d2" },
  {   9, "d3" },
  {  10, "d4" },
  {  11, "d5" },
  {  12, "d6" },
  {  13, "d7" },
  {  14, "d8" },
  {  15, "d9" },
  { 0, NULL }
};


static int
dissect_iec61850_DomainState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}



static int
dissect_iec61850_Integer8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t GetDomainAttributes_Response_sequence[] = {
  { &hf_iec61850_listOfCapabilities_05, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfCapabilities_05 },
  { &hf_iec61850_getDomainAttributes_Response_state, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_DomainState },
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_sharable   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_listOfProgramInvocations, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_Identifier },
  { &hf_iec61850_uploadInProgress, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetDomainAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetDomainAttributes_Response_sequence, hf_index, ett_iec61850_GetDomainAttributes_Response);

  return offset;
}



static int
dissect_iec61850_CreateProgramInvocation_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteProgramInvocation_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_Start_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_Stop_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_Resume_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_Reset_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_Kill_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_T_executionArgument_02_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument_02_choice[] = {
  {   0, &hf_iec61850_simpleString, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  {   1, &hf_iec61850_encodedString, -1/*imported*/, -1/*imported*/, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_executionArgument_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_executionArgument_02_choice, hf_index, ett_iec61850_T_executionArgument_02,
                                   NULL);

  return offset;
}


static const ber_sequence_t GetProgramInvocationAttributes_Response_sequence[] = {
  { &hf_iec61850_getProgramInvocationAttributes_Response_state, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_ProgramInvocationState },
  { &hf_iec61850_listOfDomainNames, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_Identifier },
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_reusable   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_monitor    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_startArgument, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_VisibleString },
  { &hf_iec61850_executionArgument_02, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_executionArgument_02 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetProgramInvocationAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetProgramInvocationAttributes_Response_sequence, hf_index, ett_iec61850_GetProgramInvocationAttributes_Response);

  return offset;
}



static int
dissect_iec61850_ObtainFile_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t FileAttributes_sequence[] = {
  { &hf_iec61850_sizeOfFile , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_lastModified, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_FileAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     FileAttributes_sequence, hf_index, ett_iec61850_FileAttributes);

  return offset;
}


static const ber_sequence_t FileOpen_Response_sequence[] = {
  { &hf_iec61850_frsmID     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  { &hf_iec61850_fileAttributes, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_FileAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_FileOpen_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     FileOpen_Response_sequence, hf_index, ett_iec61850_FileOpen_Response);

  return offset;
}



static int
dissect_iec61850_DefineEventCondition_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteEventCondition_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_monitoredVariable_vals[] = {
  {   0, "variableReference" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_monitoredVariable_choice[] = {
  {   0, &hf_iec61850_variableReference, BER_CLASS_CON, 0, 0, dissect_iec61850_VariableSpecification },
  {   1, &hf_iec61850_undefined  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_monitoredVariable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_monitoredVariable_choice, hf_index, ett_iec61850_T_monitoredVariable,
                                   NULL);

  return offset;
}


static const ber_sequence_t GetEventConditionAttributes_Response_sequence[] = {
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_class_01   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_EC_Class },
  { &hf_iec61850_prio_rity  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Priority },
  { &hf_iec61850_severity   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { &hf_iec61850_alarmSummaryReports, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_monitoredVariable_01, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_iec61850_T_monitoredVariable },
  { &hf_iec61850_evaluationInterval, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetEventConditionAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetEventConditionAttributes_Response_sequence, hf_index, ett_iec61850_GetEventConditionAttributes_Response);

  return offset;
}


static const ber_sequence_t ReportEventConditionStatus_Response_sequence[] = {
  { &hf_iec61850_currentState, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_EC_State },
  { &hf_iec61850_numberOfEventEnrollments, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_enabled    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_timeOfLastTransitionToActive, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { &hf_iec61850_timeOfLastTransitionToIdle, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportEventConditionStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportEventConditionStatus_Response_sequence, hf_index, ett_iec61850_ReportEventConditionStatus_Response);

  return offset;
}



static int
dissect_iec61850_AlterEventConditionMonitoring_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_TriggerEvent_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DefineEventAction_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteEventAction_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t GetEventActionAttributes_Response_sequence[] = {
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_listOfModifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_Modifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetEventActionAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetEventActionAttributes_Response_sequence, hf_index, ett_iec61850_GetEventActionAttributes_Response);

  return offset;
}



static int
dissect_iec61850_ReportEventActionStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_DefineEventEnrollment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteEventEnrollment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_EE_State_vals[] = {
  {   0, "disabled" },
  {   1, "idle" },
  {   2, "active" },
  {   3, "activeNoAckA" },
  {   4, "idleNoAckI" },
  {   5, "idleNoAckA" },
  {   6, "idleAcked" },
  {   7, "activeAcked" },
  { 0, NULL }
};


static int
dissect_iec61850_EE_State(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_currentState_vals[] = {
  {   0, "state" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_currentState_choice[] = {
  {   0, &hf_iec61850_alterEventEnrollment_Response_currentState_state, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_EE_State },
  {   1, &hf_iec61850_undefined  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_currentState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_currentState_choice, hf_index, ett_iec61850_T_currentState,
                                   NULL);

  return offset;
}


static const ber_sequence_t AlterEventEnrollment_Response_sequence[] = {
  { &hf_iec61850_currentState_02, BER_CLASS_CON, 0, 0, dissect_iec61850_T_currentState },
  { &hf_iec61850_transitionTime, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AlterEventEnrollment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AlterEventEnrollment_Response_sequence, hf_index, ett_iec61850_AlterEventEnrollment_Response);

  return offset;
}


static const value_string iec61850_EE_Duration_vals[] = {
  {   0, "current" },
  {   1, "permanent" },
  { 0, NULL }
};


static int
dissect_iec61850_EE_Duration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t ReportEventEnrollmentStatus_Response_sequence[] = {
  { &hf_iec61850_eventConditionTransitions, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Transitions },
  { &hf_iec61850_notificationLost, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_duration   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_EE_Duration },
  { &hf_iec61850_alarmAcknowledgmentRule, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlarmAckRule },
  { &hf_iec61850_currentState_01, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_EE_State },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportEventEnrollmentStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportEventEnrollmentStatus_Response_sequence, hf_index, ett_iec61850_ReportEventEnrollmentStatus_Response);

  return offset;
}


static const value_string iec61850_T_eventConditionName_vals[] = {
  {   0, "eventCondition" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventConditionName_choice[] = {
  {   0, &hf_iec61850_eventCondition, BER_CLASS_CON, 0, 0, dissect_iec61850_ObjectName },
  {   1, &hf_iec61850_undefined  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_eventConditionName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_eventConditionName_choice, hf_index, ett_iec61850_T_eventConditionName,
                                   NULL);

  return offset;
}


static const value_string iec61850_T_eventActionName_vals[] = {
  {   0, "eventAction" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventActionName_choice[] = {
  {   0, &hf_iec61850_eventAction, BER_CLASS_CON, 0, 0, dissect_iec61850_ObjectName },
  {   1, &hf_iec61850_undefined  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_eventActionName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_eventActionName_choice, hf_index, ett_iec61850_T_eventActionName,
                                   NULL);

  return offset;
}


static const value_string iec61850_EE_Class_vals[] = {
  {   0, "modifier" },
  {   1, "notification" },
  { 0, NULL }
};


static int
dissect_iec61850_EE_Class(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t EventEnrollment_sequence[] = {
  { &hf_iec61850_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventConditionName_01, BER_CLASS_CON, 1, 0, dissect_iec61850_T_eventConditionName },
  { &hf_iec61850_eventActionName_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_iec61850_T_eventActionName },
  { &hf_iec61850_clientApplication, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_iec61850_ApplicationReference },
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_enrollmentClass, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_EE_Class },
  { &hf_iec61850_duration   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_EE_Duration },
  { &hf_iec61850_invokeID   , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_remainingAcceptableDelay, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_EventEnrollment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     EventEnrollment_sequence, hf_index, ett_iec61850_EventEnrollment);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EventEnrollment_sequence_of[1] = {
  { &hf_iec61850_listOfEventEnrollment_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_EventEnrollment },
};

static int
dissect_iec61850_SEQUENCE_OF_EventEnrollment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_EventEnrollment_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_EventEnrollment);

  return offset;
}


static const ber_sequence_t GetEventEnrollmentAttributes_Response_sequence[] = {
  { &hf_iec61850_listOfEventEnrollment, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_EventEnrollment },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetEventEnrollmentAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetEventEnrollmentAttributes_Response_sequence, hf_index, ett_iec61850_GetEventEnrollmentAttributes_Response);

  return offset;
}



static int
dissect_iec61850_AcknowledgeEventNotification_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string iec61850_T_unacknowledgedState_vals[] = {
  {   0, "none" },
  {   1, "active" },
  {   2, "idle" },
  {   3, "both" },
  { 0, NULL }
};


static int
dissect_iec61850_T_unacknowledgedState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const ber_sequence_t AlarmSummary_sequence[] = {
  { &hf_iec61850_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_severity   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { &hf_iec61850_currentState, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_EC_State },
  { &hf_iec61850_unacknowledgedState, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_T_unacknowledgedState },
  { &hf_iec61850_timeOfLastTransitionToActive, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { &hf_iec61850_timeOfLastTransitionToIdle, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AlarmSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AlarmSummary_sequence, hf_index, ett_iec61850_AlarmSummary);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlarmSummary_sequence_of[1] = {
  { &hf_iec61850_listOfAlarmSummary_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_AlarmSummary },
};

static int
dissect_iec61850_SEQUENCE_OF_AlarmSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_AlarmSummary_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_AlarmSummary);

  return offset;
}


static const ber_sequence_t GetAlarmSummary_Response_sequence[] = {
  { &hf_iec61850_listOfAlarmSummary, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_AlarmSummary },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetAlarmSummary_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetAlarmSummary_Response_sequence, hf_index, ett_iec61850_GetAlarmSummary_Response);

  return offset;
}


static const ber_sequence_t AlarmEnrollmentSummary_sequence[] = {
  { &hf_iec61850_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_clientApplication, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_iec61850_ApplicationReference },
  { &hf_iec61850_severity   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { &hf_iec61850_currentState, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_EC_State },
  { &hf_iec61850_notificationLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_alarmAcknowledgmentRule, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlarmAckRule },
  { &hf_iec61850_enrollementState, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_EE_State },
  { &hf_iec61850_timeOfLastTransitionToActive, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { &hf_iec61850_timeActiveAcknowledged, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { &hf_iec61850_timeOfLastTransitionToIdle, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { &hf_iec61850_timeIdleAcknowledged, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_AlarmEnrollmentSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     AlarmEnrollmentSummary_sequence, hf_index, ett_iec61850_AlarmEnrollmentSummary);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlarmEnrollmentSummary_sequence_of[1] = {
  { &hf_iec61850_listOfAlarmEnrollmentSummary_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_AlarmEnrollmentSummary },
};

static int
dissect_iec61850_SEQUENCE_OF_AlarmEnrollmentSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_AlarmEnrollmentSummary_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_AlarmEnrollmentSummary);

  return offset;
}


static const ber_sequence_t GetAlarmEnrollmentSummary_Response_sequence[] = {
  { &hf_iec61850_listOfAlarmEnrollmentSummary, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_AlarmEnrollmentSummary },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetAlarmEnrollmentSummary_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetAlarmEnrollmentSummary_Response_sequence, hf_index, ett_iec61850_GetAlarmEnrollmentSummary_Response);

  return offset;
}


static const ber_sequence_t JournalEntry_sequence[] = {
  { &hf_iec61850_entryIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { &hf_iec61850_originatingApplication, BER_CLASS_CON, 1, 0, dissect_iec61850_ApplicationReference },
  { &hf_iec61850_entryContent, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_EntryContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_JournalEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     JournalEntry_sequence, hf_index, ett_iec61850_JournalEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_JournalEntry_sequence_of[1] = {
  { &hf_iec61850_listOfJournalEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_JournalEntry },
};

static int
dissect_iec61850_SEQUENCE_OF_JournalEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_JournalEntry_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_JournalEntry);

  return offset;
}


static const ber_sequence_t ReadJournal_Response_sequence[] = {
  { &hf_iec61850_listOfJournalEntry, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_JournalEntry },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReadJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReadJournal_Response_sequence, hf_index, ett_iec61850_ReadJournal_Response);

  return offset;
}



static int
dissect_iec61850_WriteJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_InitializeJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportJournalStatus_Response_sequence[] = {
  { &hf_iec61850_currentEntries, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_mmsDeletable, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ReportJournalStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     ReportJournalStatus_Response_sequence, hf_index, ett_iec61850_ReportJournalStatus_Response);

  return offset;
}



static int
dissect_iec61850_CreateJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_DeleteJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_sequence_of[1] = {
  { &hf_iec61850_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_iec61850_VisibleString },
};

static int
dissect_iec61850_T_listOfCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        T_listOfCapabilities_sequence_of, hf_index, ett_iec61850_T_listOfCapabilities);

  return offset;
}


static const ber_sequence_t GetCapabilityList_Response_sequence[] = {
  { &hf_iec61850_listOfCapabilities, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_T_listOfCapabilities },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_GetCapabilityList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     GetCapabilityList_Response_sequence, hf_index, ett_iec61850_GetCapabilityList_Response);

  return offset;
}


static const ber_sequence_t FileRead_Response_sequence[] = {
  { &hf_iec61850_fileData   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_OCTET_STRING },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_FileRead_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     FileRead_Response_sequence, hf_index, ett_iec61850_FileRead_Response);

  return offset;
}



static int
dissect_iec61850_FileClose_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_FileRename_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_FileDelete_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t DirectoryEntry_sequence[] = {
  { &hf_iec61850_filename   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_FileName },
  { &hf_iec61850_fileAttributes, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_FileAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_DirectoryEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     DirectoryEntry_sequence, hf_index, ett_iec61850_DirectoryEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DirectoryEntry_sequence_of[1] = {
  { &hf_iec61850_listOfDirectoryEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_iec61850_DirectoryEntry },
};

static int
dissect_iec61850_SEQUENCE_OF_DirectoryEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                        SEQUENCE_OF_DirectoryEntry_sequence_of, hf_index, ett_iec61850_SEQUENCE_OF_DirectoryEntry);

  return offset;
}


static const ber_sequence_t FileDirectory_Response_sequence[] = {
  { &hf_iec61850_listOfDirectoryEntry, BER_CLASS_CON, 0, 0, dissect_iec61850_SEQUENCE_OF_DirectoryEntry },
  { &hf_iec61850_moreFollows, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_FileDirectory_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     FileDirectory_Response_sequence, hf_index, ett_iec61850_FileDirectory_Response);

  return offset;
}


static const value_string iec61850_ConfirmedServiceResponse_vals[] = {
  {   0, "status" },
  {   1, "getNameList" },
  {   2, "identify" },
  {   3, "rename" },
  {   4, "read" },
  {   5, "write" },
  {   6, "getVariableAccessAttributes" },
  {   7, "defineNamedVariable" },
  {   8, "defineScatteredAccess" },
  {   9, "getScatteredAccessAttributes" },
  {  10, "deleteVariableAccess" },
  {  11, "defineNamedVariableList" },
  {  12, "getNamedVariableListAttributes" },
  {  13, "deleteNamedVariableList" },
  {  14, "defineNamedType" },
  {  15, "getNamedTypeAttributes" },
  {  16, "deleteNamedType" },
  {  17, "input" },
  {  18, "output" },
  {  19, "takeControl" },
  {  20, "relinquishControl" },
  {  21, "defineSemaphore" },
  {  22, "deleteSemaphore" },
  {  23, "reportSemaphoreStatus" },
  {  24, "reportPoolSemaphoreStatus" },
  {  25, "reportSemaphoreEntryStatus" },
  {  26, "initiateDownloadSequence" },
  {  27, "downloadSegment" },
  {  28, "terminateDownloadSequence" },
  {  29, "initiateUploadSequence" },
  {  30, "uploadSegment" },
  {  31, "terminateUploadSequence" },
  {  32, "requestDomainDownLoad" },
  {  33, "requestDomainUpload" },
  {  34, "loadDomainContent" },
  {  35, "storeDomainContent" },
  {  36, "deleteDomain" },
  {  37, "getDomainAttributes" },
  {  38, "createProgramInvocation" },
  {  39, "deleteProgramInvocation" },
  {  40, "start" },
  {  41, "stop" },
  {  42, "resume" },
  {  43, "reset" },
  {  44, "kill" },
  {  45, "getProgramInvocationAttributes" },
  {  46, "obtainFile" },
  {  72, "fileOpen" },
  {  47, "defineEventCondition" },
  {  48, "deleteEventCondition" },
  {  49, "getEventConditionAttributes" },
  {  50, "reportEventConditionStatus" },
  {  51, "alterEventConditionMonitoring" },
  {  52, "triggerEvent" },
  {  53, "defineEventAction" },
  {  54, "deleteEventAction" },
  {  55, "getEventActionAttributes" },
  {  56, "reportActionStatus" },
  {  57, "defineEventEnrollment" },
  {  58, "deleteEventEnrollment" },
  {  59, "alterEventEnrollment" },
  {  60, "reportEventEnrollmentStatus" },
  {  61, "getEventEnrollmentAttributes" },
  {  62, "acknowledgeEventNotification" },
  {  63, "getAlarmSummary" },
  {  64, "getAlarmEnrollmentSummary" },
  {  65, "readJournal" },
  {  66, "writeJournal" },
  {  67, "initializeJournal" },
  {  68, "reportJournalStatus" },
  {  69, "createJournal" },
  {  70, "deleteJournal" },
  {  71, "getCapabilityList" },
  {  73, "fileRead" },
  {  74, "fileClose" },
  {  75, "fileRename" },
  {  76, "fileDelete" },
  {  77, "fileDirectory" },
  { 0, NULL }
};

static const ber_choice_t ConfirmedServiceResponse_choice[] = {
  {   0, &hf_iec61850_status_01  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Status_Response },
  {   1, &hf_iec61850_getNameList_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_GetNameList_Response },
  {   2, &hf_iec61850_identify_01, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Identify_Response },
  {   3, &hf_iec61850_rename_01  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_Rename_Response },
  {   4, &hf_iec61850_read_01    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_Read_Response },
  {   5, &hf_iec61850_write_01   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_Write_Response },
  {   6, &hf_iec61850_getVariableAccessAttributes_01, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_iec61850_GetVariableAccessAttributes_Response },
  {   7, &hf_iec61850_defineNamedVariable_01, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineNamedVariable_Response },
  {   8, &hf_iec61850_defineScatteredAccess_01, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineScatteredAccess_Response },
  {   9, &hf_iec61850_getScatteredAccessAttributes_01, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_GetScatteredAccessAttributes_Response },
  {  10, &hf_iec61850_deleteVariableAccess_01, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteVariableAccess_Response },
  {  11, &hf_iec61850_defineNamedVariableList_01, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineNamedVariableList_Response },
  {  12, &hf_iec61850_getNamedVariableListAttributes_01, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_iec61850_GetNamedVariableListAttributes_Response },
  {  13, &hf_iec61850_deleteNamedVariableList_01, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteNamedVariableList_Response },
  {  14, &hf_iec61850_defineNamedType_01, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineNamedType_Response },
  {  15, &hf_iec61850_getNamedTypeAttributes_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_iec61850_GetNamedTypeAttributes_Response },
  {  16, &hf_iec61850_deleteNamedType_01, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteNamedType_Response },
  {  17, &hf_iec61850_input_01   , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_iec61850_Input_Response },
  {  18, &hf_iec61850_output_01  , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_iec61850_Output_Response },
  {  19, &hf_iec61850_takeControl_01, BER_CLASS_CON, 19, 0, dissect_iec61850_TakeControl_Response },
  {  20, &hf_iec61850_relinquishControl_01, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_iec61850_RelinquishControl_Response },
  {  21, &hf_iec61850_defineSemaphore_01, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineSemaphore_Response },
  {  22, &hf_iec61850_deleteSemaphore_01, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteSemaphore_Response },
  {  23, &hf_iec61850_reportSemaphoreStatus_01, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportSemaphoreStatus_Response },
  {  24, &hf_iec61850_reportPoolSemaphoreStatus_01, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportPoolSemaphoreStatus_Response },
  {  25, &hf_iec61850_reportSemaphoreEntryStatus_01, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportSemaphoreEntryStatus_Response },
  {  26, &hf_iec61850_initiateDownloadSequence_01, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_iec61850_InitiateDownloadSequence_Response },
  {  27, &hf_iec61850_downloadSegment_01, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_iec61850_DownloadSegment_Response },
  {  28, &hf_iec61850_terminateDownloadSequence_01, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_iec61850_TerminateDownloadSequence_Response },
  {  29, &hf_iec61850_initiateUploadSequence_01, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_iec61850_InitiateUploadSequence_Response },
  {  30, &hf_iec61850_uploadSegment_01, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_iec61850_UploadSegment_Response },
  {  31, &hf_iec61850_terminateUploadSequence_01, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_iec61850_TerminateUploadSequence_Response },
  {  32, &hf_iec61850_requestDomainDownLoad, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_iec61850_RequestDomainDownload_Response },
  {  33, &hf_iec61850_requestDomainUpload_01, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_iec61850_RequestDomainUpload_Response },
  {  34, &hf_iec61850_loadDomainContent_01, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_iec61850_LoadDomainContent_Response },
  {  35, &hf_iec61850_storeDomainContent_01, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_iec61850_StoreDomainContent_Response },
  {  36, &hf_iec61850_deleteDomain_01, BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteDomain_Response },
  {  37, &hf_iec61850_getDomainAttributes_01, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_iec61850_GetDomainAttributes_Response },
  {  38, &hf_iec61850_createProgramInvocation_01, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_iec61850_CreateProgramInvocation_Response },
  {  39, &hf_iec61850_deleteProgramInvocation_01, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteProgramInvocation_Response },
  {  40, &hf_iec61850_start_01   , BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_iec61850_Start_Response },
  {  41, &hf_iec61850_stop_01    , BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_iec61850_Stop_Response },
  {  42, &hf_iec61850_resume_01  , BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_iec61850_Resume_Response },
  {  43, &hf_iec61850_reset_01   , BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_iec61850_Reset_Response },
  {  44, &hf_iec61850_kill_01    , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_iec61850_Kill_Response },
  {  45, &hf_iec61850_getProgramInvocationAttributes_01, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_iec61850_GetProgramInvocationAttributes_Response },
  {  46, &hf_iec61850_obtainFile_01, BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_iec61850_ObtainFile_Response },
  {  72, &hf_iec61850_fileOpen_01, BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_iec61850_FileOpen_Response },
  {  47, &hf_iec61850_defineEventCondition_01, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineEventCondition_Response },
  {  48, &hf_iec61850_confirmedServiceResponse_deleteEventCondition, BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteEventCondition_Response },
  {  49, &hf_iec61850_getEventConditionAttributes_01, BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_iec61850_GetEventConditionAttributes_Response },
  {  50, &hf_iec61850_reportEventConditionStatus_01, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportEventConditionStatus_Response },
  {  51, &hf_iec61850_alterEventConditionMonitoring_01, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_iec61850_AlterEventConditionMonitoring_Response },
  {  52, &hf_iec61850_triggerEvent_01, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_iec61850_TriggerEvent_Response },
  {  53, &hf_iec61850_defineEventAction_01, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineEventAction_Response },
  {  54, &hf_iec61850_deleteEventAction, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteEventAction_Response },
  {  55, &hf_iec61850_getEventActionAttributes_01, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_iec61850_GetEventActionAttributes_Response },
  {  56, &hf_iec61850_reportActionStatus, BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportEventActionStatus_Response },
  {  57, &hf_iec61850_defineEventEnrollment_01, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_iec61850_DefineEventEnrollment_Response },
  {  58, &hf_iec61850_confirmedServiceResponse_deleteEventEnrollment, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteEventEnrollment_Response },
  {  59, &hf_iec61850_alterEventEnrollment_01, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_iec61850_AlterEventEnrollment_Response },
  {  60, &hf_iec61850_reportEventEnrollmentStatus_01, BER_CLASS_CON, 60, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportEventEnrollmentStatus_Response },
  {  61, &hf_iec61850_getEventEnrollmentAttributes_01, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_iec61850_GetEventEnrollmentAttributes_Response },
  {  62, &hf_iec61850_acknowledgeEventNotification_01, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_iec61850_AcknowledgeEventNotification_Response },
  {  63, &hf_iec61850_getAlarmSummary_01, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_iec61850_GetAlarmSummary_Response },
  {  64, &hf_iec61850_getAlarmEnrollmentSummary_01, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_iec61850_GetAlarmEnrollmentSummary_Response },
  {  65, &hf_iec61850_readJournal_01, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_iec61850_ReadJournal_Response },
  {  66, &hf_iec61850_writeJournal_01, BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_iec61850_WriteJournal_Response },
  {  67, &hf_iec61850_initializeJournal_01, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_iec61850_InitializeJournal_Response },
  {  68, &hf_iec61850_reportJournalStatus_01, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_iec61850_ReportJournalStatus_Response },
  {  69, &hf_iec61850_createJournal_01, BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_iec61850_CreateJournal_Response },
  {  70, &hf_iec61850_deleteJournal_01, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_iec61850_DeleteJournal_Response },
  {  71, &hf_iec61850_getCapabilityList_01, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_iec61850_GetCapabilityList_Response },
  {  73, &hf_iec61850_fileRead_01, BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_iec61850_FileRead_Response },
  {  74, &hf_iec61850_fileClose_01, BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_iec61850_FileClose_Response },
  {  75, &hf_iec61850_fileRename_01, BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_iec61850_FileRename_Response },
  {  76, &hf_iec61850_fileDelete_01, BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_iec61850_FileDelete_Response },
  {  77, &hf_iec61850_fileDirectory_01, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_iec61850_FileDirectory_Response },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_ConfirmedServiceResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   ConfirmedServiceResponse_choice, hf_index, ett_iec61850_ConfirmedServiceResponse,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->Service = branch_taken;


  return offset;
}


static const ber_sequence_t Confirmed_ResponsePDU_sequence[] = {
  { &hf_iec61850_invokeID   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_confirmedServiceResponse, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ConfirmedServiceResponse },
  { &hf_iec61850_cs_request_detail, BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_CS_Request_Detail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Confirmed_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Confirmed_ResponsePDU_sequence, hf_index, ett_iec61850_Confirmed_ResponsePDU);

  return offset;
}


static const ber_sequence_t Confirmed_ErrorPDU_sequence[] = {
  { &hf_iec61850_invokeID   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_modifierPosition, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_serviceError, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Confirmed_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Confirmed_ErrorPDU_sequence, hf_index, ett_iec61850_Confirmed_ErrorPDU);

  return offset;
}


static const ber_sequence_t InformationReport_sequence[] = {
  { &hf_iec61850_variableAccessSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_VariableAccessSpecification },
  { &hf_iec61850_listOfAccessResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_SEQUENCE_OF_AccessResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_InformationReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     InformationReport_sequence, hf_index, ett_iec61850_InformationReport);

  return offset;
}



static int
dissect_iec61850_UnsolicitedStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Status_Response(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_T_eventConditionName_01_vals[] = {
  {   0, "eventCondition" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventConditionName_01_choice[] = {
  {   0, &hf_iec61850_eventCondition, BER_CLASS_CON, 0, 0, dissect_iec61850_ObjectName },
  {   1, &hf_iec61850_undefined  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_eventConditionName_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_eventConditionName_01_choice, hf_index, ett_iec61850_T_eventConditionName_01,
                                   NULL);

  return offset;
}


static const value_string iec61850_T_eventActionResult_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  { 0, NULL }
};

static const ber_choice_t T_eventActionResult_choice[] = {
  {   0, &hf_iec61850_success_02 , BER_CLASS_CON, 0, 0, dissect_iec61850_ConfirmedServiceResponse },
  {   1, &hf_iec61850_failure_01 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ServiceError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_eventActionResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_eventActionResult_choice, hf_index, ett_iec61850_T_eventActionResult,
                                   NULL);

  return offset;
}


static const ber_sequence_t T_actionResult_sequence[] = {
  { &hf_iec61850_eventActioName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventActionResult, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_eventActionResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_actionResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     T_actionResult_sequence, hf_index, ett_iec61850_T_actionResult);

  return offset;
}


static const ber_sequence_t EventNotification_sequence[] = {
  { &hf_iec61850_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_iec61850_ObjectName },
  { &hf_iec61850_eventConditionName_02, BER_CLASS_CON, 1, 0, dissect_iec61850_T_eventConditionName_01 },
  { &hf_iec61850_severity   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned8 },
  { &hf_iec61850_currentState, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_EC_State },
  { &hf_iec61850_transitionTime, BER_CLASS_CON, 4, BER_FLAGS_NOTCHKTAG, dissect_iec61850_EventTime },
  { &hf_iec61850_notificationLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_BOOLEAN },
  { &hf_iec61850_alarmAcknowledgmentRule, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_AlarmAckRule },
  { &hf_iec61850_actionResult, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_T_actionResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_EventNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     EventNotification_sequence, hf_index, ett_iec61850_EventNotification);

  return offset;
}


static const value_string iec61850_UnconfirmedService_vals[] = {
  {   0, "informationReport" },
  {   1, "unsolicitedStatus" },
  {   2, "eventNotification" },
  { 0, NULL }
};

static const ber_choice_t UnconfirmedService_choice[] = {
  {   0, &hf_iec61850_informationReport, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_InformationReport },
  {   1, &hf_iec61850_unsolicitedStatus, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_UnsolicitedStatus },
  {   2, &hf_iec61850_eventNotification, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_EventNotification },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_UnconfirmedService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   UnconfirmedService_choice, hf_index, ett_iec61850_UnconfirmedService,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->Service = branch_taken;


  return offset;
}


static const ber_sequence_t Unconfirmed_PDU_sequence[] = {
  { &hf_iec61850_unconfirmedService, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_UnconfirmedService },
  { &hf_iec61850_cs_request_detail, BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_iec61850_CS_Request_Detail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Unconfirmed_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Unconfirmed_PDU_sequence, hf_index, ett_iec61850_Unconfirmed_PDU);

  return offset;
}


static const value_string iec61850_T_confirmed_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "unrecognized-modifier" },
  {   3, "invalid-invokeID" },
  {   4, "invalid-argument" },
  {   5, "invalid-modifier" },
  {   6, "max-serv-outstanding-exceeded" },
  {   8, "max-recursion-exceeded" },
  {   9, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_iec61850_T_confirmed_requestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_confirmed_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "invalid-invokeID" },
  {   3, "invalid-result" },
  {   5, "max-recursion-exceeded" },
  {   6, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_iec61850_T_confirmed_responsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_confirmed_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "invalid-invokeID" },
  {   3, "invalid-serviceError" },
  {   4, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_iec61850_T_confirmed_errorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_unconfirmedPDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "invalid-argument" },
  {   3, "max-recursion-exceeded" },
  {   4, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_iec61850_T_unconfirmedPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_pdu_error_vals[] = {
  {   0, "unknown-pdu-type" },
  {   1, "invalid-pdu" },
  {   2, "illegal-acse-mapping" },
  { 0, NULL }
};


static int
dissect_iec61850_T_pdu_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_cancel_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  { 0, NULL }
};


static int
dissect_iec61850_T_cancel_requestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_cancel_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  { 0, NULL }
};


static int
dissect_iec61850_T_cancel_responsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_cancel_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  {   2, "invalid-serviceError" },
  {   3, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_iec61850_T_cancel_errorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_conclude_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-argument" },
  { 0, NULL }
};


static int
dissect_iec61850_T_conclude_requestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_conclude_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-result" },
  { 0, NULL }
};


static int
dissect_iec61850_T_conclude_responsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_conclude_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-serviceError" },
  {   2, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_iec61850_T_conclude_errorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static const value_string iec61850_T_rejectReason_vals[] = {
  {   1, "confirmed-requestPDU" },
  {   2, "confirmed-responsePDU" },
  {   3, "confirmed-errorPDU" },
  {   4, "unconfirmedPDU" },
  {   5, "pdu-error" },
  {   6, "cancel-requestPDU" },
  {   7, "cancel-responsePDU" },
  {   8, "cancel-errorPDU" },
  {   9, "conclude-requestPDU" },
  {  10, "conclude-responsePDU" },
  {  11, "conclude-errorPDU" },
  { 0, NULL }
};

static const ber_choice_t T_rejectReason_choice[] = {
  {   1, &hf_iec61850_confirmed_requestPDU, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_T_confirmed_requestPDU },
  {   2, &hf_iec61850_confirmed_responsePDU, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_T_confirmed_responsePDU },
  {   3, &hf_iec61850_confirmed_errorPDU, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_T_confirmed_errorPDU },
  {   4, &hf_iec61850_unconfirmedPDU, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_T_unconfirmedPDU },
  {   5, &hf_iec61850_pdu_error  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_T_pdu_error },
  {   6, &hf_iec61850_cancel_requestPDU, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_iec61850_T_cancel_requestPDU },
  {   7, &hf_iec61850_cancel_responsePDU, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_T_cancel_responsePDU },
  {   8, &hf_iec61850_cancel_errorPDU, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_iec61850_T_cancel_errorPDU },
  {   9, &hf_iec61850_conclude_requestPDU, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_T_conclude_requestPDU },
  {  10, &hf_iec61850_conclude_responsePDU, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_iec61850_T_conclude_responsePDU },
  {  11, &hf_iec61850_conclude_errorPDU, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_iec61850_T_conclude_errorPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_T_rejectReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   T_rejectReason_choice, hf_index, ett_iec61850_T_rejectReason,
                                   NULL);

  return offset;
}


static const ber_sequence_t RejectPDU_sequence[] = {
  { &hf_iec61850_originalInvokeID, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_rejectReason, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_iec61850_T_rejectReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_RejectPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     RejectPDU_sequence, hf_index, ett_iec61850_RejectPDU);

  return offset;
}



static int
dissect_iec61850_Cancel_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_Cancel_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Cancel_ErrorPDU_sequence[] = {
  { &hf_iec61850_originalInvokeID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Unsigned32 },
  { &hf_iec61850_serviceError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Cancel_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Cancel_ErrorPDU_sequence, hf_index, ett_iec61850_Cancel_ErrorPDU);

  return offset;
}



static int
dissect_iec61850_Integer16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                  NULL);

  return offset;
}


static int * const ParameterSupportOptions_bits[] = {
  &hf_iec61850_ParameterSupportOptions_str1,
  &hf_iec61850_ParameterSupportOptions_str2,
  &hf_iec61850_ParameterSupportOptions_vnam,
  &hf_iec61850_ParameterSupportOptions_valt,
  &hf_iec61850_ParameterSupportOptions_vadr,
  &hf_iec61850_ParameterSupportOptions_vsca,
  &hf_iec61850_ParameterSupportOptions_tpy,
  &hf_iec61850_ParameterSupportOptions_vlis,
  &hf_iec61850_ParameterSupportOptions_real,
  &hf_iec61850_ParameterSupportOptions_spare_bit9,
  &hf_iec61850_ParameterSupportOptions_cei,
  NULL
};

static int
dissect_iec61850_ParameterSupportOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                      ParameterSupportOptions_bits, 11, hf_index, ett_iec61850_ParameterSupportOptions,
                                      NULL);

  return offset;
}


static int * const ServiceSupportOptions_bits[] = {
  &hf_iec61850_ServiceSupportOptions_status,
  &hf_iec61850_ServiceSupportOptions_getNameList,
  &hf_iec61850_ServiceSupportOptions_identify,
  &hf_iec61850_ServiceSupportOptions_rename,
  &hf_iec61850_ServiceSupportOptions_read,
  &hf_iec61850_ServiceSupportOptions_write,
  &hf_iec61850_ServiceSupportOptions_getVariableAccessAttributes,
  &hf_iec61850_ServiceSupportOptions_defineNamedVariable,
  &hf_iec61850_ServiceSupportOptions_defineScatteredAccess,
  &hf_iec61850_ServiceSupportOptions_getScatteredAccessAttributes,
  &hf_iec61850_ServiceSupportOptions_deleteVariableAccess,
  &hf_iec61850_ServiceSupportOptions_defineNamedVariableList,
  &hf_iec61850_ServiceSupportOptions_getNamedVariableListAttributes,
  &hf_iec61850_ServiceSupportOptions_deleteNamedVariableList,
  &hf_iec61850_ServiceSupportOptions_defineNamedType,
  &hf_iec61850_ServiceSupportOptions_getNamedTypeAttributes,
  &hf_iec61850_ServiceSupportOptions_deleteNamedType,
  &hf_iec61850_ServiceSupportOptions_input,
  &hf_iec61850_ServiceSupportOptions_output,
  &hf_iec61850_ServiceSupportOptions_takeControl,
  &hf_iec61850_ServiceSupportOptions_relinquishControl,
  &hf_iec61850_ServiceSupportOptions_defineSemaphore,
  &hf_iec61850_ServiceSupportOptions_deleteSemaphore,
  &hf_iec61850_ServiceSupportOptions_reportSemaphoreStatus,
  &hf_iec61850_ServiceSupportOptions_reportPoolSemaphoreStatus,
  &hf_iec61850_ServiceSupportOptions_reportSemaphoreEntryStatus,
  &hf_iec61850_ServiceSupportOptions_initiateDownloadSequence,
  &hf_iec61850_ServiceSupportOptions_downloadSegment,
  &hf_iec61850_ServiceSupportOptions_terminateDownloadSequence,
  &hf_iec61850_ServiceSupportOptions_initiateUploadSequence,
  &hf_iec61850_ServiceSupportOptions_uploadSegment,
  &hf_iec61850_ServiceSupportOptions_terminateUploadSequence,
  &hf_iec61850_ServiceSupportOptions_requestDomainDownload,
  &hf_iec61850_ServiceSupportOptions_requestDomainUpload,
  &hf_iec61850_ServiceSupportOptions_loadDomainContent,
  &hf_iec61850_ServiceSupportOptions_storeDomainContent,
  &hf_iec61850_ServiceSupportOptions_deleteDomain,
  &hf_iec61850_ServiceSupportOptions_getDomainAttributes,
  &hf_iec61850_ServiceSupportOptions_createProgramInvocation,
  &hf_iec61850_ServiceSupportOptions_deleteProgramInvocation,
  &hf_iec61850_ServiceSupportOptions_start,
  &hf_iec61850_ServiceSupportOptions_stop,
  &hf_iec61850_ServiceSupportOptions_resume,
  &hf_iec61850_ServiceSupportOptions_reset,
  &hf_iec61850_ServiceSupportOptions_kill,
  &hf_iec61850_ServiceSupportOptions_getProgramInvocationAttributes,
  &hf_iec61850_ServiceSupportOptions_obtainFile,
  &hf_iec61850_ServiceSupportOptions_defineEventCondition,
  &hf_iec61850_ServiceSupportOptions_deleteEventCondition,
  &hf_iec61850_ServiceSupportOptions_getEventConditionAttributes,
  &hf_iec61850_ServiceSupportOptions_reportEventConditionStatus,
  &hf_iec61850_ServiceSupportOptions_alterEventConditionMonitoring,
  &hf_iec61850_ServiceSupportOptions_triggerEvent,
  &hf_iec61850_ServiceSupportOptions_defineEventAction,
  &hf_iec61850_ServiceSupportOptions_deleteEventAction,
  &hf_iec61850_ServiceSupportOptions_getEventActionAttributes,
  &hf_iec61850_ServiceSupportOptions_reportActionStatus,
  &hf_iec61850_ServiceSupportOptions_defineEventEnrollment,
  &hf_iec61850_ServiceSupportOptions_deleteEventEnrollment,
  &hf_iec61850_ServiceSupportOptions_alterEventEnrollment,
  &hf_iec61850_ServiceSupportOptions_reportEventEnrollmentStatus,
  &hf_iec61850_ServiceSupportOptions_getEventEnrollmentAttributes,
  &hf_iec61850_ServiceSupportOptions_acknowledgeEventNotification,
  &hf_iec61850_ServiceSupportOptions_getAlarmSummary,
  &hf_iec61850_ServiceSupportOptions_getAlarmEnrollmentSummary,
  &hf_iec61850_ServiceSupportOptions_readJournal,
  &hf_iec61850_ServiceSupportOptions_writeJournal,
  &hf_iec61850_ServiceSupportOptions_initializeJournal,
  &hf_iec61850_ServiceSupportOptions_reportJournalStatus,
  &hf_iec61850_ServiceSupportOptions_createJournal,
  &hf_iec61850_ServiceSupportOptions_deleteJournal,
  &hf_iec61850_ServiceSupportOptions_getCapabilityList,
  &hf_iec61850_ServiceSupportOptions_fileOpen,
  &hf_iec61850_ServiceSupportOptions_fileRead,
  &hf_iec61850_ServiceSupportOptions_fileClose,
  &hf_iec61850_ServiceSupportOptions_fileRename,
  &hf_iec61850_ServiceSupportOptions_fileDelete,
  &hf_iec61850_ServiceSupportOptions_fileDirectory,
  &hf_iec61850_ServiceSupportOptions_unsolicitedStatus,
  &hf_iec61850_ServiceSupportOptions_informationReport,
  &hf_iec61850_ServiceSupportOptions_eventNotification,
  &hf_iec61850_ServiceSupportOptions_attachToEventCondition,
  &hf_iec61850_ServiceSupportOptions_attachToSemaphore,
  &hf_iec61850_ServiceSupportOptions_conclude,
  &hf_iec61850_ServiceSupportOptions_cancel,
  NULL
};

static int
dissect_iec61850_ServiceSupportOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                      ServiceSupportOptions_bits, 85, hf_index, ett_iec61850_ServiceSupportOptions,
                                      NULL);

  return offset;
}


static const ber_sequence_t InitRequestDetail_sequence[] = {
  { &hf_iec61850_proposedVersionNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer16 },
  { &hf_iec61850_proposedParameterCBB, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ParameterSupportOptions },
  { &hf_iec61850_servicesSupportedCalling, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_ServiceSupportOptions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_InitRequestDetail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     InitRequestDetail_sequence, hf_index, ett_iec61850_InitRequestDetail);

  return offset;
}


static const ber_sequence_t Initiate_RequestPDU_sequence[] = {
  { &hf_iec61850_localDetailCalling, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  { &hf_iec61850_proposedMaxServOutstandingCalling, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer16 },
  { &hf_iec61850_proposedMaxServOutstandingCalled, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer16 },
  { &hf_iec61850_proposedDataStructureNestingLevel, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Integer8 },
  { &hf_iec61850_mmsInitRequestDetail, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_InitRequestDetail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Initiate_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Initiate_RequestPDU_sequence, hf_index, ett_iec61850_Initiate_RequestPDU);

  return offset;
}


static const ber_sequence_t InitResponseDetail_sequence[] = {
  { &hf_iec61850_negociatedVersionNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer16 },
  { &hf_iec61850_negociatedParameterCBB, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_ParameterSupportOptions },
  { &hf_iec61850_servicesSupportedCalled, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_ServiceSupportOptions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_InitResponseDetail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     InitResponseDetail_sequence, hf_index, ett_iec61850_InitResponseDetail);

  return offset;
}


static const ber_sequence_t Initiate_ResponsePDU_sequence[] = {
  { &hf_iec61850_localDetailCalled, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Integer32 },
  { &hf_iec61850_negociatedMaxServOutstandingCalling, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer16 },
  { &hf_iec61850_negociatedMaxServOutstandingCalled, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Integer16 },
  { &hf_iec61850_negociatedDataStructureNestingLevel, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iec61850_Integer8 },
  { &hf_iec61850_mmsInitResponseDetail, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_InitResponseDetail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_Initiate_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                     Initiate_ResponsePDU_sequence, hf_index, ett_iec61850_Initiate_ResponsePDU);

  return offset;
}



static int
dissect_iec61850_Initiate_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ServiceError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_iec61850_Conclude_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_Conclude_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_iec61850_Conclude_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_iec61850_ServiceError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string iec61850_MMSpdu_vals[] = {
  {   0, "confirmed-RequestPDU" },
  {   1, "confirmed-ResponsePDU" },
  {   2, "confirmed-ErrorPDU" },
  {   3, "unconfirmed-PDU" },
  {   4, "rejectPDU" },
  {   5, "cancel-RequestPDU" },
  {   6, "cancel-ResponsePDU" },
  {   7, "cancel-ErrorPDU" },
  {   8, "initiate-RequestPDU" },
  {   9, "initiate-ResponsePDU" },
  {  10, "initiate-ErrorPDU" },
  {  11, "conclude-RequestPDU" },
  {  12, "conclude-ResponsePDU" },
  {  13, "conclude-ErrorPDU" },
  { 0, NULL }
};

static const ber_choice_t MMSpdu_choice[] = {
  {   0, &hf_iec61850_confirmed_RequestPDU, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_iec61850_Confirmed_RequestPDU },
  {   1, &hf_iec61850_confirmed_ResponsePDU, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iec61850_Confirmed_ResponsePDU },
  {   2, &hf_iec61850_confirmed_ErrorPDU, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_iec61850_Confirmed_ErrorPDU },
  {   3, &hf_iec61850_unconfirmed_PDU, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_iec61850_Unconfirmed_PDU },
  {   4, &hf_iec61850_rejectPDU  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_iec61850_RejectPDU },
  {   5, &hf_iec61850_cancel_RequestPDU, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_iec61850_Cancel_RequestPDU },
  {   6, &hf_iec61850_cancel_ResponsePDU, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_iec61850_Cancel_ResponsePDU },
  {   7, &hf_iec61850_cancel_ErrorPDU, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iec61850_Cancel_ErrorPDU },
  {   8, &hf_iec61850_initiate_RequestPDU, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_iec61850_Initiate_RequestPDU },
  {   9, &hf_iec61850_initiate_ResponsePDU, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_iec61850_Initiate_ResponsePDU },
  {  10, &hf_iec61850_initiate_ErrorPDU, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_iec61850_Initiate_ErrorPDU },
  {  11, &hf_iec61850_conclude_RequestPDU, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_iec61850_Conclude_RequestPDU },
  {  12, &hf_iec61850_conclude_ResponsePDU, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_iec61850_Conclude_ResponsePDU },
  {  13, &hf_iec61850_conclude_ErrorPDU, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_iec61850_Conclude_ErrorPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_iec61850_MMSpdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int32_t branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                   MMSpdu_choice, hf_index, ett_iec61850_MMSpdu,
                                   &branch_taken);

    iec61850_private_data_t *private_data = (iec61850_private_data_t*)iec61850_get_private_data(actx);
    private_data->MMSpdu = branch_taken;


  return offset;
}


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
        { &hf_iec61850_MMSpdu,
            { "MMSpdu", "iec61850.mmspdu",
            FT_UINT32, BASE_DEC, VALS(iec61850_MMSpdu_vals), 0,
            NULL, HFILL }},
        /*generated items */
    { &hf_iec61850_confirmed_RequestPDU,
      { "confirmed-RequestPDU", "iec61850.confirmed_RequestPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_confirmed_ResponsePDU,
      { "confirmed-ResponsePDU", "iec61850.confirmed_ResponsePDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_confirmed_ErrorPDU,
      { "confirmed-ErrorPDU", "iec61850.confirmed_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_unconfirmed_PDU,
      { "unconfirmed-PDU", "iec61850.unconfirmed_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_rejectPDU,
      { "rejectPDU", "iec61850.rejectPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_cancel_RequestPDU,
      { "cancel-RequestPDU", "iec61850.cancel_RequestPDU",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_cancel_ResponsePDU,
      { "cancel-ResponsePDU", "iec61850.cancel_ResponsePDU",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_cancel_ErrorPDU,
      { "cancel-ErrorPDU", "iec61850.cancel_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_initiate_RequestPDU,
      { "initiate-RequestPDU", "iec61850.initiate_RequestPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_initiate_ResponsePDU,
      { "initiate-ResponsePDU", "iec61850.initiate_ResponsePDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_initiate_ErrorPDU,
      { "initiate-ErrorPDU", "iec61850.initiate_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_conclude_RequestPDU,
      { "conclude-RequestPDU", "iec61850.conclude_RequestPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_conclude_ResponsePDU,
      { "conclude-ResponsePDU", "iec61850.conclude_ResponsePDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_conclude_ErrorPDU,
      { "conclude-ErrorPDU", "iec61850.conclude_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_invokeID,
      { "invokeID", "iec61850.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_listOfModifier,
      { "listOfModifier", "iec61850.listOfModifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Modifier", HFILL }},
    { &hf_iec61850_listOfModifier_item,
      { "Modifier", "iec61850.Modifier",
        FT_UINT32, BASE_DEC, VALS(iec61850_Modifier_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_confirmedServiceRequest,
      { "confirmedServiceRequest", "iec61850.confirmedServiceRequest",
        FT_UINT32, BASE_DEC, VALS(iec61850_ConfirmedServiceRequest_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_cs_request_detail,
      { "cs-request-detail", "iec61850.cs_request_detail",
        FT_UINT32, BASE_DEC, VALS(iec61850_CS_Request_Detail_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_unconfirmedService,
      { "unconfirmedService", "iec61850.unconfirmedService",
        FT_UINT32, BASE_DEC, VALS(iec61850_UnconfirmedService_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_confirmedServiceResponse,
      { "confirmedServiceResponse", "iec61850.confirmedServiceResponse",
        FT_UINT32, BASE_DEC, VALS(iec61850_ConfirmedServiceResponse_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_modifierPosition,
      { "modifierPosition", "iec61850.modifierPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_serviceError,
      { "serviceError", "iec61850.serviceError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_informationReport,
      { "informationReport", "iec61850.informationReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_unsolicitedStatus,
      { "unsolicitedStatus", "iec61850.unsolicitedStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_eventNotification,
      { "eventNotification", "iec61850.eventNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_attach_To_Event_Condition,
      { "attach-To-Event-Condition", "iec61850.attach_To_Event_Condition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttachToEventCondition", HFILL }},
    { &hf_iec61850_attach_To_Semaphore,
      { "attach-To-Semaphore", "iec61850.attach_To_Semaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttachToSemaphore", HFILL }},
    { &hf_iec61850_status,
      { "status", "iec61850.status",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "Status_Request", HFILL }},
    { &hf_iec61850_getNameList,
      { "getNameList", "iec61850.getNameList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNameList_Request", HFILL }},
    { &hf_iec61850_identify,
      { "identify", "iec61850.identify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Identify_Request", HFILL }},
    { &hf_iec61850_rename,
      { "rename", "iec61850.rename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rename_Request", HFILL }},
    { &hf_iec61850_read,
      { "read", "iec61850.read_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Read_Request", HFILL }},
    { &hf_iec61850_write,
      { "write", "iec61850.write_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Write_Request", HFILL }},
    { &hf_iec61850_getVariableAccessAttributes,
      { "getVariableAccessAttributes", "iec61850.getVariableAccessAttributes",
        FT_UINT32, BASE_DEC, VALS(iec61850_GetVariableAccessAttributes_Request_vals), 0,
        "GetVariableAccessAttributes_Request", HFILL }},
    { &hf_iec61850_defineNamedVariable,
      { "defineNamedVariable", "iec61850.defineNamedVariable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariable_Request", HFILL }},
    { &hf_iec61850_defineScatteredAccess,
      { "defineScatteredAccess", "iec61850.defineScatteredAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineScatteredAccess_Request", HFILL }},
    { &hf_iec61850_getScatteredAccessAttributes,
      { "getScatteredAccessAttributes", "iec61850.getScatteredAccessAttributes",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "GetScatteredAccessAttributes_Request", HFILL }},
    { &hf_iec61850_deleteVariableAccess,
      { "deleteVariableAccess", "iec61850.deleteVariableAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteVariableAccess_Request", HFILL }},
    { &hf_iec61850_defineNamedVariableList,
      { "defineNamedVariableList", "iec61850.defineNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariableList_Request", HFILL }},
    { &hf_iec61850_getNamedVariableListAttributes,
      { "getNamedVariableListAttributes", "iec61850.getNamedVariableListAttributes",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "GetNamedVariableListAttributes_Request", HFILL }},
    { &hf_iec61850_deleteNamedVariableList,
      { "deleteNamedVariableList", "iec61850.deleteNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedVariableList_Request", HFILL }},
    { &hf_iec61850_defineNamedType,
      { "defineNamedType", "iec61850.defineNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedType_Request", HFILL }},
    { &hf_iec61850_getNamedTypeAttributes,
      { "getNamedTypeAttributes", "iec61850.getNamedTypeAttributes",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "GetNamedTypeAttributes_Request", HFILL }},
    { &hf_iec61850_deleteNamedType,
      { "deleteNamedType", "iec61850.deleteNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedType_Request", HFILL }},
    { &hf_iec61850_input,
      { "input", "iec61850.input_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Input_Request", HFILL }},
    { &hf_iec61850_output,
      { "output", "iec61850.output_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Output_Request", HFILL }},
    { &hf_iec61850_takeControl,
      { "takeControl", "iec61850.takeControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TakeControl_Request", HFILL }},
    { &hf_iec61850_relinquishControl,
      { "relinquishControl", "iec61850.relinquishControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelinquishControl_Request", HFILL }},
    { &hf_iec61850_defineSemaphore,
      { "defineSemaphore", "iec61850.defineSemaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineSemaphore_Request", HFILL }},
    { &hf_iec61850_deleteSemaphore,
      { "deleteSemaphore", "iec61850.deleteSemaphore",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "DeleteSemaphore_Request", HFILL }},
    { &hf_iec61850_reportSemaphoreStatus,
      { "reportSemaphoreStatus", "iec61850.reportSemaphoreStatus",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ReportSemaphoreStatus_Request", HFILL }},
    { &hf_iec61850_reportPoolSemaphoreStatus,
      { "reportPoolSemaphoreStatus", "iec61850.reportPoolSemaphoreStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportPoolSemaphoreStatus_Request", HFILL }},
    { &hf_iec61850_reportSemaphoreEntryStatus,
      { "reportSemaphoreEntryStatus", "iec61850.reportSemaphoreEntryStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportSemaphoreEntryStatus_Request", HFILL }},
    { &hf_iec61850_initiateDownloadSequence,
      { "initiateDownloadSequence", "iec61850.initiateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiateDownloadSequence_Request", HFILL }},
    { &hf_iec61850_downloadSegment,
      { "downloadSegment", "iec61850.downloadSegment",
        FT_STRING, BASE_NONE, NULL, 0,
        "DownloadSegment_Request", HFILL }},
    { &hf_iec61850_terminateDownloadSequence,
      { "terminateDownloadSequence", "iec61850.terminateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateDownloadSequence_Request", HFILL }},
    { &hf_iec61850_initiateUploadSequence,
      { "initiateUploadSequence", "iec61850.initiateUploadSequence",
        FT_STRING, BASE_NONE, NULL, 0,
        "InitiateUploadSequence_Request", HFILL }},
    { &hf_iec61850_uploadSegment,
      { "uploadSegment", "iec61850.uploadSegment",
        FT_INT32, BASE_DEC, NULL, 0,
        "UploadSegment_Request", HFILL }},
    { &hf_iec61850_terminateUploadSequence,
      { "terminateUploadSequence", "iec61850.terminateUploadSequence",
        FT_INT32, BASE_DEC, NULL, 0,
        "TerminateUploadSequence_Request", HFILL }},
    { &hf_iec61850_requestDomainDownload,
      { "requestDomainDownload", "iec61850.requestDomainDownload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainDownload_Request", HFILL }},
    { &hf_iec61850_requestDomainUpload,
      { "requestDomainUpload", "iec61850.requestDomainUpload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainUpload_Request", HFILL }},
    { &hf_iec61850_loadDomainContent,
      { "loadDomainContent", "iec61850.loadDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LoadDomainContent_Request", HFILL }},
    { &hf_iec61850_storeDomainContent,
      { "storeDomainContent", "iec61850.storeDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StoreDomainContent_Request", HFILL }},
    { &hf_iec61850_deleteDomain,
      { "deleteDomain", "iec61850.deleteDomain",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeleteDomain_Request", HFILL }},
    { &hf_iec61850_getDomainAttributes,
      { "getDomainAttributes", "iec61850.getDomainAttributes",
        FT_STRING, BASE_NONE, NULL, 0,
        "GetDomainAttributes_Request", HFILL }},
    { &hf_iec61850_createProgramInvocation,
      { "createProgramInvocation", "iec61850.createProgramInvocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateProgramInvocation_Request", HFILL }},
    { &hf_iec61850_deleteProgramInvocation,
      { "deleteProgramInvocation", "iec61850.deleteProgramInvocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeleteProgramInvocation_Request", HFILL }},
    { &hf_iec61850_start,
      { "start", "iec61850.start_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Start_Request", HFILL }},
    { &hf_iec61850_stop,
      { "stop", "iec61850.stop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Stop_Request", HFILL }},
    { &hf_iec61850_resume,
      { "resume", "iec61850.resume_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Resume_Request", HFILL }},
    { &hf_iec61850_reset,
      { "reset", "iec61850.reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Reset_Request", HFILL }},
    { &hf_iec61850_kill,
      { "kill", "iec61850.kill_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Kill_Request", HFILL }},
    { &hf_iec61850_getProgramInvocationAttributes,
      { "getProgramInvocationAttributes", "iec61850.getProgramInvocationAttributes",
        FT_STRING, BASE_NONE, NULL, 0,
        "GetProgramInvocationAttributes_Request", HFILL }},
    { &hf_iec61850_obtainFile,
      { "obtainFile", "iec61850.obtainFile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObtainFile_Request", HFILL }},
    { &hf_iec61850_defineEventCondition,
      { "defineEventCondition", "iec61850.defineEventCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventCondition_Request", HFILL }},
    { &hf_iec61850_confirmedServiceRequest_deleteEventCondition,
      { "deleteEventCondition", "iec61850.confirmedServiceRequest.deleteEventCondition",
        FT_UINT32, BASE_DEC, VALS(iec61850_DeleteEventCondition_Request_vals), 0,
        "DeleteEventCondition_Request", HFILL }},
    { &hf_iec61850_getEventConditionAttributes,
      { "getEventConditionAttributes", "iec61850.getEventConditionAttributes",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "GetEventConditionAttributes_Request", HFILL }},
    { &hf_iec61850_reportEventConditionStatus,
      { "reportEventConditionStatus", "iec61850.reportEventConditionStatus",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ReportEventConditionStatus_Request", HFILL }},
    { &hf_iec61850_alterEventConditionMonitoring,
      { "alterEventConditionMonitoring", "iec61850.alterEventConditionMonitoring_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventConditionMonitoring_Request", HFILL }},
    { &hf_iec61850_triggerEvent,
      { "triggerEvent", "iec61850.triggerEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TriggerEvent_Request", HFILL }},
    { &hf_iec61850_defineEventAction,
      { "defineEventAction", "iec61850.defineEventAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventAction_Request", HFILL }},
    { &hf_iec61850_confirmedServiceRequest_deleteEventAction,
      { "deleteEventAction", "iec61850.confirmedServiceRequest.deleteEventAction",
        FT_UINT32, BASE_DEC, VALS(iec61850_DeleteEventAction_Request_vals), 0,
        "DeleteEventAction_Request", HFILL }},
    { &hf_iec61850_getEventActionAttributes,
      { "getEventActionAttributes", "iec61850.getEventActionAttributes",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "GetEventActionAttributes_Request", HFILL }},
    { &hf_iec61850_reportEventActionStatus,
      { "reportEventActionStatus", "iec61850.reportEventActionStatus",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ReportEventActionStatus_Request", HFILL }},
    { &hf_iec61850_defineEventEnrollment,
      { "defineEventEnrollment", "iec61850.defineEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventEnrollment_Request", HFILL }},
    { &hf_iec61850_confirmedServiceRequest_deleteEventEnrollment,
      { "deleteEventEnrollment", "iec61850.confirmedServiceRequest.deleteEventEnrollment",
        FT_UINT32, BASE_DEC, VALS(iec61850_DeleteEventEnrollment_Request_vals), 0,
        "DeleteEventEnrollment_Request", HFILL }},
    { &hf_iec61850_alterEventEnrollment,
      { "alterEventEnrollment", "iec61850.alterEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventEnrollment_Request", HFILL }},
    { &hf_iec61850_reportEventEnrollmentStatus,
      { "reportEventEnrollmentStatus", "iec61850.reportEventEnrollmentStatus",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ReportEventEnrollmentStatus_Request", HFILL }},
    { &hf_iec61850_getEventEnrollmentAttributes,
      { "getEventEnrollmentAttributes", "iec61850.getEventEnrollmentAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventEnrollmentAttributes_Request", HFILL }},
    { &hf_iec61850_acknowledgeEventNotification,
      { "acknowledgeEventNotification", "iec61850.acknowledgeEventNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AcknowledgeEventNotification_Request", HFILL }},
    { &hf_iec61850_getAlarmSummary,
      { "getAlarmSummary", "iec61850.getAlarmSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmSummary_Request", HFILL }},
    { &hf_iec61850_getAlarmEnrollmentSummary,
      { "getAlarmEnrollmentSummary", "iec61850.getAlarmEnrollmentSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmEnrollmentSummary_Request", HFILL }},
    { &hf_iec61850_readJournal,
      { "readJournal", "iec61850.readJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadJournal_Request", HFILL }},
    { &hf_iec61850_writeJournal,
      { "writeJournal", "iec61850.writeJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WriteJournal_Request", HFILL }},
    { &hf_iec61850_initializeJournal,
      { "initializeJournal", "iec61850.initializeJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitializeJournal_Request", HFILL }},
    { &hf_iec61850_reportJournalStatus,
      { "reportJournalStatus", "iec61850.reportJournalStatus",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ReportJournalStatus_Request", HFILL }},
    { &hf_iec61850_createJournal,
      { "createJournal", "iec61850.createJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateJournal_Request", HFILL }},
    { &hf_iec61850_deleteJournal,
      { "deleteJournal", "iec61850.deleteJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteJournal_Request", HFILL }},
    { &hf_iec61850_getCapabilityList,
      { "getCapabilityList", "iec61850.getCapabilityList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetCapabilityList_Request", HFILL }},
    { &hf_iec61850_fileOpen,
      { "fileOpen", "iec61850.fileOpen_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileOpen_Request", HFILL }},
    { &hf_iec61850_fileRead,
      { "fileRead", "iec61850.fileRead",
        FT_INT32, BASE_DEC, NULL, 0,
        "FileRead_Request", HFILL }},
    { &hf_iec61850_fileClose,
      { "fileClose", "iec61850.fileClose",
        FT_INT32, BASE_DEC, NULL, 0,
        "FileClose_Request", HFILL }},
    { &hf_iec61850_fileRename,
      { "fileRename", "iec61850.fileRename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileRename_Request", HFILL }},
    { &hf_iec61850_fileDelete,
      { "fileDelete", "iec61850.fileDelete",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileDelete_Request", HFILL }},
    { &hf_iec61850_fileDirectory,
      { "fileDirectory", "iec61850.fileDirectory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileDirectory_Request", HFILL }},
    { &hf_iec61850_foo,
      { "foo", "iec61850.foo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_iec61850_status_01,
      { "status", "iec61850.status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Status_Response", HFILL }},
    { &hf_iec61850_getNameList_01,
      { "getNameList", "iec61850.getNameList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNameList_Response", HFILL }},
    { &hf_iec61850_identify_01,
      { "identify", "iec61850.identify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Identify_Response", HFILL }},
    { &hf_iec61850_rename_01,
      { "rename", "iec61850.rename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rename_Response", HFILL }},
    { &hf_iec61850_read_01,
      { "read", "iec61850.read_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Read_Response", HFILL }},
    { &hf_iec61850_write_01,
      { "write", "iec61850.write",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Write_Response", HFILL }},
    { &hf_iec61850_getVariableAccessAttributes_01,
      { "getVariableAccessAttributes", "iec61850.getVariableAccessAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetVariableAccessAttributes_Response", HFILL }},
    { &hf_iec61850_defineNamedVariable_01,
      { "defineNamedVariable", "iec61850.defineNamedVariable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariable_Response", HFILL }},
    { &hf_iec61850_defineScatteredAccess_01,
      { "defineScatteredAccess", "iec61850.defineScatteredAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineScatteredAccess_Response", HFILL }},
    { &hf_iec61850_getScatteredAccessAttributes_01,
      { "getScatteredAccessAttributes", "iec61850.getScatteredAccessAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetScatteredAccessAttributes_Response", HFILL }},
    { &hf_iec61850_deleteVariableAccess_01,
      { "deleteVariableAccess", "iec61850.deleteVariableAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteVariableAccess_Response", HFILL }},
    { &hf_iec61850_defineNamedVariableList_01,
      { "defineNamedVariableList", "iec61850.defineNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariableList_Response", HFILL }},
    { &hf_iec61850_getNamedVariableListAttributes_01,
      { "getNamedVariableListAttributes", "iec61850.getNamedVariableListAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNamedVariableListAttributes_Response", HFILL }},
    { &hf_iec61850_deleteNamedVariableList_01,
      { "deleteNamedVariableList", "iec61850.deleteNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedVariableList_Response", HFILL }},
    { &hf_iec61850_defineNamedType_01,
      { "defineNamedType", "iec61850.defineNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedType_Response", HFILL }},
    { &hf_iec61850_getNamedTypeAttributes_01,
      { "getNamedTypeAttributes", "iec61850.getNamedTypeAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNamedTypeAttributes_Response", HFILL }},
    { &hf_iec61850_deleteNamedType_01,
      { "deleteNamedType", "iec61850.deleteNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedType_Response", HFILL }},
    { &hf_iec61850_input_01,
      { "input", "iec61850.input",
        FT_STRING, BASE_NONE, NULL, 0,
        "Input_Response", HFILL }},
    { &hf_iec61850_output_01,
      { "output", "iec61850.output_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Output_Response", HFILL }},
    { &hf_iec61850_takeControl_01,
      { "takeControl", "iec61850.takeControl",
        FT_UINT32, BASE_DEC, VALS(iec61850_TakeControl_Response_vals), 0,
        "TakeControl_Response", HFILL }},
    { &hf_iec61850_relinquishControl_01,
      { "relinquishControl", "iec61850.relinquishControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelinquishControl_Response", HFILL }},
    { &hf_iec61850_defineSemaphore_01,
      { "defineSemaphore", "iec61850.defineSemaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineSemaphore_Response", HFILL }},
    { &hf_iec61850_deleteSemaphore_01,
      { "deleteSemaphore", "iec61850.deleteSemaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSemaphore_Response", HFILL }},
    { &hf_iec61850_reportSemaphoreStatus_01,
      { "reportSemaphoreStatus", "iec61850.reportSemaphoreStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportSemaphoreStatus_Response", HFILL }},
    { &hf_iec61850_reportPoolSemaphoreStatus_01,
      { "reportPoolSemaphoreStatus", "iec61850.reportPoolSemaphoreStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportPoolSemaphoreStatus_Response", HFILL }},
    { &hf_iec61850_reportSemaphoreEntryStatus_01,
      { "reportSemaphoreEntryStatus", "iec61850.reportSemaphoreEntryStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportSemaphoreEntryStatus_Response", HFILL }},
    { &hf_iec61850_initiateDownloadSequence_01,
      { "initiateDownloadSequence", "iec61850.initiateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiateDownloadSequence_Response", HFILL }},
    { &hf_iec61850_downloadSegment_01,
      { "downloadSegment", "iec61850.downloadSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DownloadSegment_Response", HFILL }},
    { &hf_iec61850_terminateDownloadSequence_01,
      { "terminateDownloadSequence", "iec61850.terminateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateDownloadSequence_Response", HFILL }},
    { &hf_iec61850_initiateUploadSequence_01,
      { "initiateUploadSequence", "iec61850.initiateUploadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiateUploadSequence_Response", HFILL }},
    { &hf_iec61850_uploadSegment_01,
      { "uploadSegment", "iec61850.uploadSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UploadSegment_Response", HFILL }},
    { &hf_iec61850_terminateUploadSequence_01,
      { "terminateUploadSequence", "iec61850.terminateUploadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateUploadSequence_Response", HFILL }},
    { &hf_iec61850_requestDomainDownLoad,
      { "requestDomainDownLoad", "iec61850.requestDomainDownLoad_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainDownload_Response", HFILL }},
    { &hf_iec61850_requestDomainUpload_01,
      { "requestDomainUpload", "iec61850.requestDomainUpload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainUpload_Response", HFILL }},
    { &hf_iec61850_loadDomainContent_01,
      { "loadDomainContent", "iec61850.loadDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LoadDomainContent_Response", HFILL }},
    { &hf_iec61850_storeDomainContent_01,
      { "storeDomainContent", "iec61850.storeDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StoreDomainContent_Response", HFILL }},
    { &hf_iec61850_deleteDomain_01,
      { "deleteDomain", "iec61850.deleteDomain_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteDomain_Response", HFILL }},
    { &hf_iec61850_getDomainAttributes_01,
      { "getDomainAttributes", "iec61850.getDomainAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetDomainAttributes_Response", HFILL }},
    { &hf_iec61850_createProgramInvocation_01,
      { "createProgramInvocation", "iec61850.createProgramInvocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateProgramInvocation_Response", HFILL }},
    { &hf_iec61850_deleteProgramInvocation_01,
      { "deleteProgramInvocation", "iec61850.deleteProgramInvocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteProgramInvocation_Response", HFILL }},
    { &hf_iec61850_start_01,
      { "start", "iec61850.start_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Start_Response", HFILL }},
    { &hf_iec61850_stop_01,
      { "stop", "iec61850.stop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Stop_Response", HFILL }},
    { &hf_iec61850_resume_01,
      { "resume", "iec61850.resume_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Resume_Response", HFILL }},
    { &hf_iec61850_reset_01,
      { "reset", "iec61850.reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Reset_Response", HFILL }},
    { &hf_iec61850_kill_01,
      { "kill", "iec61850.kill_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Kill_Response", HFILL }},
    { &hf_iec61850_getProgramInvocationAttributes_01,
      { "getProgramInvocationAttributes", "iec61850.getProgramInvocationAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetProgramInvocationAttributes_Response", HFILL }},
    { &hf_iec61850_obtainFile_01,
      { "obtainFile", "iec61850.obtainFile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObtainFile_Response", HFILL }},
    { &hf_iec61850_fileOpen_01,
      { "fileOpen", "iec61850.fileOpen_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileOpen_Response", HFILL }},
    { &hf_iec61850_defineEventCondition_01,
      { "defineEventCondition", "iec61850.defineEventCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventCondition_Response", HFILL }},
    { &hf_iec61850_confirmedServiceResponse_deleteEventCondition,
      { "deleteEventCondition", "iec61850.confirmedServiceResponse.deleteEventCondition",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteEventCondition_Response", HFILL }},
    { &hf_iec61850_getEventConditionAttributes_01,
      { "getEventConditionAttributes", "iec61850.getEventConditionAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventConditionAttributes_Response", HFILL }},
    { &hf_iec61850_reportEventConditionStatus_01,
      { "reportEventConditionStatus", "iec61850.reportEventConditionStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportEventConditionStatus_Response", HFILL }},
    { &hf_iec61850_alterEventConditionMonitoring_01,
      { "alterEventConditionMonitoring", "iec61850.alterEventConditionMonitoring_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventConditionMonitoring_Response", HFILL }},
    { &hf_iec61850_triggerEvent_01,
      { "triggerEvent", "iec61850.triggerEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TriggerEvent_Response", HFILL }},
    { &hf_iec61850_defineEventAction_01,
      { "defineEventAction", "iec61850.defineEventAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventAction_Response", HFILL }},
    { &hf_iec61850_deleteEventAction,
      { "deleteEventAction", "iec61850.deleteEventAction",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteEventAction_Response", HFILL }},
    { &hf_iec61850_getEventActionAttributes_01,
      { "getEventActionAttributes", "iec61850.getEventActionAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventActionAttributes_Response", HFILL }},
    { &hf_iec61850_reportActionStatus,
      { "reportActionStatus", "iec61850.reportActionStatus",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReportEventActionStatus_Response", HFILL }},
    { &hf_iec61850_defineEventEnrollment_01,
      { "defineEventEnrollment", "iec61850.defineEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventEnrollment_Response", HFILL }},
    { &hf_iec61850_confirmedServiceResponse_deleteEventEnrollment,
      { "deleteEventEnrollment", "iec61850.confirmedServiceResponse.deleteEventEnrollment",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteEventEnrollment_Response", HFILL }},
    { &hf_iec61850_alterEventEnrollment_01,
      { "alterEventEnrollment", "iec61850.alterEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventEnrollment_Response", HFILL }},
    { &hf_iec61850_reportEventEnrollmentStatus_01,
      { "reportEventEnrollmentStatus", "iec61850.reportEventEnrollmentStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportEventEnrollmentStatus_Response", HFILL }},
    { &hf_iec61850_getEventEnrollmentAttributes_01,
      { "getEventEnrollmentAttributes", "iec61850.getEventEnrollmentAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventEnrollmentAttributes_Response", HFILL }},
    { &hf_iec61850_acknowledgeEventNotification_01,
      { "acknowledgeEventNotification", "iec61850.acknowledgeEventNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AcknowledgeEventNotification_Response", HFILL }},
    { &hf_iec61850_getAlarmSummary_01,
      { "getAlarmSummary", "iec61850.getAlarmSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmSummary_Response", HFILL }},
    { &hf_iec61850_getAlarmEnrollmentSummary_01,
      { "getAlarmEnrollmentSummary", "iec61850.getAlarmEnrollmentSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmEnrollmentSummary_Response", HFILL }},
    { &hf_iec61850_readJournal_01,
      { "readJournal", "iec61850.readJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadJournal_Response", HFILL }},
    { &hf_iec61850_writeJournal_01,
      { "writeJournal", "iec61850.writeJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WriteJournal_Response", HFILL }},
    { &hf_iec61850_initializeJournal_01,
      { "initializeJournal", "iec61850.initializeJournal",
        FT_INT32, BASE_DEC, NULL, 0,
        "InitializeJournal_Response", HFILL }},
    { &hf_iec61850_reportJournalStatus_01,
      { "reportJournalStatus", "iec61850.reportJournalStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportJournalStatus_Response", HFILL }},
    { &hf_iec61850_createJournal_01,
      { "createJournal", "iec61850.createJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateJournal_Response", HFILL }},
    { &hf_iec61850_deleteJournal_01,
      { "deleteJournal", "iec61850.deleteJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteJournal_Response", HFILL }},
    { &hf_iec61850_getCapabilityList_01,
      { "getCapabilityList", "iec61850.getCapabilityList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetCapabilityList_Response", HFILL }},
    { &hf_iec61850_fileRead_01,
      { "fileRead", "iec61850.fileRead_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileRead_Response", HFILL }},
    { &hf_iec61850_fileClose_01,
      { "fileClose", "iec61850.fileClose_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileClose_Response", HFILL }},
    { &hf_iec61850_fileRename_01,
      { "fileRename", "iec61850.fileRename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileRename_Response", HFILL }},
    { &hf_iec61850_fileDelete_01,
      { "fileDelete", "iec61850.fileDelete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileDelete_Response", HFILL }},
    { &hf_iec61850_fileDirectory_01,
      { "fileDirectory", "iec61850.fileDirectory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileDirectory_Response", HFILL }},
    { &hf_iec61850_FileName_item,
      { "FileName item", "iec61850.FileName_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_iec61850_vmd_specific,
      { "vmd-specific", "iec61850.vmd_specific",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_domain_specific,
      { "domain-specific", "iec61850.domain_specific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_domainId,
      { "domainId", "iec61850.domainId",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_itemId,
      { "itemId", "iec61850.itemId",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_aa_specific,
      { "aa-specific", "iec61850.aa_specific",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_ap_title,
      { "ap-title", "iec61850.ap_title_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_ap_invocation_id,
      { "ap-invocation-id", "iec61850.ap_invocation_id_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_ae_qualifier,
      { "ae-qualifier", "iec61850.ae_qualifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_ae_invocation_id,
      { "ae-invocation-id", "iec61850.ae_invocation_id_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_localDetailCalling,
      { "localDetailCalling", "iec61850.localDetailCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_proposedMaxServOutstandingCalling,
      { "proposedMaxServOutstandingCalling", "iec61850.proposedMaxServOutstandingCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_iec61850_proposedMaxServOutstandingCalled,
      { "proposedMaxServOutstandingCalled", "iec61850.proposedMaxServOutstandingCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_iec61850_proposedDataStructureNestingLevel,
      { "proposedDataStructureNestingLevel", "iec61850.proposedDataStructureNestingLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer8", HFILL }},
    { &hf_iec61850_mmsInitRequestDetail,
      { "mmsInitRequestDetail", "iec61850.mmsInitRequestDetail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitRequestDetail", HFILL }},
    { &hf_iec61850_proposedVersionNumber,
      { "proposedVersionNumber", "iec61850.proposedVersionNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_iec61850_proposedParameterCBB,
      { "proposedParameterCBB", "iec61850.proposedParameterCBB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ParameterSupportOptions", HFILL }},
    { &hf_iec61850_servicesSupportedCalling,
      { "servicesSupportedCalling", "iec61850.servicesSupportedCalling",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ServiceSupportOptions", HFILL }},
    { &hf_iec61850_localDetailCalled,
      { "localDetailCalled", "iec61850.localDetailCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_negociatedMaxServOutstandingCalling,
      { "negociatedMaxServOutstandingCalling", "iec61850.negociatedMaxServOutstandingCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_iec61850_negociatedMaxServOutstandingCalled,
      { "negociatedMaxServOutstandingCalled", "iec61850.negociatedMaxServOutstandingCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_iec61850_negociatedDataStructureNestingLevel,
      { "negociatedDataStructureNestingLevel", "iec61850.negociatedDataStructureNestingLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer8", HFILL }},
    { &hf_iec61850_mmsInitResponseDetail,
      { "mmsInitResponseDetail", "iec61850.mmsInitResponseDetail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitResponseDetail", HFILL }},
    { &hf_iec61850_negociatedVersionNumber,
      { "negociatedVersionNumber", "iec61850.negociatedVersionNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_iec61850_negociatedParameterCBB,
      { "negociatedParameterCBB", "iec61850.negociatedParameterCBB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ParameterSupportOptions", HFILL }},
    { &hf_iec61850_servicesSupportedCalled,
      { "servicesSupportedCalled", "iec61850.servicesSupportedCalled",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ServiceSupportOptions", HFILL }},
    { &hf_iec61850_originalInvokeID,
      { "originalInvokeID", "iec61850.originalInvokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_errorClass,
      { "errorClass", "iec61850.errorClass",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_errorClass_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_vmd_state,
      { "vmd-state", "iec61850.vmd_state",
        FT_INT32, BASE_DEC, VALS(iec61850_T_vmd_state_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_application_reference,
      { "application-reference", "iec61850.application_reference",
        FT_INT32, BASE_DEC, VALS(iec61850_T_application_reference_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_definition,
      { "definition", "iec61850.definition",
        FT_INT32, BASE_DEC, VALS(iec61850_T_definition_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_resource,
      { "resource", "iec61850.resource",
        FT_INT32, BASE_DEC, VALS(iec61850_T_resource_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_service,
      { "service", "iec61850.service",
        FT_INT32, BASE_DEC, VALS(iec61850_T_service_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_service_preempt,
      { "service-preempt", "iec61850.service_preempt",
        FT_INT32, BASE_DEC, VALS(iec61850_T_service_preempt_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_time_resolution,
      { "time-resolution", "iec61850.time_resolution",
        FT_INT32, BASE_DEC, VALS(iec61850_T_time_resolution_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_access,
      { "access", "iec61850.access",
        FT_INT32, BASE_DEC, VALS(iec61850_T_access_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_initiate,
      { "initiate", "iec61850.initiate",
        FT_INT32, BASE_DEC, VALS(iec61850_T_initiate_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_conclude,
      { "conclude", "iec61850.conclude",
        FT_INT32, BASE_DEC, VALS(iec61850_T_conclude_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_cancel,
      { "cancel", "iec61850.cancel",
        FT_INT32, BASE_DEC, VALS(iec61850_T_cancel_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_file,
      { "file", "iec61850.file",
        FT_INT32, BASE_DEC, VALS(iec61850_T_file_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_others,
      { "others", "iec61850.others",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_iec61850_additionalCode,
      { "additionalCode", "iec61850.additionalCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_iec61850_additionalDescription,
      { "additionalDescription", "iec61850.additionalDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_serviceSpecificInformation,
      { "serviceSpecificInformation", "iec61850.serviceSpecificInformation",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_serviceSpecificInformation_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_obtainFile_02,
      { "obtainFile", "iec61850.obtainFile",
        FT_INT32, BASE_DEC, VALS(iec61850_ObtainFile_Error_vals), 0,
        "ObtainFile_Error", HFILL }},
    { &hf_iec61850_start_02,
      { "start", "iec61850.start",
        FT_INT32, BASE_DEC, VALS(iec61850_ProgramInvocationState_vals), 0,
        "Start_Error", HFILL }},
    { &hf_iec61850_stop_02,
      { "stop", "iec61850.stop",
        FT_INT32, BASE_DEC, VALS(iec61850_ProgramInvocationState_vals), 0,
        "Stop_Error", HFILL }},
    { &hf_iec61850_resume_02,
      { "resume", "iec61850.resume",
        FT_INT32, BASE_DEC, VALS(iec61850_ProgramInvocationState_vals), 0,
        "Resume_Error", HFILL }},
    { &hf_iec61850_reset_02,
      { "reset", "iec61850.reset",
        FT_INT32, BASE_DEC, VALS(iec61850_ProgramInvocationState_vals), 0,
        "Reset_Error", HFILL }},
    { &hf_iec61850_deleteVariableAccess_02,
      { "deleteVariableAccess", "iec61850.deleteVariableAccess",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteVariableAccess_Error", HFILL }},
    { &hf_iec61850_deleteNamedVariableList_02,
      { "deleteNamedVariableList", "iec61850.deleteNamedVariableList",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteNamedVariableList_Error", HFILL }},
    { &hf_iec61850_deleteNamedType_02,
      { "deleteNamedType", "iec61850.deleteNamedType",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteNamedType_Error", HFILL }},
    { &hf_iec61850_defineEventEnrollment_Error,
      { "defineEventEnrollment-Error", "iec61850.defineEventEnrollment_Error",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_fileRename_02,
      { "fileRename", "iec61850.fileRename",
        FT_INT32, BASE_DEC, VALS(iec61850_FileRename_Error_vals), 0,
        "FileRename_Error", HFILL }},
    { &hf_iec61850_additionalService,
      { "additionalService", "iec61850.additionalService",
        FT_UINT32, BASE_DEC, VALS(iec61850_AdditionalService_Error_vals), 0,
        "AdditionalService_Error", HFILL }},
    { &hf_iec61850_changeAccessControl,
      { "changeAccessControl", "iec61850.changeAccessControl",
        FT_INT32, BASE_DEC, NULL, 0,
        "ChangeAccessControl_Error", HFILL }},
    { &hf_iec61850_defineEcl,
      { "defineEcl", "iec61850.defineEcl",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "DefineEventConditionList_Error", HFILL }},
    { &hf_iec61850_addECLReference,
      { "addECLReference", "iec61850.addECLReference",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "AddEventConditionListReference_Error", HFILL }},
    { &hf_iec61850_removeECLReference,
      { "removeECLReference", "iec61850.removeECLReference",
        FT_UINT32, BASE_DEC, VALS(iec61850_RemoveEventConditionListReference_Error_vals), 0,
        "RemoveEventConditionListReference_Error", HFILL }},
    { &hf_iec61850_initiateUC,
      { "initiateUC", "iec61850.initiateUC",
        FT_UINT32, BASE_DEC, VALS(iec61850_InitiateUnitControl_Error_vals), 0,
        "InitiateUnitControl_Error", HFILL }},
    { &hf_iec61850_startUC,
      { "startUC", "iec61850.startUC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StartUnitControl_Error", HFILL }},
    { &hf_iec61850_stopUC,
      { "stopUC", "iec61850.stopUC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StopUnitControl_Error", HFILL }},
    { &hf_iec61850_deleteUC,
      { "deleteUC", "iec61850.deleteUC",
        FT_UINT32, BASE_DEC, VALS(iec61850_DeleteUnitControl_Error_vals), 0,
        "DeleteUnitControl_Error", HFILL }},
    { &hf_iec61850_loadUCFromFile,
      { "loadUCFromFile", "iec61850.loadUCFromFile",
        FT_UINT32, BASE_DEC, VALS(iec61850_LoadUnitControlFromFile_Error_vals), 0,
        "LoadUnitControlFromFile_Error", HFILL }},
    { &hf_iec61850_eventCondition,
      { "eventCondition", "iec61850.eventCondition",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_eventConditionList,
      { "eventConditionList", "iec61850.eventConditionList",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_domain,
      { "domain", "iec61850.domain",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_programInvocation,
      { "programInvocation", "iec61850.programInvocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_programInvocationName,
      { "programInvocationName", "iec61850.programInvocationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_programInvocationState,
      { "programInvocationState", "iec61850.programInvocationState",
        FT_INT32, BASE_DEC, VALS(iec61850_ProgramInvocationState_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_none,
      { "none", "iec61850.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_rejectReason,
      { "rejectReason", "iec61850.rejectReason",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_rejectReason_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_confirmed_requestPDU,
      { "confirmed-requestPDU", "iec61850.confirmed_requestPDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_confirmed_requestPDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_confirmed_responsePDU,
      { "confirmed-responsePDU", "iec61850.confirmed_responsePDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_confirmed_responsePDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_confirmed_errorPDU,
      { "confirmed-errorPDU", "iec61850.confirmed_errorPDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_confirmed_errorPDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_unconfirmedPDU,
      { "unconfirmedPDU", "iec61850.unconfirmedPDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_unconfirmedPDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_pdu_error,
      { "pdu-error", "iec61850.pdu_error",
        FT_INT32, BASE_DEC, VALS(iec61850_T_pdu_error_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_cancel_requestPDU,
      { "cancel-requestPDU", "iec61850.cancel_requestPDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_cancel_requestPDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_cancel_responsePDU,
      { "cancel-responsePDU", "iec61850.cancel_responsePDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_cancel_responsePDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_cancel_errorPDU,
      { "cancel-errorPDU", "iec61850.cancel_errorPDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_cancel_errorPDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_conclude_requestPDU,
      { "conclude-requestPDU", "iec61850.conclude_requestPDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_conclude_requestPDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_conclude_responsePDU,
      { "conclude-responsePDU", "iec61850.conclude_responsePDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_conclude_responsePDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_conclude_errorPDU,
      { "conclude-errorPDU", "iec61850.conclude_errorPDU",
        FT_INT32, BASE_DEC, VALS(iec61850_T_conclude_errorPDU_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_vmdLogicalStatus,
      { "vmdLogicalStatus", "iec61850.vmdLogicalStatus",
        FT_INT32, BASE_DEC, VALS(iec61850_T_vmdLogicalStatus_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_vmdPhysicalStatus,
      { "vmdPhysicalStatus", "iec61850.vmdPhysicalStatus",
        FT_INT32, BASE_DEC, VALS(iec61850_T_vmdPhysicalStatus_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_localDetail,
      { "localDetail", "iec61850.localDetail",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_0_128", HFILL }},
    { &hf_iec61850_extendedObjectClass,
      { "extendedObjectClass", "iec61850.extendedObjectClass",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_extendedObjectClass_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_objectClass,
      { "objectClass", "iec61850.objectClass",
        FT_INT32, BASE_DEC, VALS(iec61850_T_objectClass_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_objectScope,
      { "objectScope", "iec61850.objectScope",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_objectScope_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_vmdSpecific,
      { "vmdSpecific", "iec61850.vmdSpecific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_domainSpecific,
      { "domainSpecific", "iec61850.domainSpecific",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_aaSpecific,
      { "aaSpecific", "iec61850.aaSpecific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_getNameList_Request_continueAfter,
      { "continueAfter", "iec61850.getNameList-Request_continueAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_listOfIdentifier,
      { "listOfIdentifier", "iec61850.listOfIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_iec61850_listOfIdentifier_item,
      { "Identifier", "iec61850.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_moreFollows,
      { "moreFollows", "iec61850.moreFollows",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_vendorName,
      { "vendorName", "iec61850.vendorName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_modelName,
      { "modelName", "iec61850.modelName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_revision,
      { "revision", "iec61850.revision",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_listOfAbstractSyntaxes,
      { "listOfAbstractSyntaxes", "iec61850.listOfAbstractSyntaxes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfAbstractSyntaxes_item,
      { "listOfAbstractSyntaxes item", "iec61850.listOfAbstractSyntaxes_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_iec61850_extendedObjectClass_01,
      { "extendedObjectClass", "iec61850.extendedObjectClass",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_extendedObjectClass_01_vals), 0,
        "T_extendedObjectClass_01", HFILL }},
    { &hf_iec61850_objectClass_01,
      { "objectClass", "iec61850.objectClass",
        FT_INT32, BASE_DEC, VALS(iec61850_T_objectClass_01_vals), 0,
        "T_objectClass_01", HFILL }},
    { &hf_iec61850_currentName,
      { "currentName", "iec61850.currentName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_newIdentifier,
      { "newIdentifier", "iec61850.newIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_getCapabilityList_Request_continueAfter,
      { "continueAfter", "iec61850.getCapabilityList-Request_continueAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_listOfCapabilities,
      { "listOfCapabilities", "iec61850.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfCapabilities_item,
      { "listOfCapabilities item", "iec61850.listOfCapabilities_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_domainName,
      { "domainName", "iec61850.domainName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_listOfCapabilities_01,
      { "listOfCapabilities", "iec61850.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_01", HFILL }},
    { &hf_iec61850_sharable,
      { "sharable", "iec61850.sharable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_loadData,
      { "loadData", "iec61850.loadData",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_loadData_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_non_coded,
      { "non-coded", "iec61850.non_coded",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_coded,
      { "coded", "iec61850.coded_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNALt", HFILL }},
    { &hf_iec61850_discard,
      { "discard", "iec61850.discard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceError", HFILL }},
    { &hf_iec61850_ulsmID,
      { "ulsmID", "iec61850.ulsmID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_listOfCapabilities_02,
      { "listOfCapabilities", "iec61850.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_02", HFILL }},
    { &hf_iec61850_loadData_01,
      { "loadData", "iec61850.loadData",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_loadData_01_vals), 0,
        "T_loadData_01", HFILL }},
    { &hf_iec61850_listOfCapabilities_03,
      { "listOfCapabilities", "iec61850.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_03", HFILL }},
    { &hf_iec61850_fileName,
      { "fileName", "iec61850.fileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfCapabilities_04,
      { "listOfCapabilities", "iec61850.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_04", HFILL }},
    { &hf_iec61850_thirdParty,
      { "thirdParty", "iec61850.thirdParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_iec61850_filenName,
      { "filenName", "iec61850.filenName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_iec61850_listOfCapabilities_05,
      { "listOfCapabilities", "iec61850.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_05", HFILL }},
    { &hf_iec61850_getDomainAttributes_Response_state,
      { "state", "iec61850.getDomainAttributes-Response_state",
        FT_INT32, BASE_DEC, VALS(iec61850_DomainState_vals), 0,
        "DomainState", HFILL }},
    { &hf_iec61850_mmsDeletable,
      { "mmsDeletable", "iec61850.mmsDeletable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_listOfProgramInvocations,
      { "listOfProgramInvocations", "iec61850.listOfProgramInvocations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_iec61850_listOfProgramInvocations_item,
      { "Identifier", "iec61850.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_uploadInProgress,
      { "uploadInProgress", "iec61850.uploadInProgress",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer8", HFILL }},
    { &hf_iec61850_listOfDomainName,
      { "listOfDomainName", "iec61850.listOfDomainName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_iec61850_listOfDomainName_item,
      { "Identifier", "iec61850.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_reusable,
      { "reusable", "iec61850.reusable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_monitorType,
      { "monitorType", "iec61850.monitorType",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_executionArgument,
      { "executionArgument", "iec61850.executionArgument",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_executionArgument_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_simpleString,
      { "simpleString", "iec61850.simpleString",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_encodedString,
      { "encodedString", "iec61850.encodedString_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNALt", HFILL }},
    { &hf_iec61850_executionArgument_01,
      { "executionArgument", "iec61850.executionArgument",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_executionArgument_01_vals), 0,
        "T_executionArgument_01", HFILL }},
    { &hf_iec61850_getProgramInvocationAttributes_Response_state,
      { "state", "iec61850.getProgramInvocationAttributes-Response_state",
        FT_INT32, BASE_DEC, VALS(iec61850_ProgramInvocationState_vals), 0,
        "ProgramInvocationState", HFILL }},
    { &hf_iec61850_listOfDomainNames,
      { "listOfDomainNames", "iec61850.listOfDomainNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_iec61850_listOfDomainNames_item,
      { "Identifier", "iec61850.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_monitor,
      { "monitor", "iec61850.monitor",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_startArgument,
      { "startArgument", "iec61850.startArgument",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_executionArgument_02,
      { "executionArgument", "iec61850.executionArgument",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_executionArgument_02_vals), 0,
        "T_executionArgument_02", HFILL }},
    { &hf_iec61850_typeName,
      { "typeName", "iec61850.typeName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_array,
      { "array", "iec61850.array_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_packed,
      { "packed", "iec61850.packed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_numberOfElements,
      { "numberOfElements", "iec61850.numberOfElements",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_elementType,
      { "elementType", "iec61850.elementType",
        FT_UINT32, BASE_DEC, VALS(iec61850_TypeSpecification_vals), 0,
        "TypeSpecification", HFILL }},
    { &hf_iec61850_structure,
      { "structure", "iec61850.structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_components,
      { "components", "iec61850.components",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_components_item,
      { "components item", "iec61850.components_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_componentName,
      { "componentName", "iec61850.componentName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_componentType,
      { "componentType", "iec61850.componentType",
        FT_UINT32, BASE_DEC, VALS(iec61850_TypeSpecification_vals), 0,
        "TypeSpecification", HFILL }},
    { &hf_iec61850_boolean,
      { "boolean", "iec61850.boolean_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_typeSpecification_bit_string,
      { "bit-string", "iec61850.typeSpecification_bit-string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_integer,
      { "integer", "iec61850.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_iec61850_unsigned,
      { "unsigned", "iec61850.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_iec61850_typeSpecification_octet_string,
      { "octet-string", "iec61850.typeSpecification.octet-string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_typeSpecification_visible_string,
      { "visible-string", "iec61850.typeSpecification.visible-string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_generalized_time,
      { "generalized-time", "iec61850.generalized_time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_typeSpecification_binary_time,
      { "binary-time", "iec61850.typeSpecification.binary-time",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_bcd,
      { "bcd", "iec61850.bcd",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_iec61850_objId,
      { "objId", "iec61850.objId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_AlternateAccess_item,
      { "AlternateAccess item", "iec61850.AlternateAccess_item",
        FT_UINT32, BASE_DEC, VALS(iec61850_AlternateAccess_item_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_unnamed,
      { "unnamed", "iec61850.unnamed",
        FT_UINT32, BASE_DEC, VALS(iec61850_AlternateAccessSelection_vals), 0,
        "AlternateAccessSelection", HFILL }},
    { &hf_iec61850_named,
      { "named", "iec61850.named_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_accesst,
      { "accesst", "iec61850.accesst",
        FT_UINT32, BASE_DEC, VALS(iec61850_AlternateAccessSelection_vals), 0,
        "AlternateAccessSelection", HFILL }},
    { &hf_iec61850_selectAlternateAccess,
      { "selectAlternateAccess", "iec61850.selectAlternateAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_accessSelection,
      { "accessSelection", "iec61850.accessSelection",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_accessSelection_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_component,
      { "component", "iec61850.component",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_index,
      { "index", "iec61850.index",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_indexRange,
      { "indexRange", "iec61850.indexRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_lowIndex,
      { "lowIndex", "iec61850.lowIndex",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_allElements,
      { "allElements", "iec61850.allElements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_alternateAccess,
      { "alternateAccess", "iec61850.alternateAccess",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_selectAccess,
      { "selectAccess", "iec61850.selectAccess",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_selectAccess_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_indexRange_01,
      { "indexRange", "iec61850.indexRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_indexRange_01", HFILL }},
    { &hf_iec61850_nmberOfElements,
      { "nmberOfElements", "iec61850.nmberOfElements",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_specificationWithResult,
      { "specificationWithResult", "iec61850.specificationWithResult",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_variableAccessSpecificatn,
      { "variableAccessSpecificatn", "iec61850.variableAccessSpecificatn",
        FT_UINT32, BASE_DEC, VALS(iec61850_VariableAccessSpecification_vals), 0,
        "VariableAccessSpecification", HFILL }},
    { &hf_iec61850_listOfAccessResult,
      { "listOfAccessResult", "iec61850.listOfAccessResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AccessResult", HFILL }},
    { &hf_iec61850_listOfAccessResult_item,
      { "AccessResult", "iec61850.AccessResult",
        FT_UINT32, BASE_DEC, VALS(iec61850_AccessResult_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfData,
      { "listOfData", "iec61850.listOfData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Data", HFILL }},
    { &hf_iec61850_listOfData_item,
      { "Data", "iec61850.Data",
        FT_UINT32, BASE_DEC, VALS(iec61850_Data_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_Write_Response_item,
      { "Write-Response item", "iec61850.Write_Response_item",
        FT_UINT32, BASE_DEC, VALS(iec61850_Write_Response_item_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_failure,
      { "failure", "iec61850.failure",
        FT_INT32, BASE_DEC, VALS(iec61850_DataAccessError_vals), 0,
        "DataAccessError", HFILL }},
    { &hf_iec61850_success,
      { "success", "iec61850.success_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_variableAccessSpecification,
      { "variableAccessSpecification", "iec61850.variableAccessSpecification",
        FT_UINT32, BASE_DEC, VALS(iec61850_VariableAccessSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_name,
      { "name", "iec61850.name",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_address,
      { "address", "iec61850.address",
        FT_UINT32, BASE_DEC, VALS(iec61850_Address_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_typeSpecification,
      { "typeSpecification", "iec61850.typeSpecification",
        FT_UINT32, BASE_DEC, VALS(iec61850_TypeSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_variableName,
      { "variableName", "iec61850.variableName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_scatteredAccessName,
      { "scatteredAccessName", "iec61850.scatteredAccessName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_scatteredAccessDescription,
      { "scatteredAccessDescription", "iec61850.scatteredAccessDescription",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_scopeOfDelete,
      { "scopeOfDelete", "iec61850.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(iec61850_T_scopeOfDelete_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfName,
      { "listOfName", "iec61850.listOfName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_iec61850_listOfName_item,
      { "ObjectName", "iec61850.ObjectName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_numberMatched,
      { "numberMatched", "iec61850.numberMatched",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_numberDeleted,
      { "numberDeleted", "iec61850.numberDeleted",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_variableListName,
      { "variableListName", "iec61850.variableListName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_listOfVariable,
      { "listOfVariable", "iec61850.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfVariable_item,
      { "listOfVariable item", "iec61850.listOfVariable_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_variableSpecification,
      { "variableSpecification", "iec61850.variableSpecification",
        FT_UINT32, BASE_DEC, VALS(iec61850_VariableSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfVariable_01,
      { "listOfVariable", "iec61850.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfVariable_01", HFILL }},
    { &hf_iec61850_listOfVariable_item_01,
      { "listOfVariable item", "iec61850.listOfVariable_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_listOfVariable_item_01", HFILL }},
    { &hf_iec61850_scopeOfDelete_01,
      { "scopeOfDelete", "iec61850.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(iec61850_T_scopeOfDelete_01_vals), 0,
        "T_scopeOfDelete_01", HFILL }},
    { &hf_iec61850_listOfVariableListName,
      { "listOfVariableListName", "iec61850.listOfVariableListName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_iec61850_listOfVariableListName_item,
      { "ObjectName", "iec61850.ObjectName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_scopeOfDelete_02,
      { "scopeOfDelete", "iec61850.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(iec61850_T_scopeOfDelete_02_vals), 0,
        "T_scopeOfDelete_02", HFILL }},
    { &hf_iec61850_listOfTypeName,
      { "listOfTypeName", "iec61850.listOfTypeName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_iec61850_listOfTypeName_item,
      { "ObjectName", "iec61850.ObjectName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_success_01,
      { "success", "iec61850.success",
        FT_UINT32, BASE_DEC, VALS(iec61850_Data_vals), 0,
        "Data", HFILL }},
    { &hf_iec61850_array_01,
      { "array", "iec61850.array",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_array_01", HFILL }},
    { &hf_iec61850_array_item,
      { "Data", "iec61850.Data",
        FT_UINT32, BASE_DEC, VALS(iec61850_Data_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_structure_01,
      { "structure", "iec61850.structure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_structure_01", HFILL }},
    { &hf_iec61850_structure_item,
      { "Data", "iec61850.Data",
        FT_UINT32, BASE_DEC, VALS(iec61850_Data_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_boolean_01,
      { "boolean", "iec61850.boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_data_bit_string,
      { "bit-string", "iec61850.data_bit-string",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_data_bit_string", HFILL }},
    { &hf_iec61850_integer_01,
      { "integer", "iec61850.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_unsigned_01,
      { "unsigned", "iec61850.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_floating_point,
      { "floating-point", "iec61850.floating_point",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FloatingPoint", HFILL }},
    { &hf_iec61850_data_octet_string,
      { "octet-string", "iec61850.data.octet-string",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_data_octet_string", HFILL }},
    { &hf_iec61850_data_visible_string,
      { "visible-string", "iec61850.data.visible-string",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_data_visible_string", HFILL }},
    { &hf_iec61850_data_binary_time,
      { "binary-time", "iec61850.data.binary-time",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_iec61850_bcd_01,
      { "bcd", "iec61850.bcd",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_booleanArray,
      { "booleanArray", "iec61850.booleanArray",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_iec61850_objId_01,
      { "objId", "iec61850.objId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_iec61850_mMSString,
      { "mMSString", "iec61850.mMSString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_utc_time,
      { "utc-time", "iec61850.utc_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "UtcTime", HFILL }},
    { &hf_iec61850_listOfVariable_02,
      { "listOfVariable", "iec61850.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfVariable_02", HFILL }},
    { &hf_iec61850_listOfVariable_item_02,
      { "listOfVariable item", "iec61850.listOfVariable_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_listOfVariable_item_02", HFILL }},
    { &hf_iec61850_ScatteredAccessDescription_item,
      { "ScatteredAccessDescription item", "iec61850.ScatteredAccessDescription_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_variableDescription,
      { "variableDescription", "iec61850.variableDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_invalidated,
      { "invalidated", "iec61850.invalidated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_numericAddress,
      { "numericAddress", "iec61850.numericAddress",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_symbolicAddress,
      { "symbolicAddress", "iec61850.symbolicAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_unconstrainedAddress,
      { "unconstrainedAddress", "iec61850.unconstrainedAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_semaphoreName,
      { "semaphoreName", "iec61850.semaphoreName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_namedToken,
      { "namedToken", "iec61850.namedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_priority,
      { "priority", "iec61850.priority",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_acceptableDelay,
      { "acceptableDelay", "iec61850.acceptableDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_controlTimeOut,
      { "controlTimeOut", "iec61850.controlTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_abortOnTimeOut,
      { "abortOnTimeOut", "iec61850.abortOnTimeOut",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_relinquishIfConnectionLost,
      { "relinquishIfConnectionLost", "iec61850.relinquishIfConnectionLost",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_applicationToPreempt,
      { "applicationToPreempt", "iec61850.applicationToPreempt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_iec61850_noResult,
      { "noResult", "iec61850.noResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_numbersOfTokens,
      { "numbersOfTokens", "iec61850.numbersOfTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_iec61850_class,
      { "class", "iec61850.class",
        FT_INT32, BASE_DEC, VALS(iec61850_T_class_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_numberOfTokens,
      { "numberOfTokens", "iec61850.numberOfTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_iec61850_numberOfOwnedTokens,
      { "numberOfOwnedTokens", "iec61850.numberOfOwnedTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_iec61850_numberOfHungTokens,
      { "numberOfHungTokens", "iec61850.numberOfHungTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_iec61850_nameToStartAfter,
      { "nameToStartAfter", "iec61850.nameToStartAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_listOfNamedTokens,
      { "listOfNamedTokens", "iec61850.listOfNamedTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfNamedTokens_item,
      { "listOfNamedTokens item", "iec61850.listOfNamedTokens_item",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_listOfNamedTokens_item_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_freeNamedToken,
      { "freeNamedToken", "iec61850.freeNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_ownedNamedToken,
      { "ownedNamedToken", "iec61850.ownedNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_hungNamedToken,
      { "hungNamedToken", "iec61850.hungNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_reportSemaphoreEntryStatus_Request_state,
      { "state", "iec61850.reportSemaphoreEntryStatus-Request_state",
        FT_INT32, BASE_DEC, VALS(iec61850_T_reportSemaphoreEntryStatus_Request_state_vals), 0,
        "T_reportSemaphoreEntryStatus_Request_state", HFILL }},
    { &hf_iec61850_entryIdToStartAfter,
      { "entryIdToStartAfter", "iec61850.entryIdToStartAfter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_listOfSemaphoreEntry,
      { "listOfSemaphoreEntry", "iec61850.listOfSemaphoreEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SemaphoreEntry", HFILL }},
    { &hf_iec61850_listOfSemaphoreEntry_item,
      { "SemaphoreEntry", "iec61850.SemaphoreEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_entryId,
      { "entryId", "iec61850.entryId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_entryClass,
      { "entryClass", "iec61850.entryClass",
        FT_INT32, BASE_DEC, VALS(iec61850_T_entryClass_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_applicationReference,
      { "applicationReference", "iec61850.applicationReference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_remainingTimeOut,
      { "remainingTimeOut", "iec61850.remainingTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_operatorStationName,
      { "operatorStationName", "iec61850.operatorStationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_iec61850_echo,
      { "echo", "iec61850.echo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_listOfPromptData,
      { "listOfPromptData", "iec61850.listOfPromptData",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfPromptData_item,
      { "listOfPromptData item", "iec61850.listOfPromptData_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_inputTimeOut,
      { "inputTimeOut", "iec61850.inputTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_listOfOutputData,
      { "listOfOutputData", "iec61850.listOfOutputData",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfOutputData_item,
      { "listOfOutputData item", "iec61850.listOfOutputData_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_eventConditionName,
      { "eventConditionName", "iec61850.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_class_01,
      { "class", "iec61850.class",
        FT_INT32, BASE_DEC, VALS(iec61850_EC_Class_vals), 0,
        "EC_Class", HFILL }},
    { &hf_iec61850_prio_rity,
      { "prio-rity", "iec61850.prio_rity",
        FT_INT32, BASE_DEC, NULL, 0,
        "Priority", HFILL }},
    { &hf_iec61850_severity,
      { "severity", "iec61850.severity",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_iec61850_alarmSummaryReports,
      { "alarmSummaryReports", "iec61850.alarmSummaryReports",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_monitoredVariable,
      { "monitoredVariable", "iec61850.monitoredVariable",
        FT_UINT32, BASE_DEC, VALS(iec61850_VariableSpecification_vals), 0,
        "VariableSpecification", HFILL }},
    { &hf_iec61850_evaluationInterval,
      { "evaluationInterval", "iec61850.evaluationInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_specific,
      { "specific", "iec61850.specific",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_iec61850_specific_item,
      { "ObjectName", "iec61850.ObjectName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_aa_specific_01,
      { "aa-specific", "iec61850.aa_specific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_vmd,
      { "vmd", "iec61850.vmd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_monitoredVariable_01,
      { "monitoredVariable", "iec61850.monitoredVariable",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_monitoredVariable_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_variableReference,
      { "variableReference", "iec61850.variableReference",
        FT_UINT32, BASE_DEC, VALS(iec61850_VariableSpecification_vals), 0,
        "VariableSpecification", HFILL }},
    { &hf_iec61850_undefined,
      { "undefined", "iec61850.undefined_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_currentState,
      { "currentState", "iec61850.currentState",
        FT_INT32, BASE_DEC, VALS(iec61850_EC_State_vals), 0,
        "EC_State", HFILL }},
    { &hf_iec61850_numberOfEventEnrollments,
      { "numberOfEventEnrollments", "iec61850.numberOfEventEnrollments",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_enabled,
      { "enabled", "iec61850.enabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_timeOfLastTransitionToActive,
      { "timeOfLastTransitionToActive", "iec61850.timeOfLastTransitionToActive",
        FT_UINT32, BASE_DEC, VALS(iec61850_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_iec61850_timeOfLastTransitionToIdle,
      { "timeOfLastTransitionToIdle", "iec61850.timeOfLastTransitionToIdle",
        FT_UINT32, BASE_DEC, VALS(iec61850_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_iec61850_eventActionName,
      { "eventActionName", "iec61850.eventActionName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_eventEnrollmentName,
      { "eventEnrollmentName", "iec61850.eventEnrollmentName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_eventConditionTransition,
      { "eventConditionTransition", "iec61850.eventConditionTransition",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Transitions", HFILL }},
    { &hf_iec61850_alarmAcknowledgementRule,
      { "alarmAcknowledgementRule", "iec61850.alarmAcknowledgementRule",
        FT_INT32, BASE_DEC, VALS(iec61850_AlarmAckRule_vals), 0,
        "AlarmAckRule", HFILL }},
    { &hf_iec61850_clientApplication,
      { "clientApplication", "iec61850.clientApplication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_iec61850_ec,
      { "ec", "iec61850.ec",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_ea,
      { "ea", "iec61850.ea",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_scopeOfRequest,
      { "scopeOfRequest", "iec61850.scopeOfRequest",
        FT_INT32, BASE_DEC, VALS(iec61850_T_scopeOfRequest_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_eventEnrollmentNames,
      { "eventEnrollmentNames", "iec61850.eventEnrollmentNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_iec61850_eventEnrollmentNames_item,
      { "ObjectName", "iec61850.ObjectName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_getEventEnrollmentAttributes_Request_continueAfter,
      { "continueAfter", "iec61850.getEventEnrollmentAttributes-Request_continueAfter",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_eventConditionName_01,
      { "eventConditionName", "iec61850.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_eventConditionName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_eventActionName_01,
      { "eventActionName", "iec61850.eventActionName",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_eventActionName_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_eventAction,
      { "eventAction", "iec61850.eventAction",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_enrollmentClass,
      { "enrollmentClass", "iec61850.enrollmentClass",
        FT_INT32, BASE_DEC, VALS(iec61850_EE_Class_vals), 0,
        "EE_Class", HFILL }},
    { &hf_iec61850_duration,
      { "duration", "iec61850.duration",
        FT_INT32, BASE_DEC, VALS(iec61850_EE_Duration_vals), 0,
        "EE_Duration", HFILL }},
    { &hf_iec61850_remainingAcceptableDelay,
      { "remainingAcceptableDelay", "iec61850.remainingAcceptableDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_listOfEventEnrollment,
      { "listOfEventEnrollment", "iec61850.listOfEventEnrollment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EventEnrollment", HFILL }},
    { &hf_iec61850_listOfEventEnrollment_item,
      { "EventEnrollment", "iec61850.EventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_eventConditionTransitions,
      { "eventConditionTransitions", "iec61850.eventConditionTransitions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Transitions", HFILL }},
    { &hf_iec61850_notificationLost,
      { "notificationLost", "iec61850.notificationLost",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_alarmAcknowledgmentRule,
      { "alarmAcknowledgmentRule", "iec61850.alarmAcknowledgmentRule",
        FT_INT32, BASE_DEC, VALS(iec61850_AlarmAckRule_vals), 0,
        "AlarmAckRule", HFILL }},
    { &hf_iec61850_currentState_01,
      { "currentState", "iec61850.currentState",
        FT_INT32, BASE_DEC, VALS(iec61850_EE_State_vals), 0,
        "EE_State", HFILL }},
    { &hf_iec61850_currentState_02,
      { "currentState", "iec61850.currentState",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_currentState_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_alterEventEnrollment_Response_currentState_state,
      { "state", "iec61850.alterEventEnrollment-Response_currentState_state",
        FT_INT32, BASE_DEC, VALS(iec61850_EE_State_vals), 0,
        "EE_State", HFILL }},
    { &hf_iec61850_transitionTime,
      { "transitionTime", "iec61850.transitionTime",
        FT_UINT32, BASE_DEC, VALS(iec61850_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_iec61850_acknowledgedState,
      { "acknowledgedState", "iec61850.acknowledgedState",
        FT_INT32, BASE_DEC, VALS(iec61850_EC_State_vals), 0,
        "EC_State", HFILL }},
    { &hf_iec61850_timeOfAcknowledgedTransition,
      { "timeOfAcknowledgedTransition", "iec61850.timeOfAcknowledgedTransition",
        FT_UINT32, BASE_DEC, VALS(iec61850_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_iec61850_enrollmentsOnly,
      { "enrollmentsOnly", "iec61850.enrollmentsOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_activeAlarmsOnly,
      { "activeAlarmsOnly", "iec61850.activeAlarmsOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_iec61850_acknowledgmentFilter,
      { "acknowledgmentFilter", "iec61850.acknowledgmentFilter",
        FT_INT32, BASE_DEC, VALS(iec61850_T_acknowledgmentFilter_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_severityFilter,
      { "severityFilter", "iec61850.severityFilter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_mostSevere,
      { "mostSevere", "iec61850.mostSevere",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_iec61850_leastSevere,
      { "leastSevere", "iec61850.leastSevere",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_iec61850_continueAfter,
      { "continueAfter", "iec61850.continueAfter",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_listOfAlarmSummary,
      { "listOfAlarmSummary", "iec61850.listOfAlarmSummary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlarmSummary", HFILL }},
    { &hf_iec61850_listOfAlarmSummary_item,
      { "AlarmSummary", "iec61850.AlarmSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_unacknowledgedState,
      { "unacknowledgedState", "iec61850.unacknowledgedState",
        FT_INT32, BASE_DEC, VALS(iec61850_T_unacknowledgedState_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_acknowledgmentFilter_01,
      { "acknowledgmentFilter", "iec61850.acknowledgmentFilter",
        FT_INT32, BASE_DEC, VALS(iec61850_T_acknowledgmentFilter_01_vals), 0,
        "T_acknowledgmentFilter_01", HFILL }},
    { &hf_iec61850_severityFilter_01,
      { "severityFilter", "iec61850.severityFilter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_severityFilter_01", HFILL }},
    { &hf_iec61850_getAlarmEnrollmentSummary_Request_continueAfter,
      { "continueAfter", "iec61850.getAlarmEnrollmentSummary-Request_continueAfter",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_listOfAlarmEnrollmentSummary,
      { "listOfAlarmEnrollmentSummary", "iec61850.listOfAlarmEnrollmentSummary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlarmEnrollmentSummary", HFILL }},
    { &hf_iec61850_listOfAlarmEnrollmentSummary_item,
      { "AlarmEnrollmentSummary", "iec61850.AlarmEnrollmentSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_enrollementState,
      { "enrollementState", "iec61850.enrollementState",
        FT_INT32, BASE_DEC, VALS(iec61850_EE_State_vals), 0,
        "EE_State", HFILL }},
    { &hf_iec61850_timeActiveAcknowledged,
      { "timeActiveAcknowledged", "iec61850.timeActiveAcknowledged",
        FT_UINT32, BASE_DEC, VALS(iec61850_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_iec61850_timeIdleAcknowledged,
      { "timeIdleAcknowledged", "iec61850.timeIdleAcknowledged",
        FT_UINT32, BASE_DEC, VALS(iec61850_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_iec61850_eventConditionName_02,
      { "eventConditionName", "iec61850.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_eventConditionName_01_vals), 0,
        "T_eventConditionName_01", HFILL }},
    { &hf_iec61850_actionResult,
      { "actionResult", "iec61850.actionResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_eventActioName,
      { "eventActioName", "iec61850.eventActioName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_eventActionResult,
      { "eventActionResult", "iec61850.eventActionResult",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_eventActionResult_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_success_02,
      { "success", "iec61850.success",
        FT_UINT32, BASE_DEC, VALS(iec61850_ConfirmedServiceResponse_vals), 0,
        "ConfirmedServiceResponse", HFILL }},
    { &hf_iec61850_failure_01,
      { "failure", "iec61850.failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceError", HFILL }},
    { &hf_iec61850_causingTransitions,
      { "causingTransitions", "iec61850.causingTransitions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Transitions", HFILL }},
    { &hf_iec61850_timeOfDayT,
      { "timeOfDayT", "iec61850.timeOfDayT",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_iec61850_timeSequenceIdentifier,
      { "timeSequenceIdentifier", "iec61850.timeSequenceIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_journalName,
      { "journalName", "iec61850.journalName",
        FT_UINT32, BASE_DEC, VALS(iec61850_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_iec61850_rangeStartSpecification,
      { "rangeStartSpecification", "iec61850.rangeStartSpecification",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_rangeStartSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_startingTime,
      { "startingTime", "iec61850.startingTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_iec61850_startingEntry,
      { "startingEntry", "iec61850.startingEntry",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_rangeStopSpecification,
      { "rangeStopSpecification", "iec61850.rangeStopSpecification",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_rangeStopSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_endingTime,
      { "endingTime", "iec61850.endingTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_iec61850_numberOfEntries,
      { "numberOfEntries", "iec61850.numberOfEntries",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_listOfVariables,
      { "listOfVariables", "iec61850.listOfVariables",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfVariables_item,
      { "listOfVariables item", "iec61850.listOfVariables_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_entryToStartAfter,
      { "entryToStartAfter", "iec61850.entryToStartAfter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_timeSpecification,
      { "timeSpecification", "iec61850.timeSpecification",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_iec61850_entrySpecification,
      { "entrySpecification", "iec61850.entrySpecification",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_listOfJournalEntry,
      { "listOfJournalEntry", "iec61850.listOfJournalEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_JournalEntry", HFILL }},
    { &hf_iec61850_listOfJournalEntry_item,
      { "JournalEntry", "iec61850.JournalEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_entryIdentifier,
      { "entryIdentifier", "iec61850.entryIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_originatingApplication,
      { "originatingApplication", "iec61850.originatingApplication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_iec61850_entryContent,
      { "entryContent", "iec61850.entryContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfJournalEntry_01,
      { "listOfJournalEntry", "iec61850.listOfJournalEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EntryContent", HFILL }},
    { &hf_iec61850_listOfJournalEntry_item_01,
      { "EntryContent", "iec61850.EntryContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_limitSpecification,
      { "limitSpecification", "iec61850.limitSpecification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_limitingTime,
      { "limitingTime", "iec61850.limitingTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_iec61850_limitingEntry,
      { "limitingEntry", "iec61850.limitingEntry",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_currentEntries,
      { "currentEntries", "iec61850.currentEntries",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_occurenceTime,
      { "occurenceTime", "iec61850.occurenceTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_iec61850_additionalDetail,
      { "additionalDetail", "iec61850.additionalDetail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "JOU_Additional_Detail", HFILL }},
    { &hf_iec61850_entryForm,
      { "entryForm", "iec61850.entryForm",
        FT_UINT32, BASE_DEC, VALS(iec61850_T_entryForm_vals), 0,
        NULL, HFILL }},
    { &hf_iec61850_data,
      { "data", "iec61850.data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_event,
      { "event", "iec61850.event_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_listOfVariables_01,
      { "listOfVariables", "iec61850.listOfVariables",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfVariables_01", HFILL }},
    { &hf_iec61850_listOfVariables_item_01,
      { "listOfVariables item", "iec61850.listOfVariables_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_variableTag,
      { "variableTag", "iec61850.variableTag",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_valueSpecification,
      { "valueSpecification", "iec61850.valueSpecification",
        FT_UINT32, BASE_DEC, VALS(iec61850_Data_vals), 0,
        "Data", HFILL }},
    { &hf_iec61850_annotation,
      { "annotation", "iec61850.annotation",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_iec61850_sourceFileServer,
      { "sourceFileServer", "iec61850.sourceFileServer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_iec61850_sourceFile,
      { "sourceFile", "iec61850.sourceFile",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_iec61850_destinationFile,
      { "destinationFile", "iec61850.destinationFile",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_iec61850_initialPosition,
      { "initialPosition", "iec61850.initialPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_frsmID,
      { "frsmID", "iec61850.frsmID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_iec61850_fileAttributes,
      { "fileAttributes", "iec61850.fileAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_fileData,
      { "fileData", "iec61850.fileData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_iec61850_currentFileName,
      { "currentFileName", "iec61850.currentFileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_iec61850_newFileName,
      { "newFileName", "iec61850.newFileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_iec61850_fileSpecification,
      { "fileSpecification", "iec61850.fileSpecification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_iec61850_fileDirectory_Request_continueAfter,
      { "continueAfter", "iec61850.fileDirectory-Request_continueAfter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_iec61850_listOfDirectoryEntry,
      { "listOfDirectoryEntry", "iec61850.listOfDirectoryEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DirectoryEntry", HFILL }},
    { &hf_iec61850_listOfDirectoryEntry_item,
      { "DirectoryEntry", "iec61850.DirectoryEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_filename,
      { "filename", "iec61850.filename",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_iec61850_sizeOfFile,
      { "sizeOfFile", "iec61850.sizeOfFile",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_iec61850_lastModified,
      { "lastModified", "iec61850.lastModified",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_iec61850_ParameterSupportOptions_str1,
      { "str1", "iec61850.ParameterSupportOptions.str1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_str2,
      { "str2", "iec61850.ParameterSupportOptions.str2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_vnam,
      { "vnam", "iec61850.ParameterSupportOptions.vnam",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_valt,
      { "valt", "iec61850.ParameterSupportOptions.valt",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_vadr,
      { "vadr", "iec61850.ParameterSupportOptions.vadr",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_vsca,
      { "vsca", "iec61850.ParameterSupportOptions.vsca",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_tpy,
      { "tpy", "iec61850.ParameterSupportOptions.tpy",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_vlis,
      { "vlis", "iec61850.ParameterSupportOptions.vlis",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_real,
      { "real", "iec61850.ParameterSupportOptions.real",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_spare_bit9,
      { "spare_bit9", "iec61850.ParameterSupportOptions.spare.bit9",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ParameterSupportOptions_cei,
      { "cei", "iec61850.ParameterSupportOptions.cei",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_status,
      { "status", "iec61850.ServiceSupportOptions.status",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getNameList,
      { "getNameList", "iec61850.ServiceSupportOptions.getNameList",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_identify,
      { "identify", "iec61850.ServiceSupportOptions.identify",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_rename,
      { "rename", "iec61850.ServiceSupportOptions.rename",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_read,
      { "read", "iec61850.ServiceSupportOptions.read",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_write,
      { "write", "iec61850.ServiceSupportOptions.write",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getVariableAccessAttributes,
      { "getVariableAccessAttributes", "iec61850.ServiceSupportOptions.getVariableAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineNamedVariable,
      { "defineNamedVariable", "iec61850.ServiceSupportOptions.defineNamedVariable",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineScatteredAccess,
      { "defineScatteredAccess", "iec61850.ServiceSupportOptions.defineScatteredAccess",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getScatteredAccessAttributes,
      { "getScatteredAccessAttributes", "iec61850.ServiceSupportOptions.getScatteredAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteVariableAccess,
      { "deleteVariableAccess", "iec61850.ServiceSupportOptions.deleteVariableAccess",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineNamedVariableList,
      { "defineNamedVariableList", "iec61850.ServiceSupportOptions.defineNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getNamedVariableListAttributes,
      { "getNamedVariableListAttributes", "iec61850.ServiceSupportOptions.getNamedVariableListAttributes",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteNamedVariableList,
      { "deleteNamedVariableList", "iec61850.ServiceSupportOptions.deleteNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineNamedType,
      { "defineNamedType", "iec61850.ServiceSupportOptions.defineNamedType",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getNamedTypeAttributes,
      { "getNamedTypeAttributes", "iec61850.ServiceSupportOptions.getNamedTypeAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteNamedType,
      { "deleteNamedType", "iec61850.ServiceSupportOptions.deleteNamedType",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_input,
      { "input", "iec61850.ServiceSupportOptions.input",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_output,
      { "output", "iec61850.ServiceSupportOptions.output",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_takeControl,
      { "takeControl", "iec61850.ServiceSupportOptions.takeControl",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_relinquishControl,
      { "relinquishControl", "iec61850.ServiceSupportOptions.relinquishControl",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineSemaphore,
      { "defineSemaphore", "iec61850.ServiceSupportOptions.defineSemaphore",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteSemaphore,
      { "deleteSemaphore", "iec61850.ServiceSupportOptions.deleteSemaphore",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reportSemaphoreStatus,
      { "reportSemaphoreStatus", "iec61850.ServiceSupportOptions.reportSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reportPoolSemaphoreStatus,
      { "reportPoolSemaphoreStatus", "iec61850.ServiceSupportOptions.reportPoolSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reportSemaphoreEntryStatus,
      { "reportSemaphoreEntryStatus", "iec61850.ServiceSupportOptions.reportSemaphoreEntryStatus",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_initiateDownloadSequence,
      { "initiateDownloadSequence", "iec61850.ServiceSupportOptions.initiateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_downloadSegment,
      { "downloadSegment", "iec61850.ServiceSupportOptions.downloadSegment",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_terminateDownloadSequence,
      { "terminateDownloadSequence", "iec61850.ServiceSupportOptions.terminateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_initiateUploadSequence,
      { "initiateUploadSequence", "iec61850.ServiceSupportOptions.initiateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_uploadSegment,
      { "uploadSegment", "iec61850.ServiceSupportOptions.uploadSegment",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_terminateUploadSequence,
      { "terminateUploadSequence", "iec61850.ServiceSupportOptions.terminateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_requestDomainDownload,
      { "requestDomainDownload", "iec61850.ServiceSupportOptions.requestDomainDownload",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_requestDomainUpload,
      { "requestDomainUpload", "iec61850.ServiceSupportOptions.requestDomainUpload",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_loadDomainContent,
      { "loadDomainContent", "iec61850.ServiceSupportOptions.loadDomainContent",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_storeDomainContent,
      { "storeDomainContent", "iec61850.ServiceSupportOptions.storeDomainContent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteDomain,
      { "deleteDomain", "iec61850.ServiceSupportOptions.deleteDomain",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getDomainAttributes,
      { "getDomainAttributes", "iec61850.ServiceSupportOptions.getDomainAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_createProgramInvocation,
      { "createProgramInvocation", "iec61850.ServiceSupportOptions.createProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteProgramInvocation,
      { "deleteProgramInvocation", "iec61850.ServiceSupportOptions.deleteProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_start,
      { "start", "iec61850.ServiceSupportOptions.start",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_stop,
      { "stop", "iec61850.ServiceSupportOptions.stop",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_resume,
      { "resume", "iec61850.ServiceSupportOptions.resume",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reset,
      { "reset", "iec61850.ServiceSupportOptions.reset",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_kill,
      { "kill", "iec61850.ServiceSupportOptions.kill",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getProgramInvocationAttributes,
      { "getProgramInvocationAttributes", "iec61850.ServiceSupportOptions.getProgramInvocationAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_obtainFile,
      { "obtainFile", "iec61850.ServiceSupportOptions.obtainFile",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineEventCondition,
      { "defineEventCondition", "iec61850.ServiceSupportOptions.defineEventCondition",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteEventCondition,
      { "deleteEventCondition", "iec61850.ServiceSupportOptions.deleteEventCondition",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getEventConditionAttributes,
      { "getEventConditionAttributes", "iec61850.ServiceSupportOptions.getEventConditionAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reportEventConditionStatus,
      { "reportEventConditionStatus", "iec61850.ServiceSupportOptions.reportEventConditionStatus",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_alterEventConditionMonitoring,
      { "alterEventConditionMonitoring", "iec61850.ServiceSupportOptions.alterEventConditionMonitoring",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_triggerEvent,
      { "triggerEvent", "iec61850.ServiceSupportOptions.triggerEvent",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineEventAction,
      { "defineEventAction", "iec61850.ServiceSupportOptions.defineEventAction",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteEventAction,
      { "deleteEventAction", "iec61850.ServiceSupportOptions.deleteEventAction",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getEventActionAttributes,
      { "getEventActionAttributes", "iec61850.ServiceSupportOptions.getEventActionAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reportActionStatus,
      { "reportActionStatus", "iec61850.ServiceSupportOptions.reportActionStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_defineEventEnrollment,
      { "defineEventEnrollment", "iec61850.ServiceSupportOptions.defineEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteEventEnrollment,
      { "deleteEventEnrollment", "iec61850.ServiceSupportOptions.deleteEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_alterEventEnrollment,
      { "alterEventEnrollment", "iec61850.ServiceSupportOptions.alterEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reportEventEnrollmentStatus,
      { "reportEventEnrollmentStatus", "iec61850.ServiceSupportOptions.reportEventEnrollmentStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getEventEnrollmentAttributes,
      { "getEventEnrollmentAttributes", "iec61850.ServiceSupportOptions.getEventEnrollmentAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_acknowledgeEventNotification,
      { "acknowledgeEventNotification", "iec61850.ServiceSupportOptions.acknowledgeEventNotification",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getAlarmSummary,
      { "getAlarmSummary", "iec61850.ServiceSupportOptions.getAlarmSummary",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getAlarmEnrollmentSummary,
      { "getAlarmEnrollmentSummary", "iec61850.ServiceSupportOptions.getAlarmEnrollmentSummary",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_readJournal,
      { "readJournal", "iec61850.ServiceSupportOptions.readJournal",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_writeJournal,
      { "writeJournal", "iec61850.ServiceSupportOptions.writeJournal",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_initializeJournal,
      { "initializeJournal", "iec61850.ServiceSupportOptions.initializeJournal",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_reportJournalStatus,
      { "reportJournalStatus", "iec61850.ServiceSupportOptions.reportJournalStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_createJournal,
      { "createJournal", "iec61850.ServiceSupportOptions.createJournal",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_deleteJournal,
      { "deleteJournal", "iec61850.ServiceSupportOptions.deleteJournal",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_getCapabilityList,
      { "getCapabilityList", "iec61850.ServiceSupportOptions.getCapabilityList",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_fileOpen,
      { "fileOpen", "iec61850.ServiceSupportOptions.fileOpen",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_fileRead,
      { "fileRead", "iec61850.ServiceSupportOptions.fileRead",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_fileClose,
      { "fileClose", "iec61850.ServiceSupportOptions.fileClose",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_fileRename,
      { "fileRename", "iec61850.ServiceSupportOptions.fileRename",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_fileDelete,
      { "fileDelete", "iec61850.ServiceSupportOptions.fileDelete",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_fileDirectory,
      { "fileDirectory", "iec61850.ServiceSupportOptions.fileDirectory",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_unsolicitedStatus,
      { "unsolicitedStatus", "iec61850.ServiceSupportOptions.unsolicitedStatus",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_informationReport,
      { "informationReport", "iec61850.ServiceSupportOptions.informationReport",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_eventNotification,
      { "eventNotification", "iec61850.ServiceSupportOptions.eventNotification",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_attachToEventCondition,
      { "attachToEventCondition", "iec61850.ServiceSupportOptions.attachToEventCondition",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_attachToSemaphore,
      { "attachToSemaphore", "iec61850.ServiceSupportOptions.attachToSemaphore",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_conclude,
      { "conclude", "iec61850.ServiceSupportOptions.conclude",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_ServiceSupportOptions_cancel,
      { "cancel", "iec61850.ServiceSupportOptions.cancel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_Transitions_idle_to_disabled,
      { "idle-to-disabled", "iec61850.Transitions.idle.to.disabled",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_iec61850_Transitions_active_to_disabled,
      { "active-to-disabled", "iec61850.Transitions.active.to.disabled",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_iec61850_Transitions_disabled_to_idle,
      { "disabled-to-idle", "iec61850.Transitions.disabled.to.idle",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_iec61850_Transitions_active_to_idle,
      { "active-to-idle", "iec61850.Transitions.active.to.idle",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iec61850_Transitions_disabled_to_active,
      { "disabled-to-active", "iec61850.Transitions.disabled.to.active",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_iec61850_Transitions_idle_to_active,
      { "idle-to-active", "iec61850.Transitions.idle.to.active",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_iec61850_Transitions_any_to_deleted,
      { "any-to-deleted", "iec61850.Transitions.any.to.deleted",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    };

    /* List of subtrees */
    static int32_t *ett_mms[] = {
        &ettmms,
    &ett_iec61850_MMSpdu,
    &ett_iec61850_Confirmed_RequestPDU,
    &ett_iec61850_SEQUENCE_OF_Modifier,
    &ett_iec61850_Unconfirmed_PDU,
    &ett_iec61850_Confirmed_ResponsePDU,
    &ett_iec61850_Confirmed_ErrorPDU,
    &ett_iec61850_UnconfirmedService,
    &ett_iec61850_Modifier,
    &ett_iec61850_ConfirmedServiceRequest,
    &ett_iec61850_CS_Request_Detail,
    &ett_iec61850_ConfirmedServiceResponse,
    &ett_iec61850_FileName,
    &ett_iec61850_ObjectName,
    &ett_iec61850_T_domain_specific,
    &ett_iec61850_ApplicationReference,
    &ett_iec61850_Initiate_RequestPDU,
    &ett_iec61850_InitRequestDetail,
    &ett_iec61850_Initiate_ResponsePDU,
    &ett_iec61850_InitResponseDetail,
    &ett_iec61850_ParameterSupportOptions,
    &ett_iec61850_ServiceSupportOptions,
    &ett_iec61850_Cancel_ErrorPDU,
    &ett_iec61850_ServiceError,
    &ett_iec61850_T_errorClass,
    &ett_iec61850_T_serviceSpecificInformation,
    &ett_iec61850_AdditionalService_Error,
    &ett_iec61850_RemoveEventConditionListReference_Error,
    &ett_iec61850_InitiateUnitControl_Error,
    &ett_iec61850_StartUnitControl_Error,
    &ett_iec61850_StopUnitControl_Error,
    &ett_iec61850_DeleteUnitControl_Error,
    &ett_iec61850_LoadUnitControlFromFile_Error,
    &ett_iec61850_RejectPDU,
    &ett_iec61850_T_rejectReason,
    &ett_iec61850_Status_Response,
    &ett_iec61850_GetNameList_Request,
    &ett_iec61850_T_extendedObjectClass,
    &ett_iec61850_T_objectScope,
    &ett_iec61850_GetNameList_Response,
    &ett_iec61850_SEQUENCE_OF_Identifier,
    &ett_iec61850_Identify_Response,
    &ett_iec61850_T_listOfAbstractSyntaxes,
    &ett_iec61850_Rename_Request,
    &ett_iec61850_T_extendedObjectClass_01,
    &ett_iec61850_GetCapabilityList_Request,
    &ett_iec61850_GetCapabilityList_Response,
    &ett_iec61850_T_listOfCapabilities,
    &ett_iec61850_InitiateDownloadSequence_Request,
    &ett_iec61850_T_listOfCapabilities_01,
    &ett_iec61850_DownloadSegment_Response,
    &ett_iec61850_T_loadData,
    &ett_iec61850_TerminateDownloadSequence_Request,
    &ett_iec61850_InitiateUploadSequence_Response,
    &ett_iec61850_T_listOfCapabilities_02,
    &ett_iec61850_UploadSegment_Response,
    &ett_iec61850_T_loadData_01,
    &ett_iec61850_RequestDomainDownload_Request,
    &ett_iec61850_T_listOfCapabilities_03,
    &ett_iec61850_RequestDomainUpload_Request,
    &ett_iec61850_LoadDomainContent_Request,
    &ett_iec61850_T_listOfCapabilities_04,
    &ett_iec61850_StoreDomainContent_Request,
    &ett_iec61850_GetDomainAttributes_Response,
    &ett_iec61850_T_listOfCapabilities_05,
    &ett_iec61850_CreateProgramInvocation_Request,
    &ett_iec61850_Start_Request,
    &ett_iec61850_T_executionArgument,
    &ett_iec61850_Stop_Request,
    &ett_iec61850_Resume_Request,
    &ett_iec61850_T_executionArgument_01,
    &ett_iec61850_Reset_Request,
    &ett_iec61850_Kill_Request,
    &ett_iec61850_GetProgramInvocationAttributes_Response,
    &ett_iec61850_T_executionArgument_02,
    &ett_iec61850_TypeSpecification,
    &ett_iec61850_T_array,
    &ett_iec61850_T_structure,
    &ett_iec61850_T_components,
    &ett_iec61850_T_components_item,
    &ett_iec61850_AlternateAccess,
    &ett_iec61850_AlternateAccess_item,
    &ett_iec61850_T_named,
    &ett_iec61850_AlternateAccessSelection,
    &ett_iec61850_T_selectAlternateAccess,
    &ett_iec61850_T_accessSelection,
    &ett_iec61850_T_indexRange,
    &ett_iec61850_T_selectAccess,
    &ett_iec61850_T_indexRange_01,
    &ett_iec61850_Read_Request,
    &ett_iec61850_Read_Response,
    &ett_iec61850_SEQUENCE_OF_AccessResult,
    &ett_iec61850_Write_Request,
    &ett_iec61850_SEQUENCE_OF_Data,
    &ett_iec61850_Write_Response,
    &ett_iec61850_Write_Response_item,
    &ett_iec61850_InformationReport,
    &ett_iec61850_GetVariableAccessAttributes_Request,
    &ett_iec61850_GetVariableAccessAttributes_Response,
    &ett_iec61850_DefineNamedVariable_Request,
    &ett_iec61850_DefineScatteredAccess_Request,
    &ett_iec61850_GetScatteredAccessAttributes_Response,
    &ett_iec61850_DeleteVariableAccess_Request,
    &ett_iec61850_SEQUENCE_OF_ObjectName,
    &ett_iec61850_DeleteVariableAccess_Response,
    &ett_iec61850_DefineNamedVariableList_Request,
    &ett_iec61850_T_listOfVariable,
    &ett_iec61850_T_listOfVariable_item,
    &ett_iec61850_GetNamedVariableListAttributes_Response,
    &ett_iec61850_T_listOfVariable_01,
    &ett_iec61850_T_listOfVariable_item_01,
    &ett_iec61850_DeleteNamedVariableList_Request,
    &ett_iec61850_DeleteNamedVariableList_Response,
    &ett_iec61850_DefineNamedType_Request,
    &ett_iec61850_GetNamedTypeAttributes_Response,
    &ett_iec61850_DeleteNamedType_Request,
    &ett_iec61850_DeleteNamedType_Response,
    &ett_iec61850_AccessResult,
    &ett_iec61850_Data,
    &ett_iec61850_T_array_01,
    &ett_iec61850_T_structure_01,
    &ett_iec61850_VariableAccessSpecification,
    &ett_iec61850_T_listOfVariable_02,
    &ett_iec61850_T_listOfVariable_item_02,
    &ett_iec61850_ScatteredAccessDescription,
    &ett_iec61850_ScatteredAccessDescription_item,
    &ett_iec61850_VariableSpecification,
    &ett_iec61850_T_variableDescription,
    &ett_iec61850_Address,
    &ett_iec61850_TakeControl_Request,
    &ett_iec61850_TakeControl_Response,
    &ett_iec61850_RelinquishControl_Request,
    &ett_iec61850_DefineSemaphore_Request,
    &ett_iec61850_ReportSemaphoreStatus_Response,
    &ett_iec61850_ReportPoolSemaphoreStatus_Request,
    &ett_iec61850_ReportPoolSemaphoreStatus_Response,
    &ett_iec61850_T_listOfNamedTokens,
    &ett_iec61850_T_listOfNamedTokens_item,
    &ett_iec61850_ReportSemaphoreEntryStatus_Request,
    &ett_iec61850_ReportSemaphoreEntryStatus_Response,
    &ett_iec61850_SEQUENCE_OF_SemaphoreEntry,
    &ett_iec61850_AttachToSemaphore,
    &ett_iec61850_SemaphoreEntry,
    &ett_iec61850_Input_Request,
    &ett_iec61850_T_listOfPromptData,
    &ett_iec61850_Output_Request,
    &ett_iec61850_T_listOfOutputData,
    &ett_iec61850_DefineEventCondition_Request,
    &ett_iec61850_DeleteEventCondition_Request,
    &ett_iec61850_GetEventConditionAttributes_Response,
    &ett_iec61850_T_monitoredVariable,
    &ett_iec61850_ReportEventConditionStatus_Response,
    &ett_iec61850_AlterEventConditionMonitoring_Request,
    &ett_iec61850_TriggerEvent_Request,
    &ett_iec61850_DefineEventAction_Request,
    &ett_iec61850_DeleteEventAction_Request,
    &ett_iec61850_GetEventActionAttributes_Response,
    &ett_iec61850_DefineEventEnrollment_Request,
    &ett_iec61850_DeleteEventEnrollment_Request,
    &ett_iec61850_GetEventEnrollmentAttributes_Request,
    &ett_iec61850_EventEnrollment,
    &ett_iec61850_T_eventConditionName,
    &ett_iec61850_T_eventActionName,
    &ett_iec61850_GetEventEnrollmentAttributes_Response,
    &ett_iec61850_SEQUENCE_OF_EventEnrollment,
    &ett_iec61850_ReportEventEnrollmentStatus_Response,
    &ett_iec61850_AlterEventEnrollment_Request,
    &ett_iec61850_AlterEventEnrollment_Response,
    &ett_iec61850_T_currentState,
    &ett_iec61850_AcknowledgeEventNotification_Request,
    &ett_iec61850_GetAlarmSummary_Request,
    &ett_iec61850_T_severityFilter,
    &ett_iec61850_GetAlarmSummary_Response,
    &ett_iec61850_SEQUENCE_OF_AlarmSummary,
    &ett_iec61850_AlarmSummary,
    &ett_iec61850_GetAlarmEnrollmentSummary_Request,
    &ett_iec61850_T_severityFilter_01,
    &ett_iec61850_GetAlarmEnrollmentSummary_Response,
    &ett_iec61850_SEQUENCE_OF_AlarmEnrollmentSummary,
    &ett_iec61850_AlarmEnrollmentSummary,
    &ett_iec61850_EventNotification,
    &ett_iec61850_T_eventConditionName_01,
    &ett_iec61850_T_actionResult,
    &ett_iec61850_T_eventActionResult,
    &ett_iec61850_AttachToEventCondition,
    &ett_iec61850_EventTime,
    &ett_iec61850_Transitions,
    &ett_iec61850_ReadJournal_Request,
    &ett_iec61850_T_rangeStartSpecification,
    &ett_iec61850_T_rangeStopSpecification,
    &ett_iec61850_T_listOfVariables,
    &ett_iec61850_T_entryToStartAfter,
    &ett_iec61850_ReadJournal_Response,
    &ett_iec61850_SEQUENCE_OF_JournalEntry,
    &ett_iec61850_JournalEntry,
    &ett_iec61850_WriteJournal_Request,
    &ett_iec61850_SEQUENCE_OF_EntryContent,
    &ett_iec61850_InitializeJournal_Request,
    &ett_iec61850_T_limitSpecification,
    &ett_iec61850_ReportJournalStatus_Response,
    &ett_iec61850_CreateJournal_Request,
    &ett_iec61850_DeleteJournal_Request,
    &ett_iec61850_EntryContent,
    &ett_iec61850_T_entryForm,
    &ett_iec61850_T_data,
    &ett_iec61850_T_event,
    &ett_iec61850_T_listOfVariables_01,
    &ett_iec61850_T_listOfVariables_item,
    &ett_iec61850_ObtainFile_Request,
    &ett_iec61850_FileOpen_Request,
    &ett_iec61850_FileOpen_Response,
    &ett_iec61850_FileRead_Response,
    &ett_iec61850_FileRename_Request,
    &ett_iec61850_FileDirectory_Request,
    &ett_iec61850_FileDirectory_Response,
    &ett_iec61850_SEQUENCE_OF_DirectoryEntry,
    &ett_iec61850_DirectoryEntry,
    &ett_iec61850_FileAttributes,
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
