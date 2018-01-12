//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2017 ChangeDynamix, LLC
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include "WfpFlt.h"
#include "KmMemoryManagery.h"

typedef struct _WFP_CALLOUT_DEFINITION
{
    GUID    const   *CalloutLayer;
    UINT16          LayerId;

    struct Callbacks
    {
        FWPS_CALLOUT_CLASSIFY_FN            Classify;
        FWPS_CALLOUT_NOTIFY_FN              Notify;
        FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN  FlowDeleteNotify;
    } Callbacks;
} WFP_CALLOUT_DEFINITION, *PWFP_CALLOUT_DEFINITION;

#define WFP_DECLARE_CALLOUT_CALLBACK1(CallbackName) \
    void CallbackName( \
        __in        const FWPS_INCOMING_VALUES          *InFixedValues, \
        __in        const FWPS_INCOMING_METADATA_VALUES *InMetaValues, \
        __inout     PVOID                               LayerData, \
        __in_opt    const void                          *ClassifyContext, \
        __in        const FWPS_FILTER1                  *Filter, \
        __in        UINT64                              FlowContext, \
        __out       FWPS_CLASSIFY_OUT                   *ClassifyOut)

#define __WFP_DECLARE_CALLOUT_DEFINITION(Layer, LayerId, ClassifyCallback) \
{ \
    Layer, \
    LayerId, \
    { \
        ClassifyCallback, \
        Wfp_Generic_NotifyCallback, \
        Wfp_Generic_FlowDeleteNotifyCallback \
    } \
}

#define WFP_ALE_AUTH_CONNECT_V4_CALLOUT_DEFINITION \
    __WFP_DECLARE_CALLOUT_DEFINITION( \
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4, \
        FWPS_LAYER_ALE_AUTH_CONNECT_V4, \
        Wfp_ALE_Connect_Callback)

#define WFP_ALE_AUTH_CONNECT_V6_CALLOUT_DEFINITION \
    __WFP_DECLARE_CALLOUT_DEFINITION( \
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6, \
        FWPS_LAYER_ALE_AUTH_CONNECT_V6, \
        Wfp_ALE_Connect_Callback)

WFP_DECLARE_CALLOUT_CALLBACK1(Wfp_ALE_Connect_Callback);

NTSTATUS Wfp_Generic_NotifyCallback(
    __in            FWPS_CALLOUT_NOTIFY_TYPE    NotifyType,
    __in    const   GUID                        *FilterKey,
    __in    const   FWPS_FILTER1                *Filter);

void Wfp_Generic_FlowDeleteNotifyCallback(
    __in	UINT16	LayerId,
    __in	UINT32	CalloutId,
    __in	UINT64	FlowContext);

const WFP_CALLOUT_DEFINITION Wfp_Callout_Definitions[] =
{
    WFP_ALE_AUTH_CONNECT_V4_CALLOUT_DEFINITION,
    WFP_ALE_AUTH_CONNECT_V6_CALLOUT_DEFINITION
};

typedef struct _WFP_CALLOUT_REG_ITEM
{
    ULONG32		CalloutRegId;
    GUID		LayerGUID;
    UINT16		LayerId;
    UINT64      FilterId;
} WFP_CALLOUT_REG_ITEM, *PWFP_CALLOUT_REG_ITEM;

typedef struct _WFP_CALLOUT_REG_INFO
{
    ULONG					MaxCount;
    ULONG					Count;
    PWFP_CALLOUT_REG_ITEM   Items;
} WFP_CALLOUT_REG_INFO, *PWFP_CALLOUT_REG_INFO;

typedef struct _WFP_DATA
{
    PKM_MEMORY_MANAGER  MemoryManager;

    PDRIVER_OBJECT      DriverObject;

    struct BFEInfo
    {
        HANDLE  TransportInjectionHandle;
        HANDLE  EngineHandle;
        GUID    SubLayerGuid;
        HANDLE  BFEChangeHandle;
    } BFEInfo;

    PWFP_CALLOUT_REG_INFO   CalloutRegInfo;

} WFP_DATA, *PWFP_DATA;

NTSTATUS __stdcall Wfp_Initialize(
    __in    PDRIVER_OBJECT      DriverObject,
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PHANDLE             Instance)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PWFP_DATA   NewWfp = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DriverObject),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Instance),
        STATUS_INVALID_PARAMETER_3);

    NewWfp = Km_MM_AllocMemTyped(
        MemoryManager,
        WFP_DATA);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewWfp),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewWfp, sizeof(WFP_DATA));

    NewWfp->DriverObject = DriverObject;
    NewWfp->MemoryManager = MemoryManager;
    
cleanup:
    return Status;
};

NTSTATUS __stdcall Wfp_Finalize(
    __in    HANDLE  Instance)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PWFP_DATA   Data = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);

    Data = (PWFP_DATA)Instance;

cleanup:
    return Status;
};