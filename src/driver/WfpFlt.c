//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2017 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include <fwpsk.h>
#include <fwpmk.h>

#include "WfpFlt.h"
#include "KmMemoryManager.h"
#include "BfeStateWatcher.h"
#include "WfpUtils.h"
#include "KmList.h"
#include "..\shared\CommonDefs.h"

/*
    ----------------------------------------------------------------------
    Types
    ----------------------------------------------------------------------
*/

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

typedef struct _WFP_CALLOUT_REG_ITEM
{
    ULONG32		CalloutRegId;
    GUID        CalloutKey;
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
    //  Memory manager
    PKM_MEMORY_MANAGER  MemoryManager;

    //  Driver object received in DriverEntry routine
    PDRIVER_OBJECT      DriverObject;

    //  Device object (used for callouts registration)
    PDEVICE_OBJECT      DeviceObject;

    //  Device object

    struct BFEInfo
    {
        //  Transport level injection handle
        //  Note: wfp requires separate injection
        //        handles for ipv6/ipv4 packet inspection
        HANDLE  TransportInjectionHandle;

        //  Handle to BFE engine
        HANDLE  EngineHandle;

        struct SubLayer
        {
            //  Boolean flag that identifies whether the sublayer was added
            BOOLEAN Added;

            //  Sublayer key
            GUID    Guid;

        } SubLayer;

        struct Provider
        {
            //  Boolean flag that identifies whether the provider was added
            BOOLEAN Added;

            //  Provider key
            GUID    Guid;

        } Provider;

        //  Handle to BFE state watcher instance
        HANDLE  BFEStateWatcher;

    } BFEInfo;

    //  Callouts registration information
    WFP_CALLOUT_REG_INFO        CalloutRegInfo;

    KM_LIST                     FlowContexts;

    //  Boolean value representing the current state
    ULONG                       FilteringActive;

    //  Event callback routine
    PWFP_NETWORK_EVENT_CALLBACK EventCallback;

    PVOID                       EventCallbackContext;

} WFP_DATA, *PWFP_DATA;

typedef struct _WFP_FLOW_INFO
{
    //  Layer id
    UINT16  LayerId;

    //  Callout id
    ULONG   CalloutId;

    //  Flow id (flow handle)
    UINT64  FlowId;

} WFP_FLOW_INFO, *PWFP_FLOW_INFO;

typedef struct _WFP_FLOW_CONTEXT
{
    //  List link
    LIST_ENTRY      Link;

    //  Flow info
    WFP_FLOW_INFO   FlowInfo;

    //  Network event info
    PNET_EVENT_INFO Info;

    //  Wfp data
    PWFP_DATA       WfpData;

} WFP_FLOW_CONTEXT, *PWFP_FLOW_CONTEXT;

/*
    ----------------------------------------------------------------------
    Various macros
    ----------------------------------------------------------------------
*/

#define WFP_SUBLAYER_NAME_W         L"ChangeDynamix Inspection sublayer"
#define WFP_SUBLAYER_DESC_W         L"ChangeDynamix sublayer for inspection callouts"

//  The string below MUST be exactly the same as the CompanyName string in the .info file for the HLK test
#define WFP_PROVIDER_NAME_W         L"Change Dynamix, LLC"

//  The string below MUST be exactly the same as the ProductName string in the .info file for the HLK test
#define WFP_PROVIDER_DESC_W         L"AEGIS WinPcap";

#define WFP_DEVICE_NAME_W           L"\\Device\\4FA9893C-A44A-4474-A9B9-ACDE01F32AFB"

#define WFP_GENERIC_CALLOUT_NAME_W  L"ChangeDynamix inspection callout"
#define WFP_GENERIC_CALLOUT_DESC_W  L"ChangeDynamix inspection callout"

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

#define WFP_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT_DEFINITION \
    __WFP_DECLARE_CALLOUT_DEFINITION( \
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, \
        FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4, \
        Wfp_ALE_RecvAccept_Callback)

#define WFP_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT_DEFINITION \
    __WFP_DECLARE_CALLOUT_DEFINITION( \
    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, \
    FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6, \
    Wfp_ALE_RecvAccept_Callback)

/*
    ----------------------------------------------------------------------
    Forward declarations
    ----------------------------------------------------------------------
*/

void __stdcall Wfp_BFEStateChangeCallback(
    __inout PVOID               Context,
    __in    FWPM_SERVICE_STATE  NewState);

WFP_DECLARE_CALLOUT_CALLBACK1(Wfp_ALE_Connect_Callback);

WFP_DECLARE_CALLOUT_CALLBACK1(Wfp_ALE_RecvAccept_Callback);

NTSTATUS __stdcall Wfp_Generic_NotifyCallback(
    __in            FWPS_CALLOUT_NOTIFY_TYPE    NotifyType,
    __in    const   GUID                        *FilterKey,
    __in    const   FWPS_FILTER                 *Filter);

void __stdcall Wfp_Generic_FlowDeleteNotifyCallback(
    __in	UINT16	LayerId,
    __in	UINT32	CalloutId,
    __in	UINT64	FlowContext);

NTSTATUS __stdcall Wfp_StartFiltering(
    __in    PWFP_DATA   Data);

NTSTATUS __stdcall Wfp_StopFiltering(
    __in    PWFP_DATA   Data);

NTSTATUS __stdcall Wfp_RegisterCallouts(
    __in            PWFP_DATA               Data,
    __in    const   WFP_CALLOUT_DEFINITION  *CalloutDefinitions,
    __in            ULONG                   NumberOfDefinitions);

NTSTATUS Wfp_RegisterCalloutsSub(
    __in            PWFP_DATA               Data,
    __in    const   WFP_CALLOUT_DEFINITION  *CalloutDefinition,
    __in            PDEVICE_OBJECT          DeviceObject,
    __out           PUINT32                 CalloutId,
    __out           PGUID                   CalloutKey,
    __out           PUINT64                 FilterId);

NTSTATUS Wfp_AddDefaultFilteringRule(
    __in            PWFP_DATA   Data,
    __in            PWCHAR      FilterName,
    __in            PWCHAR      FilterDesc,
    __in    const   GUID        *LayerKey,
    __in    const   GUID        *CalloutKey,
    __out           PUINT64     FilterId);

NTSTATUS Wfp_AllocateAndAssociateFlowContext(
    __in    PWFP_DATA       Data,
    __in    PNET_EVENT_INFO Info,
    __in    UINT64          FlowHandle,
    __in    UINT16          LayerId);

NTSTATUS Wfp_FindCalloutIdByLayerId(
    __in    PWFP_DATA   Data,
    __in    UINT16      LayerId,
    __out   PULONG      CalloutId);

void Wfp_CleanupFlowContexts(
    __in    PWFP_DATA   Data);

NTSTATUS Wfp_UnregisterCallouts(
    __in    PWFP_DATA   Data);

/*
    ----------------------------------------------------------------------
    Constants
    ----------------------------------------------------------------------
*/

const WFP_CALLOUT_DEFINITION Wfp_Callout_Definitions[] =
{
    WFP_ALE_AUTH_CONNECT_V4_CALLOUT_DEFINITION,
    WFP_ALE_AUTH_CONNECT_V6_CALLOUT_DEFINITION,
    WFP_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT_DEFINITION,
    WFP_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT_DEFINITION
};

const ULONG Wfp_Callouts_Count = ARRAYSIZE(Wfp_Callout_Definitions);

/*
    ----------------------------------------------------------------------
    Implementations
    ----------------------------------------------------------------------
*/

void __stdcall Wfp_BFEStateChangeCallback(
    __inout PVOID               Context,
    __in    FWPM_SERVICE_STATE  NewState)
{
    RETURN_IF_FALSE(Assigned(Context));

    switch (NewState)
    {
    case FWPM_SERVICE_RUNNING:
        {
            Wfp_StartFiltering((PWFP_DATA)Context);
        }break;

    case FWPM_SERVICE_STOP_PENDING:
        {
            Wfp_StopFiltering((PWFP_DATA)Context);
        }break;
    };
};

NTSTATUS __stdcall Wfp_Initialize(
    __in    PDRIVER_OBJECT              DriverObject,
    __in    PKM_MEMORY_MANAGER          MemoryManager,
    __in    PWFP_NETWORK_EVENT_CALLBACK EventCallback,
    __in    PVOID                       EventCallbackContext,
    __out   PHANDLE                     Instance)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PWFP_DATA           NewWfp = NULL;
    FWPM_SERVICE_STATE  BFEState;
    UNICODE_STRING      WfpDeviceName = RTL_CONSTANT_STRING(WFP_DEVICE_NAME_W);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DriverObject),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EventCallback),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Instance),
        STATUS_INVALID_PARAMETER_4);

    NewWfp = Km_MM_AllocMemTyped(
        MemoryManager,
        WFP_DATA);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewWfp),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewWfp, sizeof(WFP_DATA));

    Status = Km_List_Initialize(&NewWfp->FlowContexts);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = ExUuidCreate(&NewWfp->BFEInfo.SubLayer.Guid);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewWfp->CalloutRegInfo.Items = Km_MM_AllocArray(
        MemoryManager,
        WFP_CALLOUT_REG_ITEM,
        Wfp_Callouts_Count);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewWfp->CalloutRegInfo.Items),
        STATUS_INSUFFICIENT_RESOURCES);
    RtlZeroMemory(
        NewWfp->CalloutRegInfo.Items,
        sizeof(WFP_CALLOUT_REG_ITEM) * Wfp_Callouts_Count);
    NewWfp->CalloutRegInfo.MaxCount = Wfp_Callouts_Count;

    Status = IoCreateDevice(
        DriverObject,
        0,
        &WfpDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &NewWfp->DeviceObject);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewWfp->DriverObject = DriverObject;
    NewWfp->MemoryManager = MemoryManager;
    NewWfp->EventCallback = EventCallback;
    NewWfp->EventCallbackContext = EventCallbackContext;

    Status = BfeStateWatcher_Initialize(
        DriverObject,
        MemoryManager,
        Wfp_BFEStateChangeCallback,
        NewWfp,
        &NewWfp->BFEInfo.BFEStateWatcher);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    BFEState = FwpmBfeStateGet();

    if (BFEState == FWPM_SERVICE_RUNNING)
    {
        Wfp_StartFiltering(NewWfp);
    }

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewWfp))
        {
            if (Assigned(NewWfp->DeviceObject))
            {
                IoDeleteDevice(NewWfp->DeviceObject);
            }

            if (Assigned(NewWfp->CalloutRegInfo.Items))
            {
                Km_MM_FreeMem(
                    MemoryManager,
                    NewWfp->CalloutRegInfo.Items);
            }

            Km_MM_FreeMem(
                MemoryManager,
                NewWfp);
        }
    }
    else
    {
        *Instance = (HANDLE)NewWfp;
    }

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

    BfeStateWatcher_Finalize(Data->BFEInfo.BFEStateWatcher);

    Wfp_StopFiltering(Data);

    if (Assigned(Data->CalloutRegInfo.Items))
    {
        Km_MM_FreeMem(
            Data->MemoryManager,
            Data->CalloutRegInfo.Items);
    }

    if (Assigned(Data->DeviceObject))
    {
        IoDeleteDevice(Data->DeviceObject);
    }

    Km_MM_FreeMem(
        Data->MemoryManager,
        Data);

cleanup:
    return Status;
};

WFP_DECLARE_CALLOUT_CALLBACK1(Wfp_ALE_Connect_Callback)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PWFP_DATA       Data = NULL;
    PNET_EVENT_INFO Info = NULL;

    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(LayerData);

    RETURN_IF_FALSE(
        (Assigned(InFixedValues)) &&
        (Assigned(InMetaValues)) &&
        (Assigned(Filter)) &&
        (Assigned(ClassifyOut)));

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Filter->context != 0,
        STATUS_INVALID_PARAMETER);

    RETURN_IF_FALSE(
        IsBitFlagSet(
            ClassifyOut->rights,
            FWPS_RIGHT_ACTION_WRITE));

    Data = (PWFP_DATA)((ULONG_PTR)Filter->context);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Data->FilteringActive,
        STATUS_UNSUCCESSFUL);

    //  If the context is non-zero then
    //  the event in question was processed previously
    GOTO_CLEANUP_IF_FALSE(FlowContext == 0);

    Info = Km_MM_AllocMemTyped(
        Data->MemoryManager,
        NET_EVENT_INFO);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        Status = WfpUtils_FillNetworkEventInfo(
            InFixedValues,
            InMetaValues,
            Info);
        if (NT_SUCCESS(Status))
        {
            if (Assigned(Data->EventCallback))
            {
                Data->EventCallback(
                    wnetNewFlow,
                    Info,
                    Data->EventCallbackContext);
            }

            LEAVE_IF_FALSE(Data->FilteringActive);

            LEAVE_IF_FALSE(
                FWPS_IS_METADATA_FIELD_PRESENT(
                    InMetaValues,
                    FWPS_METADATA_FIELD_FLOW_HANDLE));

            Status = Wfp_AllocateAndAssociateFlowContext(
                Data,
                Info,
                InMetaValues->flowHandle,
                InFixedValues->layerId);

            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            Info = NULL;
        }
    }
    __finally
    {
        if (Assigned(Info))
        {
            Km_MM_FreeMem(
                Data->MemoryManager,
                Info);
        }
    }

cleanup:

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    return;
};

WFP_DECLARE_CALLOUT_CALLBACK1(Wfp_ALE_RecvAccept_Callback)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PWFP_DATA       Data = NULL;
    PNET_EVENT_INFO Info = NULL;

    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(LayerData);

    RETURN_IF_FALSE(
        (Assigned(InFixedValues)) &&
        (Assigned(InMetaValues)) &&
        (Assigned(Filter)) &&
        (Assigned(ClassifyOut)));

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Filter->context != 0,
        STATUS_INVALID_PARAMETER);

    RETURN_IF_FALSE(
        IsBitFlagSet(
            ClassifyOut->rights,
            FWPS_RIGHT_ACTION_WRITE));

    Data = (PWFP_DATA)((ULONG_PTR)Filter->context);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Data->FilteringActive,
        STATUS_UNSUCCESSFUL);

    //  If the context is non-zero then
    //  the event in question was processed previously
    GOTO_CLEANUP_IF_FALSE(FlowContext == 0);

    Info = Km_MM_AllocMemTyped(
        Data->MemoryManager,
        NET_EVENT_INFO);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        Status = WfpUtils_FillNetworkEventInfo(
            InFixedValues,
            InMetaValues,
            Info);
        if (NT_SUCCESS(Status))
        {
            if (Assigned(Data->EventCallback))
            {
                Data->EventCallback(
                    wnetNewFlow,
                    Info,
                    Data->EventCallbackContext);
            }

            LEAVE_IF_FALSE(Data->FilteringActive);

            LEAVE_IF_FALSE(
                FWPS_IS_METADATA_FIELD_PRESENT(
                    InMetaValues,
                    FWPS_METADATA_FIELD_FLOW_HANDLE));

            Status = Wfp_AllocateAndAssociateFlowContext(
                Data,
                Info,
                InMetaValues->flowHandle,
                InFixedValues->layerId);

            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            Info = NULL;
        }
    }
    __finally
    {
        if (Assigned(Info))
        {
            Km_MM_FreeMem(
                Data->MemoryManager,
                Info);
        }
    }

cleanup:

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    return;
};

NTSTATUS __stdcall Wfp_Generic_NotifyCallback(
    __in            FWPS_CALLOUT_NOTIFY_TYPE    NotifyType,
    __in    const   GUID                        *FilterKey,
    __in    const   FWPS_FILTER                 *Filter)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
};

void __stdcall Wfp_Generic_FlowDeleteNotifyCallback(
    __in	UINT16	LayerId,
    __in	UINT32	CalloutId,
    __in	UINT64	FlowContext)
{
    PWFP_FLOW_CONTEXT   Context = NULL;

    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);

    RETURN_IF_FALSE(FlowContext != 0);

    Context = (PWFP_FLOW_CONTEXT)((UINT_PTR)FlowContext);

    Km_List_RemoveItem(
        &Context->WfpData->FlowContexts,
        &Context->Link);

    if (Assigned(Context->Info))
    {
        if (Assigned(Context->WfpData->EventCallback))
        {
            Context->WfpData->EventCallback(
                wnetFlowRemove,
                Context->Info,
                Context->WfpData->EventCallbackContext);
        }

        Km_MM_FreeMem(
            Context->WfpData->MemoryManager,
            Context->Info);
    }

    Km_MM_FreeMem(
        Context->WfpData->MemoryManager,
        Context);
};

NTSTATUS __stdcall Wfp_StartFiltering(
    __in    PWFP_DATA   Data)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);

    Status = FwpsInjectionHandleCreate(
        AF_UNSPEC,
        FWPS_INJECTION_TYPE_TRANSPORT,
        &Data->BFEInfo.TransportInjectionHandle);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Wfp_RegisterCallouts(
        Data,
        Wfp_Callout_Definitions,
        Wfp_Callouts_Count);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    InterlockedExchange(
        (volatile LONG *)&Data->FilteringActive,
        TRUE);

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(Data))
        {
            if (Data->BFEInfo.TransportInjectionHandle != NULL)
            {
                FwpsInjectionHandleDestroy(Data->BFEInfo.TransportInjectionHandle);
                Data->BFEInfo.TransportInjectionHandle = NULL;
            }
        }
    }

    return Status;
};

NTSTATUS __stdcall Wfp_StopFiltering(
    __in    PWFP_DATA   Data)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);

    InterlockedExchange(
        (volatile LONG *)&Data->FilteringActive,
        FALSE);

    Wfp_CleanupFlowContexts(Data);

    Wfp_UnregisterCallouts(Data);

    if (Data->BFEInfo.TransportInjectionHandle != NULL)
    {
        FwpsInjectionHandleDestroy(Data->BFEInfo.TransportInjectionHandle);
        Data->BFEInfo.TransportInjectionHandle = NULL;
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Wfp_AddProvider(
    __in    PWFP_DATA   Data)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    UUID            ProviderKey = { 0, };
    FWPM_PROVIDER   Provider;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Data->BFEInfo.EngineHandle != NULL,
        STATUS_INVALID_PARAMETER_1);

    RtlZeroMemory(&Provider, sizeof(Provider));

    Status = ExUuidCreate(&ProviderKey);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Provider.displayData.name = WFP_PROVIDER_NAME_W;
    Provider.displayData.description = WFP_PROVIDER_DESC_W;

    RtlCopyMemory(
        &Provider.providerKey,
        &ProviderKey,
        sizeof(GUID));

    Status = FwpmProviderAdd(
        Data->BFEInfo.EngineHandle,
        &Provider,
        NULL);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Data->BFEInfo.Provider.Added = TRUE;
    RtlCopyMemory(
        &Data->BFEInfo.Provider.Guid,
        &ProviderKey,
        sizeof(GUID));

cleanup:
    return Status;
};

NTSTATUS __stdcall Wfp_RegisterCallouts(
    __in            PWFP_DATA               Data,
    __in    const   WFP_CALLOUT_DEFINITION  *CalloutDefinitions,
    __in            ULONG                   NumberOfDefinitions)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    FWPM_SUBLAYER   SubLayer = { 0, };
    BOOLEAN         EngineOpened = FALSE;
    BOOLEAN         TransactionInProgress = FALSE;
    FWPM_SESSION    Session = { 0, };
    ULONG           k;
    
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutDefinitions),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NumberOfDefinitions > 0,
        STATUS_INVALID_PARAMETER_3);

    Session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    Status = FwpmEngineOpen(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &Session,
        &Data->BFEInfo.EngineHandle);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    EngineOpened = TRUE;

    Status = FwpmTransactionBegin(
        Data->BFEInfo.EngineHandle,
        0);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    TransactionInProgress = TRUE;

    Status = Wfp_AddProvider(Data);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    SubLayer.subLayerKey = Data->BFEInfo.SubLayer.Guid;
    SubLayer.displayData.name = WFP_SUBLAYER_NAME_W;
    SubLayer.displayData.description = WFP_SUBLAYER_DESC_W;
    SubLayer.flags = 0;
    SubLayer.weight = 0;
    SubLayer.providerKey = &Data->BFEInfo.Provider.Guid;

    Status = FwpmSubLayerAdd(
        Data->BFEInfo.EngineHandle,
        &SubLayer,
        NULL);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    Data->BFEInfo.SubLayer.Added = TRUE;

    /* Now start registering the callouts. */
    for (k = 0; k < NumberOfDefinitions; k++)
    {
        GUID    CalloutKey = { 0, };

        Status = Wfp_RegisterCalloutsSub(
            Data,
            &CalloutDefinitions[k],
            Data->DeviceObject,
            &Data->CalloutRegInfo.Items[k].CalloutRegId,
            &CalloutKey,
            &Data->CalloutRegInfo.Items[k].FilterId);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

        RtlCopyMemory(
            &Data->CalloutRegInfo.Items[k].CalloutKey,
            &CalloutKey,
            sizeof(GUID));

        Data->CalloutRegInfo.Items[k].LayerId = CalloutDefinitions[k].LayerId;
        Data->CalloutRegInfo.Count++;
    }

    Status = FwpmTransactionCommit(Data->BFEInfo.EngineHandle);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    TransactionInProgress = FALSE;

cleanup:
    if (!NT_SUCCESS(Status))
    {
        if (TransactionInProgress)
        {
            FwpmTransactionAbort(Data->BFEInfo.EngineHandle);
        }

        if (Data->BFEInfo.SubLayer.Added)
        {
            FwpmSubLayerDeleteByKey(
                Data->BFEInfo.EngineHandle,
                &Data->BFEInfo.SubLayer.Guid);
            Data->BFEInfo.SubLayer.Added = FALSE;
        }

        if (Data->BFEInfo.Provider.Added)
        {
            Data->BFEInfo.Provider.Added = FALSE;
        }

        if (EngineOpened)
        {
            FwpmEngineClose(Data->BFEInfo.EngineHandle);
            Data->BFEInfo.EngineHandle = NULL;
        }

        if (Assigned(Data->CalloutRegInfo.Items))
        {
            RtlZeroMemory(
                Data->CalloutRegInfo.Items,
                sizeof(WFP_CALLOUT_REG_INFO) * Data->CalloutRegInfo.MaxCount);
        }
    }

    return Status;
};

NTSTATUS Wfp_RegisterCalloutsSub(
    __in            PWFP_DATA               Data,
    __in    const   WFP_CALLOUT_DEFINITION  *CalloutDefinition,
    __in            PDEVICE_OBJECT          DeviceObject,
    __out           PUINT32                 CalloutId,
    __out           PGUID                   CalloutKey,
    __out           PUINT64                 FilterId)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    FWPS_CALLOUT1       sCallout = { 0, };
    FWPM_CALLOUT        mCallout = { 0, };
    FWPM_DISPLAY_DATA   DisplayData = { 0, };
    BOOLEAN             Registered = FALSE;
    GUID                NewGuid;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutDefinition),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutDefinition->CalloutLayer),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceObject),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutId),
        STATUS_INVALID_PARAMETER_4);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutKey),
        STATUS_INVALID_PARAMETER_5);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(FilterId),
        STATUS_INVALID_PARAMETER_6);

    Status = ExUuidCreate(&NewGuid);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    RtlCopyMemory(
        CalloutKey,
        &NewGuid,
        sizeof(NewGuid));

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutDefinition->Callbacks.Classify),
        STATUS_INVALID_PARAMETER_MIX);
    RtlCopyMemory(
        &sCallout.calloutKey,
        &NewGuid,
        sizeof(NewGuid));

    sCallout.classifyFn = CalloutDefinition->Callbacks.Classify;
    sCallout.notifyFn = CalloutDefinition->Callbacks.Notify;
    sCallout.flowDeleteFn = CalloutDefinition->Callbacks.FlowDeleteNotify;

    Status = FwpsCalloutRegister(
        DeviceObject,
        &sCallout,
        CalloutId);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Registered = TRUE;

    DisplayData.name = WFP_GENERIC_CALLOUT_NAME_W;
    DisplayData.description = WFP_GENERIC_CALLOUT_DESC_W;

    mCallout.calloutKey = NewGuid;
    mCallout.displayData = DisplayData;
    mCallout.applicableLayer = *(CalloutDefinition->CalloutLayer);
    mCallout.flags |= FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT;
    mCallout.providerKey = &Data->BFEInfo.Provider.Guid;

    Status = FwpmCalloutAdd(
        Data->BFEInfo.EngineHandle,
        &mCallout,
        NULL,
        NULL);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Wfp_AddDefaultFilteringRule(
        Data,
        WFP_GENERIC_CALLOUT_NAME_W,
        WFP_GENERIC_CALLOUT_DESC_W,
        CalloutDefinition->CalloutLayer,
        &NewGuid,
        FilterId);
    if (!NT_SUCCESS(Status))
    {
        FwpsCalloutUnregisterById(*CalloutId);
        *CalloutId = 0;
    }

cleanup:
    return Status;
};

NTSTATUS Wfp_AddDefaultFilteringRule(
    __in            PWFP_DATA   Data,
    __in            PWCHAR      FilterName,
    __in            PWCHAR      FilterDesc,
    __in    const   GUID        *LayerKey,
    __in    const   GUID        *CalloutKey,
    __out           PUINT64     FilterId)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    FWPM_FILTER Filter = { 0, };

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(LayerKey),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutKey),
        STATUS_INVALID_PARAMETER_4);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(FilterId),
        STATUS_INVALID_PARAMETER_5);

    Filter.numFilterConditions = 0;

    Filter.layerKey = *LayerKey;
    Filter.subLayerKey = Data->BFEInfo.SubLayer.Guid;

    Filter.displayData.name = FilterName;
    Filter.displayData.description = FilterDesc;

    /* We want all sorts of calls to come to us. */
    Filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    Filter.action.calloutKey = *CalloutKey;

    Filter.weight.type = FWP_EMPTY;

    Filter.rawContext = (UINT_PTR)Data;

    Filter.providerKey = &Data->BFEInfo.Provider.Guid;

    Status = FwpmFilterAdd(
        Data->BFEInfo.EngineHandle,
        &Filter,
        NULL,
        FilterId);

cleanup:
    return Status;
};

NTSTATUS Wfp_AllocateAndAssociateFlowContext(
    __in    PWFP_DATA       Data,
    __in    PNET_EVENT_INFO Info,
    __in    UINT64          FlowHandle,
    __in    UINT16          LayerId)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    ULONG               CalloutId;
    PWFP_FLOW_CONTEXT   NewContext;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Data->FilteringActive,
        STATUS_UNSUCCESSFUL);

    Status = Wfp_FindCalloutIdByLayerId(
        Data,
        LayerId,
        &CalloutId);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewContext = Km_MM_AllocMemTyped(
        Data->MemoryManager,
        WFP_FLOW_CONTEXT);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewContext),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        RtlZeroMemory(
            NewContext,
            sizeof(WFP_FLOW_CONTEXT));

        NewContext->FlowInfo.CalloutId = CalloutId;
        NewContext->FlowInfo.FlowId = FlowHandle;
        NewContext->FlowInfo.LayerId = LayerId;
        NewContext->Info = Info;
        NewContext->WfpData = Data;

        Status = Km_List_Lock(&Data->FlowContexts);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));
        __try
        {
            Status = Km_List_AddItemEx(
                &Data->FlowContexts,
                &NewContext->Link,
                FALSE,
                FALSE);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));
            __try
            {
                Status = FwpsFlowAssociateContext(
                    FlowHandle,
                    LayerId,
                    CalloutId,
                    (UINT64)NewContext);
            }
            __finally
            {
                if (!NT_SUCCESS(Status))
                {
                    Km_List_RemoveItemEx(
                        &Data->FlowContexts,
                        &NewContext->Link,
                        FALSE,
                        FALSE);
                }
            }
        }
        __finally
        {
            Km_List_Unlock(&Data->FlowContexts);
        }
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            Km_MM_FreeMem(
                Data->MemoryManager,
                NewContext);
        }
    }

cleanup:
    return Status;
};

NTSTATUS Wfp_FindCalloutIdByLayerId(
    __in    PWFP_DATA   Data,
    __in    UINT16      LayerId,
    __out   PULONG      CalloutId)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    ULONG       k;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CalloutId),
        STATUS_INVALID_PARAMETER_3);

    Status = STATUS_NOT_FOUND;

    for (k = 0; k < Data->CalloutRegInfo.Count; k++)
    {
        if (Data->CalloutRegInfo.Items[k].LayerId == LayerId)
        {
            *CalloutId = Data->CalloutRegInfo.Items[k].CalloutRegId;
            Status = STATUS_SUCCESS;
            break;
        }
    }

cleanup:
    return Status;
};

void Wfp_CleanupFlowContexts(
    __in    PWFP_DATA   Data)
{
    PWFP_FLOW_CONTEXT   Context;
    PLIST_ENTRY         ListEntry;
    NTSTATUS            Status = STATUS_SUCCESS;
    ULARGE_INTEGER      Count;
    PWFP_FLOW_INFO      InfoArray = NULL;
    ULONG               k;

    RETURN_IF_FALSE(Assigned(Data));

    Count.QuadPart = MAXULONGLONG;

    Status = Km_List_Lock(&Data->FlowContexts);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_GetCountEx(&Data->FlowContexts, &Count, FALSE, FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        LEAVE_IF_FALSE(Count.QuadPart > 0);

        InfoArray = Km_MM_AllocArray(
            Data->MemoryManager,
            WFP_FLOW_INFO,
            (SIZE_T)Count.QuadPart);
        LEAVE_IF_FALSE(Assigned(InfoArray));

        for (ListEntry = Data->FlowContexts.Head.Flink, k = 0;
            ListEntry != &Data->FlowContexts.Head;
            ListEntry = ListEntry->Flink, k++)
        {
            Context = CONTAINING_RECORD(ListEntry, WFP_FLOW_CONTEXT, Link);

            RtlCopyMemory(
                &(InfoArray[k]),
                &Context->FlowInfo,
                sizeof(WFP_FLOW_INFO));
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->FlowContexts);
    }

    GOTO_CLEANUP_IF_FALSE(
        (NT_SUCCESS(Status)) &&
        (Assigned(InfoArray)));

    for (k = 0; k < Count.QuadPart; k++)
    {
        FwpsFlowRemoveContext(
            InfoArray[k].FlowId,
            InfoArray[k].LayerId,
            InfoArray[k].CalloutId);
    }

cleanup:

    if (Assigned(InfoArray))
    {
        Km_MM_FreeMem(
            Data->MemoryManager, 
            InfoArray);
    }

    return;
};

NTSTATUS Wfp_UnregisterCallouts(
    __in    PWFP_DATA   Data)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    ULONG       k;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);

    if (Data->CalloutRegInfo.Count > 0)
    {
        for (k = 0; k < Data->CalloutRegInfo.Count; k++)
        {
            Status = FwpmFilterDeleteById(
                Data->BFEInfo.EngineHandle,
                Data->CalloutRegInfo.Items[k].FilterId);
            GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

            FwpsCalloutUnregisterById(Data->CalloutRegInfo.Items[k].CalloutRegId);

            FwpmCalloutDeleteByKey(
                Data->BFEInfo.EngineHandle,
                &Data->CalloutRegInfo.Items[k].CalloutKey);
        }

        Data->CalloutRegInfo.Count = 0;
    }

    if (Data->BFEInfo.SubLayer.Added)
    {
        Status = FwpmSubLayerDeleteByKey(
            Data->BFEInfo.EngineHandle,
            &Data->BFEInfo.SubLayer.Guid);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

        Data->BFEInfo.SubLayer.Added = FALSE;
    }

    if (Data->BFEInfo.Provider.Added)
    {
        Status = FwpmProviderDeleteByKey(
            Data->BFEInfo.EngineHandle,
            &Data->BFEInfo.Provider.Guid);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

        Data->BFEInfo.Provider.Added = FALSE;
    }

    if (Data->BFEInfo.EngineHandle != NULL)
    {
        Status = FwpmEngineClose(Data->BFEInfo.EngineHandle);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

        Data->BFEInfo.EngineHandle = NULL;
    }

cleanup:
    return Status;
};