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
// Author: Mikhail Burilov
// 
// Based on original WinPcap source code - https://www.winpcap.org/
// Copyright(c) 1999 - 2005 NetGroup, Politecnico di Torino(Italy)
// Copyright(c) 2005 - 2007 CACE Technologies, Davis(California)
// Filter driver based on Microsoft examples - https://github.com/Microsoft/Windows-driver-samples
// Copyrithg(C) 2015 Microsoft
// All rights reserved.
//////////////////////////////////////////////////////////////////////

#include "precomp.h"
#include "KernelUtil.h"
#include "Device.h"
#include "Adapter.h"
#include "KmTypes.h"
#include "NdisMemoryManager.h"

#include "..\shared\CommonDefs.h"

// This directive puts the DriverEntry function into the INIT segment of the
// driver.  To conserve memory, the code will be discarded when the driver's
// DriverEntry function returns.  You can declare other functions used only
// during initialization here.
#pragma NDIS_INIT_FUNCTION(DriverEntry)

//
// Global variables
//

DRIVER_DATA DriverData;

NTSTATUS __stdcall RegisterNdisProtocol(
    __inout PDRIVER_DATA    Data)
{
    NTSTATUS                                Status = STATUS_SUCCESS;
    NDIS_STATUS                             NdisStatus = NDIS_STATUS_SUCCESS;
    NDIS_PROTOCOL_DRIVER_CHARACTERISTICS    Chars;
    NDIS_STRING                             ProtocolName = RTL_CONSTANT_STRING(FILTER_PROTOCOL_NAME);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);

    RtlZeroMemory(&Chars, sizeof(Chars));

    Chars.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;

    Chars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    Chars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;

    Chars.MajorNdisVersion = 6;
    Chars.MinorNdisVersion = 20;
    Chars.Name = ProtocolName;

    Chars.SetOptionsHandler = Protocol_SetOptionsHandler;
    Chars.BindAdapterHandlerEx = Protocol_BindAdapterHandlerEx;
    Chars.UnbindAdapterHandlerEx = Protocol_UnbindAdapterHandlerEx;
    Chars.OpenAdapterCompleteHandlerEx = Protocol_OpenAdapterCompleteHandlerEx;
    Chars.CloseAdapterCompleteHandlerEx = Protocol_CloseAdapterCompleteHandlerEx;
    Chars.NetPnPEventHandler = Protocol_NetPnPEventHandler;
    Chars.UninstallHandler = Protocol_UninstallHandler;
    Chars.OidRequestCompleteHandler = Protocol_OidRequestCompleteHandler;
    Chars.StatusHandlerEx = Protocol_StatusHandlerEx;
    Chars.ReceiveNetBufferListsHandler = Protocol_ReceiveNetBufferListsHandler;
    Chars.SendNetBufferListsCompleteHandler = Protocol_SendNetBufferListsCompleteHandler;
    Chars.DirectOidRequestCompleteHandler = Protocol_DirectOidRequestCompleteHandler;
    
    NdisStatus = NdisRegisterProtocolDriver(
        (NDIS_HANDLE)Data,
        &Chars,
        &Data->Ndis.ProtocolHandle);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NdisStatus == NDIS_STATUS_SUCCESS,
        STATUS_UNSUCCESSFUL);

cleanup:
    return Status;
};

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT      DriverObject,
    PUNICODE_STRING     RegistryPath)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(
        &DriverData,
        sizeof(DriverData));

    Status = RegisterNdisProtocol(&DriverData);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Ndis_MM_Initialize(
        &DriverData.Ndis.MemoryManager,
        DriverData.Ndis.ProtocolHandle,
        HighPoolPriority,
        NDIS_FLT_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    DriverData.Other.DriverObject = DriverObject;

    Status = Km_List_Initialize(&DriverData.AdaptersList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    DriverData.ListAdaptersDevice = CreateDevice2(
        DriverObject,
        &DriverData,
        ADAPTER_NAME_FORLIST_W);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DriverData.ListAdaptersDevice),
        STATUS_INSUFFICIENT_RESOURCES);

    DriverData.ListAdaptersDevice->IsAdaptersList = TRUE;

    RtlZeroMemory(
        DriverObject->MajorFunction,
        sizeof(DriverObject->MajorFunction));

    DriverObject->MajorFunction[IRP_MJ_CREATE] = Device_CreateHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = Device_CloseHandler;
    DriverObject->MajorFunction[IRP_MJ_READ] = Device_ReadHandler;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = Device_WriteHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Device_IoControlHandler;

    DriverObject->DriverUnload = DriverUnload;

cleanup:

    if (!NT_SUCCESS(Status))
    {
        Km_MM_Finalize(&DriverData.Ndis.MemoryManager);
        if (DriverData.Ndis.ProtocolHandle != NULL)
        {
            NdisDeregisterProtocolDriver(DriverData.Ndis.ProtocolHandle);
            DriverData.Ndis.ProtocolHandle = NULL;
        }

        RtlZeroMemory(
            &DriverData,
            sizeof(DriverData));
    }

    return Status;
};

void
_Function_class_(DRIVER_UNLOAD)
DriverUnload(DRIVER_OBJECT* DriverObject)
{
    _CRT_UNUSED(DriverObject);

    InterlockedExchange(
        &DriverData.DriverUnload,
        TRUE);

    Km_MM_Finalize(&DriverData.Ndis.MemoryManager);

    if (DriverData.Ndis.ProtocolHandle != NULL)
    {
        NdisDeregisterProtocolDriver(DriverData.Ndis.ProtocolHandle);
        DriverData.Ndis.ProtocolHandle = NULL;
    }

    FreeDevice(DriverData.ListAdaptersDevice);

    ClearAdaptersList(&DriverData.AdaptersList);

    RtlZeroMemory(
        &DriverData,
        sizeof(DriverData));
}