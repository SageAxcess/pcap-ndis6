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

// This directive puts the DriverEntry function into the INIT segment of the
// driver.  To conserve memory, the code will be discarded when the driver's
// DriverEntry function returns.  You can declare other functions used only
// during initialization here.
#pragma NDIS_INIT_FUNCTION(DriverEntry)

//
// Global variables
//
//TODO: check which are used, write description in comments, rename so it's readable!
PDRIVER_OBJECT      FilterDriverObject;
NDIS_HANDLE         FilterDriverHandle;
NDIS_HANDLE         FilterProtocolHandle;
NDIS_HANDLE         FilterProtocolObject;
NDIS_HANDLE         NdisFilterDeviceHandle = NULL;
PDEVICE_OBJECT      NdisDeviceObject = NULL;

FILTER_LOCK         FilterListLock;
LIST_ENTRY          FilterModuleList;

PDEVICE             ListAdaptersDevice = NULL;

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT      DriverObject,
    PUNICODE_STRING     RegistryPath
    )
{
    NDIS_STATUS Status;
//    NDIS_FILTER_DRIVER_CHARACTERISTICS      FChars;
//    NDIS_STRING ServiceName  = RTL_CONSTANT_STRING(FILTER_SERVICE_NAME);
//    NDIS_STRING UniqueName   = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME);
//    NDIS_STRING DisplayName = RTL_CONSTANT_STRING(FILTER_DISPLAY_NAME);
    NDIS_STRING ProtocolName = RTL_CONSTANT_STRING(FILTER_PROTOCOL_NAME);

    UNREFERENCED_PARAMETER(RegistryPath);

    DEBUGP(DL_TRACE, "===>DriverEntry...\n");

    FilterDriverObject = DriverObject;

	NDIS_PROTOCOL_DRIVER_CHARACTERISTICS pChars;
	NdisZeroMemory(&pChars, sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS));

	pChars.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;

	pChars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
	pChars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;

	pChars.MajorNdisVersion = 6;
	pChars.MinorNdisVersion = 20;
	pChars.Name = ProtocolName;

	pChars.SetOptionsHandler = Protocol_SetOptionsHandler;
	pChars.BindAdapterHandlerEx = Protocol_BindAdapterHandlerEx;
	pChars.UnbindAdapterHandlerEx = Protocol_UnbindAdapterHandlerEx;
	pChars.OpenAdapterCompleteHandlerEx = Protocol_OpenAdapterCompleteHandlerEx;
	pChars.CloseAdapterCompleteHandlerEx = Protocol_CloseAdapterCompleteHandlerEx;
	pChars.NetPnPEventHandler = Protocol_NetPnPEventHandler;
	pChars.UninstallHandler = Protocol_UninstallHandler;
	pChars.OidRequestCompleteHandler = Protocol_OidRequestCompleteHandler;
	pChars.StatusHandlerEx = Protocol_StatusHandlerEx;
	pChars.ReceiveNetBufferListsHandler = Protocol_ReceiveNetBufferListsHandler;
	pChars.SendNetBufferListsCompleteHandler = Protocol_SendNetBufferListsCompleteHandler;
	pChars.DirectOidRequestCompleteHandler = Protocol_DirectOidRequestCompleteHandler;

	Status = NdisRegisterProtocolDriver(NULL, &pChars, &FilterProtocolHandle);

	NdisZeroMemory(DriverObject->MajorFunction, sizeof(DriverObject->MajorFunction));

	DriverObject->MajorFunction[IRP_MJ_CREATE] = Device_CreateHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Device_CloseHandler;
	DriverObject->MajorFunction[IRP_MJ_READ] = Device_ReadHandler;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = Device_WriteHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Device_IoControlHandler;
	
	DriverObject->DriverUnload = DriverUnload;
	AdapterList = CreateList();
	ListAdaptersDevice = CreateDevice(ADAPTER_NAME_FORLIST);
	if (ListAdaptersDevice) {
		ListAdaptersDevice->IsAdaptersList = TRUE;
	}

	if(Status!=NDIS_STATUS_SUCCESS)
	{
		DriverUnload(DriverObject);
	}

    DEBUGP(DL_TRACE, "<===DriverEntry, Status = %8x\n", Status);
    return Status;
}

void DriverUnload(DRIVER_OBJECT* DriverObject)
{
	DEBUGP(DL_TRACE, "===>DriverUnload");

	_CRT_UNUSED(DriverObject);

	if (FilterProtocolHandle != NULL)
	{
		NdisDeregisterProtocolDriver(FilterProtocolHandle);
		FilterProtocolHandle = NULL;
	}

	ListAdaptersDevice->Releasing = TRUE;
	DriverSleep(500);

	FreeDevice(ListAdaptersDevice);
	FreeAdapterList(AdapterList);
	AdapterList = NULL;
	DEBUGP(DL_TRACE, "<===DriverUnload");
}

PVOID FilterAllocMem(NDIS_HANDLE NdisHandle, UINT Size)
{
	_CRT_UNUSED(NdisHandle);

	PVOID Result = NULL;
	NDIS_STATUS ret = NdisAllocateMemoryWithTag(&Result, Size, FILTER_ALLOC_TAG);
	if(ret!=NDIS_STATUS_SUCCESS)
	{
		return NULL;
	}

	//DEBUGP(DL_TRACE, "FilterAllocMem, size=%u, result=0x%08x\n", Size, Result);

	return Result;
}

void FilterFreeMem(PVOID Data)
{
	//DEBUGP(DL_TRACE, "FilterFreeMem 0x%08x\n", Data);
	NdisFreeMemory(Data, 0, 0);
}