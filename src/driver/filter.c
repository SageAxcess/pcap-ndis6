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
	memset(&pChars, 0, sizeof(pChars));
	pChars.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
#if NDIS_SUPPORT_NDIS61
	pChars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
	pChars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
#else
	pChars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
	pChars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
#endif

	pChars.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
	pChars.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;
	pChars.Name = ProtocolName;

	pChars.BindAdapterHandlerEx = Protocol_BindAdapterHandlerEx;
	pChars.UnbindAdapterHandlerEx = Protocol_UnbindAdapterHandlerEx;
	pChars.OpenAdapterCompleteHandlerEx = Protocol_OpenAdapterCompleteHandlerEx;
	pChars.CloseAdapterCompleteHandlerEx = Protocol_CloseAdapterCompleteHandlerEx;
	pChars.OidRequestCompleteHandler = Protocol_OidRequestCompleteHandler;
	pChars.ReceiveNetBufferListsHandler = Protocol_ReceiveNetBufferListsHandler;
	pChars.SendNetBufferListsCompleteHandler = Protocol_SendNetBufferListsCompleteHandler;

	memset(DriverObject->MajorFunction, 0, sizeof(DriverObject->MajorFunction));

	DriverObject->MajorFunction[IRP_MJ_CREATE] = Device_CreateHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Device_CloseHandler;
	DriverObject->MajorFunction[IRP_MJ_READ] = Device_ReadHandler;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = Device_WriteHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Device_IoControlHandler;
	
	DriverObject->DriverUnload = DriverUnload;
	AdapterList = CreateList();
	ListAdaptersDevice = CreateDevice(ADAPTER_NAME_FORLIST);
	ListAdaptersDevice->IsAdaptersList = TRUE;

	Status = NdisRegisterProtocolDriver(NULL, &pChars, &FilterProtocolHandle);

    DEBUGP(DL_TRACE, "<===DriverEntry, Status = %8x\n", Status);
    return Status;
}

void DriverUnload(DRIVER_OBJECT* DriverObject)
{
	_CRT_UNUSED(DriverObject);

	if (FilterProtocolHandle != NULL)
	{
		NdisDeregisterProtocolDriver(FilterProtocolHandle);
		FilterProtocolHandle = NULL;
	}

	FreeDevice(ListAdaptersDevice);
	FreeAdapterList(AdapterList);
}


