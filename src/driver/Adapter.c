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
#include "Adapter.h"
#include "Client.h"
#include "Device.h"
#include "Events.h"
#include "Packet.h"
#include "KernelUtil.h"

//////////////////////////////////////////////////////////////////////
// Adapter variables
//////////////////////////////////////////////////////////////////////

PLIST AdapterList = NULL;
UINT SelectedMediumIndex = 0;

//////////////////////////////////////////////////////////////////////
// Adapter methods
//////////////////////////////////////////////////////////////////////

/**
 * Generate OID Request for Adapter
 * Read these articles:
 * https://msdn.microsoft.com/ru-ru/windows/hardware/drivers/network/generating-oid-requests-from-an-ndis-filter-driver
 * https://msdn.microsoft.com/ru-ru/windows/hardware/drivers/network/miniport-adapter-oid-requests
*/
BOOL SendOidRequest(PADAPTER adapter, BOOL set, NDIS_OID oid, void *data, UINT size)
{
	DEBUGP(DL_TRACE, "===>SendOidRequest set=%d oid=%u...\n", set, oid);
	if (!adapter || !data || size <= 0)
	{
		return FALSE;
	}

	NDIS_OID_REQUEST* request = (NDIS_OID_REQUEST*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(NDIS_OID_REQUEST));
	if(!request)
	{
		return FALSE;
	}
	NdisZeroMemory(request, sizeof(NDIS_OID_REQUEST));

	request->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	request->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	request->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;

	if(set)
	{
		request->RequestType = NdisRequestSetInformation;
		request->DATA.SET_INFORMATION.Oid = oid;
		request->DATA.SET_INFORMATION.InformationBuffer = FILTER_ALLOC_MEM(FilterDriverObject, size);
		memcpy(request->DATA.SET_INFORMATION.InformationBuffer, data, size);
		request->DATA.SET_INFORMATION.InformationBufferLength = size;
	} else
	{
		request->RequestType = NdisRequestQueryInformation;
		request->DATA.QUERY_INFORMATION.Oid = oid;
		request->DATA.QUERY_INFORMATION.InformationBuffer = data;
		request->DATA.QUERY_INFORMATION.InformationBufferLength = size;
	}

	NdisAcquireSpinLock(adapter->Lock);
	if(adapter->AdapterHandle!=NULL)
	{
		InterlockedIncrement((volatile long*)&adapter->PendingOidRequests);
	}
	NdisReleaseSpinLock(adapter->Lock);

	NDIS_STATUS ret = NdisOidRequest(adapter->AdapterHandle, request);
	if(ret!=NDIS_STATUS_PENDING)
	{
		InterlockedDecrement((volatile long*)&adapter->PendingOidRequests);

		if (set && request->DATA.SET_INFORMATION.InformationBuffer)
		{
			FILTER_FREE_MEM(request->DATA.SET_INFORMATION.InformationBuffer);
		}
		FILTER_FREE_MEM(request);
	}

	DEBUGP(DL_TRACE, "<===SendOidRequest ret=0x%8x\n", ret);
	return (ret == NDIS_STATUS_PENDING || ret == NDIS_STATUS_SUCCESS);	
}

BOOL FreeAdapter(ADAPTER* adapter)
{
	DEBUGP(DL_TRACE, "===>FreeAdapter...\n");
	if (!adapter)
	{
		return FALSE;
	}

	FreeString(adapter->Name);
	FreeSpinLock(adapter->Lock);

	FILTER_FREE_MEM(adapter);

	DEBUGP(DL_TRACE, "<===FreeAdapter\n");
	return TRUE;
}

BOOL FreeAdapterList(PLIST list)
{
	DEBUGP(DL_TRACE, "===>FreeAdapterList...\n");
	NdisAcquireSpinLock(list->Lock);
	PLIST_ITEM item = list->First;
	while (item)
	{
		ADAPTER* adapter = (ADAPTER*)item->Data;
		if (adapter)
		{
			FreeAdapter(adapter);
		}
		item->Data = NULL;

		item = item->Next;
	}

	NdisReleaseSpinLock(list->Lock);

	//TODO: possible memory leak if something is added to the list before it's released
	FreeList(list);
	DEBUGP(DL_TRACE, "<===FreeAdapterList\n");
	return TRUE;
}

// Returns timestamp in milliseconds since adapter started
LARGE_INTEGER GetAdapterTime(ADAPTER* adapter)
{
	LARGE_INTEGER Result = { 0 };

	if (!adapter)
	{
		return Result;
	}

	LARGE_INTEGER Freq;
	LARGE_INTEGER Ticks = KeQueryPerformanceCounter(&Freq);
	
	Result.QuadPart = Ticks.QuadPart - adapter->BindTimestamp.QuadPart;

	Result.QuadPart *= 1000;
	Result.QuadPart /= Freq.QuadPart;

	return Result;
}

//////////////////////////////////////////////////////////////////////
// Adapter callbacks
//////////////////////////////////////////////////////////////////////

NDIS_STATUS Protocol_BindAdapterHandlerEx(NDIS_HANDLE ProtocolDriverContext, NDIS_HANDLE BindContext, PNDIS_BIND_PARAMETERS BindParameters)
{
	DEBUGP(DL_TRACE, "===>Protocol_BindAdapterHandlerEx...\n");
	_CRT_UNUSED(ProtocolDriverContext);

	NDIS_STATUS ret = NDIS_STATUS_FAILURE;	

	// Check the attributes of the adapter, and process only adapter which should be bound to
	if (BindParameters->MediaType == NdisMedium802_3 &&
		BindParameters->MacAddressLength == 6 &&
		BindParameters->AccessType == NET_IF_ACCESS_BROADCAST &&
		BindParameters->DirectionType == NET_IF_DIRECTION_SENDRECEIVE &&
		BindParameters->ConnectionType == NET_IF_CONNECTION_DEDICATED)
	{

		NDIS_OPEN_PARAMETERS parameters;
		memset(&parameters, 0, sizeof(NDIS_OPEN_PARAMETERS));

		NDIS_MEDIUM medium_array = { NdisMedium802_3 };

		parameters.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
		parameters.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
		parameters.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVSION_1;

		parameters.AdapterName = BindParameters->AdapterName;
		parameters.MediumArray = &medium_array;
		parameters.MediumArraySize = 1;
		parameters.SelectedMediumIndex = &SelectedMediumIndex;
		parameters.FrameTypeArray = NULL;
		parameters.FrameTypeArraySize = 0;

		ADAPTER* adapter = (ADAPTER*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(ADAPTER));
		NdisZeroMemory(adapter, sizeof(ADAPTER));

		adapter->Lock = CreateSpinLock();
		adapter->Name = CopyString(BindParameters->AdapterName);
		adapter->Ready = FALSE;
		memset(adapter->AdapterId, 0, 1024);

		ANSI_STRING adapterIdStr;
		RtlUnicodeStringToAnsiString(&adapterIdStr, adapter->Name, TRUE);
		if (adapter->Name->Length > 8) {
			RtlCopyBytes(adapter->AdapterId, adapterIdStr.Buffer + 8, adapterIdStr.Length > 1030 ? 1023 : adapterIdStr.Length - 8);
		}

		RtlCopyBytes(adapter->MacAddress, BindParameters->CurrentMacAddress, 6);

		adapter->BindTimestamp = KeQueryPerformanceCounter(NULL);
		adapter->BindContext = BindContext;
		adapter->MtuSize = BindParameters->MtuSize;

		ret = NdisOpenAdapterEx(FilterProtocolHandle, adapter, &parameters, BindContext, &adapter->AdapterHandle);

		if (ret != NDIS_STATUS_PENDING)
		{
			adapter->BindContext = NULL;
			Protocol_OpenAdapterCompleteHandlerEx(adapter, ret);
		}
	}

	DEBUGP(DL_TRACE, "<===Protocol_BindAdapterHandlerEx, ret=0x%8x\n", ret);
	return ret;
}

NDIS_STATUS Protocol_UnbindAdapterHandlerEx(NDIS_HANDLE UnbindContext, NDIS_HANDLE ProtocolBindingContext)
{
	DEBUGP(DL_TRACE, "===>Protocol_UnbindAdapterHandlerEx...\n");
	ADAPTER* adapter = (ADAPTER*)ProtocolBindingContext;

	NDIS_HANDLE handle = adapter->AdapterHandle;
	adapter->AdapterHandle = NULL;
	adapter->UnbindContext = UnbindContext;

	RemoveFromListByData(AdapterList, adapter);

	while (adapter->PendingOidRequests>0 || adapter->PendingSendPackets>0)
	{
		DriverSleep(50);
	}

	NDIS_STATUS ret = NdisCloseAdapterEx(handle);
	if (ret != NDIS_STATUS_PENDING)
	{
		adapter->UnbindContext = NULL;
		Protocol_CloseAdapterCompleteHandlerEx(adapter);
	}

	DEBUGP(DL_TRACE, "<===Protocol_UnbindAdapterHandlerEx, ret=0x%8x\n", ret);

	return ret;
}

void Protocol_OpenAdapterCompleteHandlerEx(NDIS_HANDLE ProtocolBindingContext, NDIS_STATUS Status)
{
	DEBUGP(DL_TRACE, "===>Protocol_OpenAdapterCompleteHandlerEx status=0x%8x...\n", Status);

	ADAPTER* adapter = (ADAPTER*) ProtocolBindingContext;
	if (Status == STATUS_SUCCESS)
	{
		DEVICE* device = CreateDevice(adapter->AdapterId);

		if (device != NULL)
		{
			// Get the display name
			SendOidRequest(adapter, FALSE, OID_GEN_VENDOR_DESCRIPTION, adapter->DisplayName, sizeof(adapter->DisplayName) - 1);

			device->Adapter = adapter;
			adapter->Device = device;

			AddToList(AdapterList, adapter);
		}

		adapter->Ready = TRUE;
	}
	else
	{
		adapter->AdapterHandle = NULL;
		FreeAdapter(adapter);
		adapter = NULL;
	}

	if (adapter->BindContext!=NULL)
	{
		NdisCompleteBindAdapterEx(adapter->BindContext, Status);
	}

	DEBUGP(DL_TRACE, "<===Protocol_UnbindAdapterHandlerEx\n");
}

void Protocol_CloseAdapterCompleteHandlerEx(NDIS_HANDLE ProtocolBindingContext)
{
	DEBUGP(DL_TRACE, "===>Protocol_CloseAdapterCompleteHandlerEx...\n");
	ADAPTER* adapter = (ADAPTER*)ProtocolBindingContext;

	if (adapter->UnbindContext != NULL)
	{
		NdisCompleteUnbindAdapterEx(adapter->UnbindContext);
	}

	if(adapter->Device)
	{
		NdisAcquireSpinLock(adapter->Device->ClientList->Lock);

		PLIST_ITEM item = adapter->Device->ClientList->First;
		while(item)
		{
			PCLIENT client = (PCLIENT)item->Data;

			KeSetEvent(client->Event->Event, PASSIVE_LEVEL, FALSE);

			item = item->Next;
		}

		NdisReleaseSpinLock(adapter->Device->ClientList->Lock);

		while (adapter->Device->ClientList->Size>0) //TODO: make sure it really disconnects
		{
			DriverSleep(50);
		}

		FreeDevice(adapter->Device);
		adapter->Device = NULL;
	}

	FreeAdapter(adapter);
	DEBUGP(DL_TRACE, "<===Protocol_CloseAdapterCompleteHandlerEx\n");
}

void Protocol_OidRequestCompleteHandler(NDIS_HANDLE ProtocolBindingContext, NDIS_OID_REQUEST *OidRequest, NDIS_STATUS Status)
{
	DEBUGP(DL_TRACE, "===>Protocol_OidRequestCompleteHandler...\n");
	_CRT_UNUSED(Status);
	if(!OidRequest)
	{
		return;
	}

	ADAPTER* adapter = (ADAPTER*)ProtocolBindingContext;
	BOOL canRelease = TRUE;

	if (OidRequest->RequestType == NdisRequestQueryInformation && OidRequest->DATA.QUERY_INFORMATION.Oid == OID_GEN_VENDOR_DESCRIPTION)
	{
		canRelease = FALSE;
	}

	if (canRelease && OidRequest->DATA.SET_INFORMATION.InformationBuffer)
	{
		FILTER_FREE_MEM(OidRequest->DATA.SET_INFORMATION.InformationBuffer);
	}

	FILTER_FREE_MEM(OidRequest);
	InterlockedDecrement((volatile long*)&adapter->PendingOidRequests);
	DEBUGP(DL_TRACE, "<===Protocol_OidRequestCompleteHandler, pending=%u\n", adapter->PendingOidRequests);
}

void Protocol_ReceiveNetBufferListsHandler(
	NDIS_HANDLE             ProtocolBindingContext,
	PNET_BUFFER_LIST        NetBufferLists,
	NDIS_PORT_NUMBER        PortNumber,
	ULONG                   NumberOfNetBufferLists,
	ULONG                   ReceiveFlags)
{
	DEBUGP(DL_TRACE, "===>Protocol_ReceiveNetBufferListsHandler...\n");
	_CRT_UNUSED(PortNumber);
	ADAPTER* adapter = (ADAPTER*)ProtocolBindingContext;

	if (NetBufferLists == NULL || NumberOfNetBufferLists == 0)
	{
		return;
	}

	ULONG ReturnFlags = 0;

	if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
	{
		NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
	}

	if (adapter==NULL || adapter->AdapterHandle == NULL)
	{
		return;
	}

	if(adapter->Ready==FALSE || adapter->Device == NULL)
	{
		NdisReturnNetBufferLists(adapter->AdapterHandle, NetBufferLists, ReturnFlags);
		return;
	}

	DEBUGP(DL_TRACE, "   acquire lock for client list\n");
	NdisAcquireSpinLock(adapter->Device->ClientList->Lock); // No more clients while sending packets

	// DEBUGP(DL_TRACE, "   iterate clients and lock each\n");
	// Lock all client receiving queues
	PLIST_ITEM item = adapter->Device->ClientList->First;
	while (item)
	{
		CLIENT* client = (CLIENT*)item->Data;
		if (client && client->ReadLock) {
			NdisAcquireSpinLock(client->ReadLock);
		}
		item = item->Next;
	}

	DEBUGP(DL_TRACE, "   iterate lists\n");
	PNET_BUFFER_LIST nbl = NetBufferLists;
	while (nbl)
	{
		NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
		//TODO: Support for IEEE802.1Q

		DEBUGP(DL_TRACE, "   iterate buffers\n");
		while (nb)
		{
			UINT size = NET_BUFFER_DATA_LENGTH(nb);

			DEBUGP(DL_TRACE, "     buffer size %u\n", size);
			if(size>0 && size<MAX_PACKET_SIZE) //TODO: it seems we lose packets here
			{				
				UCHAR *ptr = NdisGetDataBuffer(nb, size, adapter->TmpBuf, 1, 0);

				if (ptr != NULL)
				{
					LARGE_INTEGER timestamp = GetAdapterTime(adapter);

					item = adapter->Device->ClientList->First;
					while (item)
					{
						CLIENT* client = (CLIENT*)item->Data;

						DEBUGP(DL_TRACE, "   adding packet to client, size=%u\n", client->PacketList->Size);
						if (client->PacketList->Size<MAX_PACKET_QUEUE_SIZE) //TODO: it seems we lose packets here
						{
							AddToList(client->PacketList, CreatePacket(ptr, size, timestamp));
						}

						item = item->Next;
					}
				}
			}

			nb = NET_BUFFER_NEXT_NB(nb);
		}

		nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
	}

	
	DEBUGP(DL_TRACE, "   releasing lock for clients and set event\n");
	// Unlock client receiving queues and set event
	item = adapter->Device->ClientList->First;
	while (item)
	{
		CLIENT* client = (CLIENT*)item->Data;
		if(client && client->ReadLock)
			NdisReleaseSpinLock(client->ReadLock);

		if(client && client->Event && client->Event->Event)
			KeSetEvent(client->Event->Event, PASSIVE_LEVEL, FALSE);

		item = item->Next;
	}

	DEBUGP(DL_TRACE, "   release lock for client list\n");
	NdisReleaseSpinLock(adapter->Device->ClientList->Lock);

	if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
	{
		NdisReturnNetBufferLists(adapter->AdapterHandle, NetBufferLists, ReturnFlags);
	}

	DEBUGP(DL_TRACE, "<===Protocol_ReceiveNetBufferListsHandler\n");
}

void Protocol_SendNetBufferListsCompleteHandler(NDIS_HANDLE ProtocolBindingContext, PNET_BUFFER_LIST NetBufferList, ULONG SendCompleteFlags)
{
	DEBUGP(DL_TRACE, "===>Protocol_SendNetBufferListsCompleteHandler...\n");
	_CRT_UNUSED(ProtocolBindingContext);
	_CRT_UNUSED(SendCompleteFlags);

	NET_BUFFER_LIST* first = NetBufferList;

	while (first)
	{
		NET_BUFFER_LIST *current_nbl = first;

		CLIENT* client;
		NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(first);

		if (NET_BUFFER_LIST_INFO(first, Ieee8021QNetBufferListInfo) != 0)
		{
			DEBUGP(DL_TRACE, "!!! 802.11Q !!!\n");
		}

		if (nb != NULL)
		{
			UINT size = NET_BUFFER_DATA_LENGTH(nb);

			NdisAdvanceNetBufferDataStart(nb, size, FALSE, NULL);
		}

		client = ((void **)NET_BUFFER_LIST_CONTEXT_DATA_START(first))[0];

		first = NET_BUFFER_LIST_NEXT_NBL(first);
		NET_BUFFER_LIST_NEXT_NBL(current_nbl) = NULL;

		NdisFreeNetBufferList(current_nbl);

		InterlockedDecrement((volatile long*)&client->PendingSendPackets);
		InterlockedDecrement((volatile long*)&client->Device->Adapter->PendingSendPackets);
	}
	DEBUGP(DL_TRACE, "<===Protocol_SendNetBufferListsCompleteHandler\n");
}


NDIS_STATUS Protocol_SetOptionsHandler(NDIS_HANDLE NdisDriverHandle, NDIS_HANDLE DriverContext)
{
	_CRT_UNUSED(NdisDriverHandle);
	_CRT_UNUSED(DriverContext);
	DEBUGP(DL_TRACE, "===>Protocol_SetOptionsHandler...\n");
	DEBUGP(DL_TRACE, "<===Protocol_SetOptionsHandler\n");
	return NDIS_STATUS_SUCCESS; //TODO: ?
}

NDIS_STATUS Protocol_NetPnPEventHandler(NDIS_HANDLE ProtocolBindingContext, PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
	_CRT_UNUSED(ProtocolBindingContext);	;
	DEBUGP(DL_TRACE, "===>Protocol_NetPnPEventHandler...\n");

	if (NetPnPEventNotification != NULL)
	{
		if (NetPnPEventNotification->NetPnPEvent.NetEvent == NetEventBindsComplete)
		{
			DEBUGP(DL_TRACE, "   finished binding adapters!\n");
		}

		if (NetPnPEventNotification->NetPnPEvent.NetEvent == NetEventSetPower)
		{
			DEBUGP(DL_TRACE, "   power up adapter\n");
		}
	}

	DEBUGP(DL_TRACE, "<===Protocol_NetPnPEventHandler\n");
	return NDIS_STATUS_SUCCESS; //TODO: ?
}

void Protocol_UninstallHandler(VOID)
{
	DEBUGP(DL_TRACE, "===>Protocol_UninstallHandler...\n");
	DEBUGP(DL_TRACE, "<===Protocol_UninstallHandler\n");
}

void Protocol_StatusHandlerEx(NDIS_HANDLE ProtocolBindingContext, PNDIS_STATUS_INDICATION StatusIndication)
{
	_CRT_UNUSED(ProtocolBindingContext);
	_CRT_UNUSED(StatusIndication);
	DEBUGP(DL_TRACE, "===>Protocol_StatusHandlerEx...\n");
	DEBUGP(DL_TRACE, "<===Protocol_StatusHandlerEx\n");
}

void Protocol_DirectOidRequestCompleteHandler(NDIS_HANDLE ProtocolBindingContext, PNDIS_OID_REQUEST OidRequest, NDIS_STATUS Status)
{
	_CRT_UNUSED(ProtocolBindingContext);
	_CRT_UNUSED(OidRequest);
	_CRT_UNUSED(Status);
	DEBUGP(DL_TRACE, "===>Protocol_DirectOidRequestCompleteHandler...\n");
	DEBUGP(DL_TRACE, "<===Protocol_DirectOidRequestCompleteHandler\n");
}