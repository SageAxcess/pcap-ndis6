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
	if (!adapter || !data || size <= 0)
	{
		return FALSE;
	}

	NDIS_OID_REQUEST* request = (NDIS_OID_REQUEST*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(NDIS_OID_REQUEST));
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

		if (set)
		{
			FILTER_FREE_MEM(request->DATA.SET_INFORMATION.InformationBuffer);
		}
		FILTER_FREE_MEM(request);
	}

	return (ret == NDIS_STATUS_PENDING || ret == NDIS_STATUS_SUCCESS);	
}

BOOL FreeAdapter(ADAPTER* adapter)
{
	if (!adapter)
	{
		return FALSE;
	}

	FreeString(adapter->Name);
	FreeSpinLock(adapter->Lock);

	FILTER_FREE_MEM(adapter);

	return TRUE;
}

BOOL FreeAdapterList(PLIST list)
{
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
		RtlCopyBytes(adapter->AdapterId, adapterIdStr.Buffer, adapterIdStr.Length > 1023 ? 1023 : adapterIdStr.Length);		

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

	return ret;
}

NDIS_STATUS Protocol_UnbindAdapterHandlerEx(NDIS_HANDLE UnbindContext, NDIS_HANDLE ProtocolBindingContext)
{
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

	return ret;
}

void Protocol_OpenAdapterCompleteHandlerEx(NDIS_HANDLE ProtocolBindingContext, NDIS_STATUS Status)
{
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
}

void Protocol_CloseAdapterCompleteHandlerEx(NDIS_HANDLE ProtocolBindingContext)
{
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
}

void Protocol_OidRequestCompleteHandler(NDIS_HANDLE ProtocolBindingContext, NDIS_OID_REQUEST *OidRequest, NDIS_STATUS Status)
{
	_CRT_UNUSED(Status);

	ADAPTER* adapter = (ADAPTER*)ProtocolBindingContext;
	BOOL canRelease = TRUE;

	if (OidRequest->RequestType == NdisRequestQueryInformation && OidRequest->DATA.QUERY_INFORMATION.Oid == OID_GEN_VENDOR_DESCRIPTION)
	{
		canRelease = FALSE;
	}

	if (canRelease)
	{
		FILTER_FREE_MEM(OidRequest->DATA.SET_INFORMATION.InformationBuffer);
	}

	FILTER_FREE_MEM(OidRequest);
	InterlockedDecrement((volatile long*)&adapter->PendingOidRequests);
}

void Protocol_ReceiveNetBufferListsHandler(
	NDIS_HANDLE             ProtocolBindingContext,
	PNET_BUFFER_LIST        NetBufferLists,
	NDIS_PORT_NUMBER        PortNumber,
	ULONG                   NumberOfNetBufferLists,
	ULONG                   ReceiveFlags)
{
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

	if (adapter->Device == NULL || adapter->Ready == FALSE || adapter->AdapterHandle == NULL)
	{
		NdisReturnNetBufferLists(adapter->AdapterHandle, NetBufferLists, ReturnFlags);
		return;
	}

	NdisAcquireSpinLock(adapter->Device->ClientList->Lock); // No more clients while sending packets

	// Lock all client receiving queues
	PLIST_ITEM item = adapter->Device->ClientList->First;
	while (item)
	{
		CLIENT* client = (CLIENT*)item->Data;
		NdisAcquireSpinLock(client->PacketList->Lock);
		item = item->Next;
	}

	UCHAR buf[MAX_PACKET_SIZE];

	PNET_BUFFER_LIST nbl = NetBufferLists;
	while (nbl)
	{
		NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
		//TODO: Support for IEEE802.1Q

		while (nb)
		{
			UINT size = NET_BUFFER_DATA_LENGTH(nb);

			if(size>0 && size<MAX_PACKET_SIZE) //TODO: it seems we lose packets here
			{				
				UCHAR *ptr = NdisGetDataBuffer(nb, size, &buf, 1, 0);

				if (ptr != NULL)
				{
					LARGE_INTEGER timestamp = GetAdapterTime(adapter);

					item = adapter->Device->ClientList->First;
					while (item)
					{
						CLIENT* client = (CLIENT*)item->Data;

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

	
	// Unlock client receiving queues and set event
	item = adapter->Device->ClientList->First;
	while (item)
	{
		CLIENT* client = (CLIENT*)item->Data;
		NdisAcquireSpinLock(client->PacketList->Lock);

		KeSetEvent(client->Event->Event, PASSIVE_LEVEL, FALSE);

		item = item->Next;
	}

	NdisReleaseSpinLock(adapter->Device->ClientList->Lock);

	if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
	{
		NdisReturnNetBufferLists(adapter->AdapterHandle, NetBufferLists, ReturnFlags);
	}
}

void Protocol_SendNetBufferListsCompleteHandler(NDIS_HANDLE ProtocolBindingContext, PNET_BUFFER_LIST NetBufferList, ULONG SendCompleteFlags)
{
	_CRT_UNUSED(ProtocolBindingContext);
	_CRT_UNUSED(SendCompleteFlags);

	NET_BUFFER_LIST* first = NetBufferList;

	while (first)
	{
		NET_BUFFER_LIST *current_nbl = first;

		CLIENT* client;
		NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(first);

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
}
