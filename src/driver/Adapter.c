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

#include "..\..\driver_version.h"
#include "..\shared\CommonDefs.h"

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
		if(!request->DATA.SET_INFORMATION.InformationBuffer)
		{
			FILTER_FREE_MEM(request);
			return FALSE;
		}
		memcpy(request->DATA.SET_INFORMATION.InformationBuffer, data, size);
		request->DATA.SET_INFORMATION.InformationBufferLength = size;
	} else
	{
		request->RequestType = NdisRequestQueryInformation;
		request->DATA.QUERY_INFORMATION.Oid = oid;
		request->DATA.QUERY_INFORMATION.InformationBuffer = data;
		request->DATA.QUERY_INFORMATION.InformationBufferLength = size;
	}

	if (adapter->AdapterHandle == NULL)
	{
		return FALSE;
	}

	InterlockedIncrement((volatile long*)&adapter->PendingOidRequests);

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

	if (adapter->Device)
	{
		adapter->Device->Releasing = TRUE;

		int i = 0;
		while (adapter->Device->ClientList->Size > 0)
		{
			if (i == 0) {
				NdisAcquireSpinLock(adapter->Device->ClientList->Lock);
				PLIST_ITEM item = adapter->Device->ClientList->First;
				while (item)
				{
					CLIENT* client = (CLIENT*)item->Data;
					if (client && client->Event) {
						KeSetEvent(client->Event->Event, PASSIVE_LEVEL, FALSE);
					}
					item = item->Next;
				}
				NdisReleaseSpinLock(adapter->Device->ClientList->Lock);
			}

			i++;
			DriverSleep(100); //TODO: wait until adapter->Device stops

			if (i>1000)
			{
				break;
			}
		}

		FreeDevice(adapter->Device);
		adapter->Device = NULL;
	}

	FreeString(adapter->Name);

	//FreeString(adapter->Name);

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

NDIS_STATUS
_Function_class_(PROTOCOL_BIND_ADAPTER_EX)
Protocol_BindAdapterHandlerEx(
    __in    NDIS_HANDLE             ProtocolDriverContext,
    __in    NDIS_HANDLE             BindContext,
    __in    PNDIS_BIND_PARAMETERS   BindParameters)
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

		adapter->Name = CopyString(BindParameters->AdapterName);
		adapter->Ready = FALSE;
		memset(adapter->AdapterId, 0, 1024);

		ANSI_STRING adapterIdStr;
		NTSTATUS res = RtlUnicodeStringToAnsiString(&adapterIdStr, adapter->Name, TRUE);

		if(NT_SUCCESS(res) && adapter->Name->Length > 8) {
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

NDIS_STATUS
_Function_class_(PROTOCOL_UNBIND_ADAPTER_EX)
Protocol_UnbindAdapterHandlerEx(
    __in    NDIS_HANDLE UnbindContext,
    __in    NDIS_HANDLE ProtocolBindingContext)
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

void
_Function_class_(PROTOCOL_OPEN_ADAPTER_COMPLETE_EX)
Protocol_OpenAdapterCompleteHandlerEx(
    __in    NDIS_HANDLE ProtocolBindingContext,
    __in    NDIS_STATUS Status)
{
	DEBUGP(DL_TRACE, "===>Protocol_OpenAdapterCompleteHandlerEx status=0x%8x...\n", Status);

	ADAPTER* adapter = (ADAPTER*) ProtocolBindingContext;
	if (Status == STATUS_SUCCESS && !AdapterList->Releasing)
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

	if (adapter!=NULL && adapter->BindContext!=NULL)
	{
		NdisCompleteBindAdapterEx(adapter->BindContext, Status);
	}

	DEBUGP(DL_TRACE, "<===Protocol_OpenAdapterCompleteHandlerEx\n");
}

void
_Function_class_(PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX)
Protocol_CloseAdapterCompleteHandlerEx(
    __in    NDIS_HANDLE ProtocolBindingContext)
{
	DEBUGP(DL_TRACE, "===>Protocol_CloseAdapterCompleteHandlerEx...\n");
	ADAPTER* adapter = (ADAPTER*)ProtocolBindingContext;

	if (adapter->UnbindContext != NULL)
	{
		NdisCompleteUnbindAdapterEx(adapter->UnbindContext);
	}

	FreeAdapter(adapter);
	DEBUGP(DL_TRACE, "<===Protocol_CloseAdapterCompleteHandlerEx\n");
}

void
_Function_class_(PROTOCOL_OID_REQUEST_COMPLETE)
Protocol_OidRequestCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    NDIS_OID_REQUEST    *OidRequest,
    __in    NDIS_STATUS         Status)
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

void LockClients(
    __in    PDEVICE Device,
    __in    BOOLEAN LockList)
{
    PLIST_ITEM  Item;

    RETURN_IF_FALSE(Assigned(Device));

    if (LockList)
    {
        NdisAcquireSpinLock(Device->ClientList->Lock);
    }

    for (Item = Device->ClientList->First;
        Assigned(Item);
        Item = Item->Next)
    {
        CLIENT* Client = (CLIENT*)Item->Data;
        if ((Assigned(Client)) &&
            (Assigned(Client->ReadLock)))
        {
            NdisAcquireSpinLock(Client->ReadLock);
        }
    }
};

void UnlockClients(
    __in    PDEVICE Device,
    __in    BOOLEAN UnlockList,
    __in    BOOLEAN SignalEvents)
{
    PLIST_ITEM  Item;

    RETURN_IF_FALSE(Assigned(Device));

    for (Item = Device->ClientList->First;
        Assigned(Item);
        Item = Item->Next)
    {
        CLIENT* Client = (CLIENT*)Item->Data;
        if ((Assigned(Client)) &&
            (Assigned(Client->ReadLock)))
        {
            NdisReleaseSpinLock(Client->ReadLock);
        }

        if (SignalEvents)
        {
            if ((Assigned(Client->Event)) &&
                (Assigned(Client->Event->Event)))
            {
                KeSetEvent(Client->Event->Event, 0, FALSE);
            }
        }
    }

    if (UnlockList)
    {
        NdisReleaseSpinLock(Device->ClientList->Lock);
    }
};

void
_Function_class_(PROTOCOL_RECEIVE_NET_BUFFER_LISTS)
Protocol_ReceiveNetBufferListsHandler(
	NDIS_HANDLE             ProtocolBindingContext,
	PNET_BUFFER_LIST        NetBufferLists,
	NDIS_PORT_NUMBER        PortNumber,
	ULONG                   NumberOfNetBufferLists,
	ULONG                   ReceiveFlags)
{
	ADAPTER *adapter = (ADAPTER*)ProtocolBindingContext;
    ULONG   ReturnFlags = 0;

    _CRT_UNUSED(PortNumber);

    RETURN_IF_FALSE(
        (Assigned(NetBufferLists)) &&
        (NumberOfNetBufferLists > 0));

	if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
	{
		NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
	}

    RETURN_IF_FALSE(
        (Assigned(adapter)) &&
        (adapter->AdapterHandle != NULL));

    RETURN_IF_FALSE_EX(
        (adapter->Ready) &&
        (Assigned(adapter->Device)),
        NdisReturnNetBufferLists(
            adapter->AdapterHandle, 
            NetBufferLists, 
            ReturnFlags));

    LockClients(adapter->Device, TRUE);
    __try
    {
        PNET_BUFFER_LIST    CurrentNbl;
        LARGE_INTEGER       PacketTimeStamp = GetAdapterTime(adapter);

        for (CurrentNbl = NetBufferLists;
             Assigned(CurrentNbl);
             CurrentNbl = NET_BUFFER_LIST_NEXT_NBL(CurrentNbl))
        {
            PUCHAR      MdlVA = NULL;
            PNET_BUFFER NB = NET_BUFFER_LIST_FIRST_NB(CurrentNbl);
            PMDL        Mdl = NET_BUFFER_CURRENT_MDL(NB);
            ULONG       Offset = NET_BUFFER_DATA_OFFSET(NB);
            ULONG       BufferLength = 0;

            if (Assigned(Mdl))
            {
                PLIST_ITEM  Item;

                NdisQueryMdl(
                    Mdl, 
                    &MdlVA, 
                    &BufferLength, 
                    NormalPagePriority);

                BREAK_IF_FALSE(
                    (Assigned(MdlVA)) &&
                    (BufferLength > 0));

                BREAK_IF_FALSE(BufferLength > Offset);

                BufferLength -= Offset;

                BREAK_IF_FALSE(BufferLength >= sizeof(ETH_HEADER));

                for (Item = adapter->Device->ClientList->First;
                    Assigned(Item);
                    Item = Item->Next)
                {
                    PCLIENT Client = (PCLIENT)Item->Data;

                    if ((Client->PacketList->Size < MAX_PACKET_QUEUE_SIZE) &&
                        (!Client->PacketList->Releasing)) //TODO: it seems we lose packets here
                    {
                        AddToList(
                            Client->PacketList, 
                            CreatePacket(MdlVA + Offset, BufferLength, PacketTimeStamp));
                    }

                }
            }
        }
    }
    __finally
    {
        UnlockClients(adapter->Device, TRUE, TRUE);
    }
	
	if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
	{
		NdisReturnNetBufferLists(adapter->AdapterHandle, NetBufferLists, ReturnFlags);
	}
};

void
_Function_class_(PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE)
Protocol_SendNetBufferListsCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    PNET_BUFFER_LIST    NetBufferList,
    __in    ULONG               SendCompleteFlags)
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


NDIS_STATUS
_Function_class_(SET_OPTIONS)
Protocol_SetOptionsHandler(
    __in    NDIS_HANDLE NdisDriverHandle,
    __in    NDIS_HANDLE DriverContext)
{
	_CRT_UNUSED(NdisDriverHandle);
	_CRT_UNUSED(DriverContext);
	DEBUGP(DL_TRACE, "===>Protocol_SetOptionsHandler...\n");
	DEBUGP(DL_TRACE, "<===Protocol_SetOptionsHandler\n");
	return NDIS_STATUS_SUCCESS; //TODO: ?
}

NDIS_STATUS
_Function_class_(PROTOCOL_NET_PNP_EVENT)
Protocol_NetPnPEventHandler(
    __in    NDIS_HANDLE                 ProtocolBindingContext,
    __in    PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
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

void
_Function_class_(PROTOCOL_UNINSTALL)
Protocol_UninstallHandler()
{
	DEBUGP(DL_TRACE, "===>Protocol_UninstallHandler...\n");
	DEBUGP(DL_TRACE, "<===Protocol_UninstallHandler\n");
}

void
_Function_class_(PROTOCOL_STATUS_EX)
Protocol_StatusHandlerEx(
    __in    NDIS_HANDLE             ProtocolBindingContext,
    __in    PNDIS_STATUS_INDICATION StatusIndication)
{
	_CRT_UNUSED(ProtocolBindingContext);
	_CRT_UNUSED(StatusIndication);
	DEBUGP(DL_TRACE, "===>Protocol_StatusHandlerEx... " DRIVER_VER_STRING "\n");
	DEBUGP(DL_TRACE, "<===Protocol_StatusHandlerEx\n");
}

void
_Function_class_(PROTOCOL_DIRECT_OID_REQUEST_COMPLETE)
Protocol_DirectOidRequestCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    PNDIS_OID_REQUEST   OidRequest,
    __in    NDIS_STATUS         Status)
{
	_CRT_UNUSED(ProtocolBindingContext);
	_CRT_UNUSED(OidRequest);
	_CRT_UNUSED(Status);
	DEBUGP(DL_TRACE, "===>Protocol_DirectOidRequestCompleteHandler...\n");
	DEBUGP(DL_TRACE, "<===Protocol_DirectOidRequestCompleteHandler\n");
}