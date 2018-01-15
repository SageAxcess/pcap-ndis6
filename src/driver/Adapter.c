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
#include "KmList.h"
#include "KmMemoryManager.h"

#include "..\..\driver_version.h"
#include "..\shared\CommonDefs.h"

//////////////////////////////////////////////////////////////////////
// Adapter variables
//////////////////////////////////////////////////////////////////////

KM_LIST AdapterList = { 0, };
UINT    SelectedMediumIndex = 0;

//////////////////////////////////////////////////////////////////////
// Adapter methods
//////////////////////////////////////////////////////////////////////

NTSTATUS __stdcall Adapter_Allocate(
    __in    PKM_MEMORY_MANAGER      MemoryManager,
    __in    PNDIS_BIND_PARAMETERS   BindParameters,
    __in    NDIS_HANDLE             BindContext,
    __out   PADAPTER                *Adapter)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PADAPTER    NewAdapter = NULL;
    DWORD       SizeRequired = sizeof(ADAPTER);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BindParameters),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Adapter),
        STATUS_INVALID_PARAMETER_4);

    SizeRequired +=
        Assigned(BindParameters->AdapterName) ?
        BindParameters->AdapterName->Length + sizeof(wchar_t) :
        sizeof(wchar_t);

    NewAdapter = Km_MM_AllocMemTypedWithSize(
        MemoryManager,
        ADAPTER,
        SizeRequired);
    RETURN_VALUE_IF_FALSE(
        Assigned(NewAdapter),
        NDIS_STATUS_FAILURE);

    RtlZeroMemory(NewAdapter, sizeof(ADAPTER));

    NewAdapter->Name.Buffer =
        (PWCH)((PUCHAR)NewAdapter + sizeof(ADAPTER));
    NewAdapter->Name.Length = BindParameters->AdapterName->Length;
    NewAdapter->Name.MaximumLength = NewAdapter->Name.Length;

    if (BindParameters->AdapterName->Length > 0)
    {
        RtlCopyMemory(
            NewAdapter->Name.Buffer,
            BindParameters->AdapterName->Buffer,
            BindParameters->AdapterName->Length);
    }
    
    if (BindParameters->MacAddressLength > 0)
    {
        NewAdapter->MacAddressSize = BindParameters->MacAddressLength;
        RtlCopyMemory(
            NewAdapter->MacAddress,
            BindParameters->CurrentMacAddress,
            BindParameters->MacAddressLength);
    }

    NewAdapter->MtuSize = BindParameters->MtuSize;
    NewAdapter->BindTimestamp = KeQueryPerformanceCounter(NULL);
    NewAdapter->BindContext = BindContext;

cleanup:

    if (NT_SUCCESS(Status))
    {
        *Adapter = NewAdapter;
    }

    return Status;
};

/**
 * Generate OID Request for Adapter
 * Read these articles:
 * https://msdn.microsoft.com/ru-ru/windows/hardware/drivers/network/generating-oid-requests-from-an-ndis-filter-driver
 * https://msdn.microsoft.com/ru-ru/windows/hardware/drivers/network/miniport-adapter-oid-requests
*/
BOOL SendOidRequest(
    __in    PADAPTER    adapter,
    __in    BOOL        set,
    __in    NDIS_OID    oid,
    __in    void        *data,
    __in    UINT        size)
{
    NDIS_OID_REQUEST    *request = NULL;

    RETURN_VALUE_IF_FALSE(
        (Assigned(adapter)) &&
        (Assigned(data)) &&
        (size > 0),
        FALSE);

    RETURN_VALUE_IF_FALSE(
        Assigned(adapter->DriverData),
        FALSE);
    request = Km_MM_AllocMemTyped(
        &adapter->DriverData->Ndis.MemoryManager,
        NDIS_OID_REQUEST);

    RETURN_VALUE_IF_FALSE(
        Assigned(request),
        FALSE);
	
    NdisZeroMemory(request, sizeof(NDIS_OID_REQUEST));

	request->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	request->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	request->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;

	if(set)
	{
		request->RequestType = NdisRequestSetInformation;
		request->DATA.SET_INFORMATION.Oid = oid;
        request->DATA.SET_INFORMATION.InformationBuffer = Km_MM_AllocMem(
            &adapter->DriverData->Ndis.MemoryManager,
            size);

		if(!request->DATA.SET_INFORMATION.InformationBuffer)
		{
            Km_MM_FreeMem(
                &adapter->DriverData->Ndis.MemoryManager,
                request);
			return FALSE;
		}

        RtlCopyMemory(
            request->DATA.SET_INFORMATION.InformationBuffer,
            data,
            size);

		request->DATA.SET_INFORMATION.InformationBufferLength = size;

	} else
	{
		request->RequestType = NdisRequestQueryInformation;
		request->DATA.QUERY_INFORMATION.Oid = oid;
		request->DATA.QUERY_INFORMATION.InformationBuffer = data;
		request->DATA.QUERY_INFORMATION.InformationBufferLength = size;
	}

    RETURN_VALUE_IF_FALSE(
        adapter->AdapterHandle != NULL,
        FALSE);

	InterlockedIncrement((volatile LONG *)&adapter->PendingOidRequests);

	NDIS_STATUS ret = NdisOidRequest(adapter->AdapterHandle, request);
	if(ret != NDIS_STATUS_PENDING)
	{
		InterlockedDecrement((volatile LONG *)&adapter->PendingOidRequests);

		if (set)
		{
            Km_MM_FreeMem(
                &adapter->DriverData->Ndis.MemoryManager,
                request->DATA.SET_INFORMATION.InformationBuffer);
		}

        Km_MM_FreeMem(
            &adapter->DriverData->Ndis.MemoryManager,
            request);
	}

	return 
        (ret == NDIS_STATUS_PENDING) || 
        (ret == NDIS_STATUS_SUCCESS);	
}

BOOL FreeAdapter(
    __in    PADAPTER    Adapter)
{
    PKM_MEMORY_MANAGER  MemoryManager = NULL;

    RETURN_VALUE_IF_FALSE(
        Assigned(Adapter),
        FALSE);
    RETURN_VALUE_IF_FALSE(
        Assigned(Adapter->DriverData),
        FALSE);

    MemoryManager = &Adapter->DriverData->Ndis.MemoryManager;

    if (Assigned(Adapter->Device))
	{
		Adapter->Device->Releasing = TRUE;

		FreeDevice(Adapter->Device);

		Adapter->Device = NULL;
	}

    Km_MM_FreeMem(
        MemoryManager,
        Adapter);

	return TRUE;
};

void _stdcall ClearAdaptersList_ItemCallback(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item)
{
    PADAPTER    Adapter;

    UNREFERENCED_PARAMETER(List);

    RETURN_IF_FALSE(Assigned(Item));

    Adapter = CONTAINING_RECORD(Item, ADAPTER, Link);

    FreeAdapter(Adapter);
};

NTSTATUS ClearAdaptersList(
    __in    PKM_LIST    List)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(List),
        STATUS_INVALID_PARAMETER_1);

    Km_List_Clear(List, ClearAdaptersList_ItemCallback);

cleanup:
    return Status;
};

// Returns timestamp in milliseconds since adapter started
LARGE_INTEGER GetAdapterTime(
    __in    PADAPTER    Adapter)
{
	LARGE_INTEGER Result = { 0 };
    LARGE_INTEGER Freq;
    LARGE_INTEGER Ticks = KeQueryPerformanceCounter(&Freq);

    RETURN_VALUE_IF_FALSE(
        Assigned(Adapter),
        Result);

	Result.QuadPart = Ticks.QuadPart - Adapter->BindTimestamp.QuadPart;

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
    NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
    NTSTATUS                Status2 = STATUS_SUCCESS;
    NDIS_MEDIUM             MediumArray = { NdisMedium802_3 };
    NDIS_OPEN_PARAMETERS    OpenParameters;
    PADAPTER                Adapter = NULL;
    PDRIVER_DATA            Data = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (ProtocolDriverContext != NULL) &&
        (Assigned(BindParameters)),
        NDIS_STATUS_FAILURE);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (BindParameters->MediaType == NdisMedium802_3) &&
        (BindParameters->MacAddressLength == 6) &&
        (BindParameters->AccessType == NET_IF_ACCESS_BROADCAST) &&
        (BindParameters->DirectionType == NET_IF_DIRECTION_SENDRECEIVE) &&
        (BindParameters->ConnectionType == NET_IF_CONNECTION_DEDICATED),
        NDIS_STATUS_NOT_SUPPORTED);

    Data = (PDRIVER_DATA)ProtocolDriverContext;

    Status2 = Adapter_Allocate(
        &Data->Ndis.MemoryManager,
        BindParameters,
        BindContext,
        &Adapter);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NT_SUCCESS(Status2),
        NDIS_STATUS_RESOURCES);

    RtlZeroMemory(&OpenParameters, sizeof(OpenParameters));

    OpenParameters.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
    OpenParameters.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
    OpenParameters.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVSION_1;

    OpenParameters.AdapterName = BindParameters->AdapterName;
    OpenParameters.MediumArray = &MediumArray;
    OpenParameters.MediumArraySize = 1;
    OpenParameters.SelectedMediumIndex = &SelectedMediumIndex;

    Status = NdisOpenAdapterEx(
        Data->Ndis.ProtocolHandle,
        (NDIS_HANDLE)Adapter,
        &OpenParameters,
        BindContext,
        &Adapter->AdapterHandle);

    GOTO_CLEANUP_IF_TRUE(Status == NDIS_STATUS_PENDING);

    Adapter->BindContext = NULL;
    Protocol_OpenAdapterCompleteHandlerEx(
        (NDIS_HANDLE)Adapter,
        Status);

cleanup:
    return Status;
};

NDIS_STATUS
_Function_class_(PROTOCOL_UNBIND_ADAPTER_EX)
Protocol_UnbindAdapterHandlerEx(
    __in    NDIS_HANDLE UnbindContext,
    __in    NDIS_HANDLE ProtocolBindingContext)
{
    PADAPTER    Adapter = (PADAPTER)ProtocolBindingContext;
    NDIS_HANDLE AdapterHandle = Adapter->AdapterHandle;

    Adapter->AdapterHandle = NULL;
    Adapter->UnbindContext = UnbindContext;

    Km_List_RemoveItem(&AdapterList, &Adapter->Link);

    while ((Adapter->PendingOidRequests > 0) ||
            (Adapter->PendingSendPackets > 0))
	{
		DriverSleep(50);
	}

    NDIS_STATUS NdisStatus = NdisCloseAdapterEx(AdapterHandle);
    if (NdisStatus != NDIS_STATUS_PENDING)
	{
        Adapter->UnbindContext = NULL;
        Protocol_CloseAdapterCompleteHandlerEx((NDIS_HANDLE)Adapter);
	}

	return NdisStatus;
}

void
_Function_class_(PROTOCOL_OPEN_ADAPTER_COMPLETE_EX)
Protocol_OpenAdapterCompleteHandlerEx(
    __in    NDIS_HANDLE ProtocolBindingContext,
    __in    NDIS_STATUS Status)
{
    PADAPTER    Adapter = (PADAPTER)ProtocolBindingContext;

    if (Status == NDIS_STATUS_SUCCESS)
    {
        PDEVICE Device = CreateDevice(
            Adapter->DriverData->Other.DriverObject,
            Adapter->DriverData,
            &Adapter->Name);
        if (Assigned(Device))
        {
            SendOidRequest(
                Adapter,
                FALSE,
                OID_GEN_VENDOR_DESCRIPTION,
                Adapter->DisplayName,
                sizeof(Adapter->DisplayName) - 1);

            Device->Adapter = Adapter;
            Adapter->Device = Device;

            Km_List_AddItem(
                &AdapterList,
                &Adapter->Link);
        }

        Adapter->Ready = TRUE;
    }
    else
    {
        Adapter->AdapterHandle = NULL;
        FreeAdapter(Adapter);
        Adapter = NULL;
    }

    if (Assigned(Adapter))
    {
        if (Adapter->BindContext != NULL)
        {
            NdisCompleteBindAdapterEx(Adapter->BindContext, Status);
        }
    }
};

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
    /*
        A handle to a protocol driver-allocated context area in which the protocol driver 
        maintains per-binding run-time state. 
        The driver supplied this handle when it called the NdisOpenAdapterEx function.
    */
    PADAPTER    Adapter = (PADAPTER)ProtocolBindingContext;
    BOOL        CanRelease = FALSE;

    UNREFERENCED_PARAMETER(Status);

    RETURN_IF_FALSE(
        Assigned(Adapter->DriverData));
    RETURN_IF_FALSE(Assigned(OidRequest));

	if ((OidRequest->RequestType == NdisRequestQueryInformation) && 
        (OidRequest->DATA.QUERY_INFORMATION.Oid == OID_GEN_VENDOR_DESCRIPTION))
	{
        CanRelease = FALSE;
	}

    if ((CanRelease) &&
        (Assigned(OidRequest->DATA.SET_INFORMATION.InformationBuffer)))
	{
        Km_MM_FreeMem(
            &Adapter->DriverData->Ndis.MemoryManager,
            OidRequest->DATA.SET_INFORMATION.InformationBuffer);
	}

    Km_MM_FreeMem(
        &Adapter->DriverData->Ndis.MemoryManager,
        OidRequest);

    InterlockedDecrement((volatile LONG *)&Adapter->PendingOidRequests);
};

void LockClients(
    __in    PDEVICE Device,
    __in    BOOLEAN LockList)
{
    PLIST_ENTRY ListEntry = NULL;

    RETURN_IF_FALSE(Assigned(Device));

    if (LockList)
    {
        Km_List_Lock(&Device->ClientList);
    }

    for (ListEntry = Device->ClientList.Head.Flink;
         ListEntry != &Device->ClientList.Head;
         ListEntry = ListEntry->Flink)
    {
        PCLIENT Client = CONTAINING_RECORD(ListEntry, CLIENT, Link);

        Km_Lock_Acquire(&Client->ReadLock);
    }
};

void UnlockClients(
    __in    PDEVICE Device,
    __in    BOOLEAN UnlockList,
    __in    BOOLEAN SignalEvents)
{
    PLIST_ENTRY ListEntry = NULL;

    RETURN_IF_FALSE(Assigned(Device));

    for (ListEntry = Device->ClientList.Head.Flink;
        ListEntry != &Device->ClientList.Head;
        ListEntry = ListEntry->Flink)
    {
        PCLIENT  Client = CONTAINING_RECORD(ListEntry, CLIENT, Link);

        if (SignalEvents)
        {
            if (Assigned(Client->Event.Event))
            {
                KeSetEvent(Client->Event.Event, 0, FALSE);
            }
        }

        if (Assigned(Client))
        {
            Km_Lock_Release(&Client->ReadLock);
        }
    }

    if (UnlockList)
    {
        Km_List_Unlock(&Device->ClientList);
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
                PLIST_ENTRY ListEntry = NULL;

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

                for (ListEntry = adapter->Device->ClientList.Head.Flink;
                     ListEntry != &adapter->Device->ClientList.Head;
                     ListEntry = ListEntry->Flink)
                {
                    PCLIENT Client = CONTAINING_RECORD(ListEntry, CLIENT, Link);
                    PPACKET NewPacket = CreatePacket(
                        &adapter->DriverData->Ndis.MemoryManager,
                        MdlVA + Offset, 
                        BufferLength, 
                        &PacketTimeStamp);

                    if ((Client->PacketList.Count.QuadPart < MAX_PACKET_QUEUE_SIZE) &&
                        (!Client->Releasing)) //TODO: it seems we lose packets here
                    {
                        NTSTATUS    InsertStatus = Km_List_AddItemEx(
                            &Client->PacketList,
                            &NewPacket->Link,
                            FALSE,
                            FALSE);

                        if (NT_SUCCESS(InsertStatus))
                        {
                            FreePacket(NewPacket);
                        }
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