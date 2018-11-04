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

#include "KernelUtil.h"
#include "Adapter.h"
#include "KmTypes.h"
#include "NdisMemoryManager.h"
#include "WfpMemoryManager.h"
#include "WfpFlt.h"
#include "KmConnections.h"
#include "KmInterModeComms.h"
#include "KmMemoryPool.h"
#include "KmProcessWatcher.h"

#include "..\shared\win_bpf.h"

#include "..\shared\CommonDefs.h"

//  Forward declarations
NTSTATUS __stdcall Filter_GetAdapters(
    __in    PDRIVER_DATA    Data,
    __in    PVOID           Buffer,
    __in    DWORD           BufferSize,
    __out   PDWORD          BytesRead);

NTSTATUS __stdcall Filter_CreateClient(
    __in    PDRIVER_DATA            Data,
    __in    HANDLE                  ProcessId,
    __in    PVOID                   NewDataEventObject,
    __in    PADAPTER                Adapter,
    __out   PPCAP_NDIS_CLIENT_ID    ClientId);

NTSTATUS __stdcall Filter_DestroyClient(
    __in    PDRIVER_DATA    Data,
    __in    PDRIVER_CLIENT  Client);

NTSTATUS __stdcall Filter_OpenAdapter(
    __in    PDRIVER_DATA                            Data,
    __in    HANDLE                                  ProcessId,
    __in    PPCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA    RequestData,
    __out   PPCAP_NDIS_CLIENT_ID                    ClientId);

NTSTATUS __stdcall Filter_CloseAdapter(
    __in    PDRIVER_DATA            Data,
    __in    PPCAP_NDIS_CLIENT_ID    ClientId);

NTSTATUS __stdcall Filter_CloseClientsByPID(
    __in    PDRIVER_DATA    Data,
    __in    HANDLE          ProcessId);

NTSTATUS __stdcall Filter_ReadPackets(
    __in    PDRIVER_DATA            Data,
    __in    PPCAP_NDIS_CLIENT_ID    ClientId,
    __in    HANDLE                  ProcessId,
    __out   PVOID                   Buffer,
    __in    ULONG                   BufferSize,
    __out   PULONG                  BytesReturned);

NTSTATUS __stdcall Filter_GetDiagInfo(
    __in    PDRIVER_DATA                Data,
    __out   PDRIVER_DIAG_INFORMATION    DiagInfo);

NTSTATUS __stdcall Filter_IMC_IOCTL_Callback(
    __in    PVOID       Context,
    __in    ULONG       ControlCode,
    __in    PVOID       InBuffer,
    __in    ULONG       InBufferSize,
    __out   PVOID       OutBuffer,
    __in    ULONG       OutBufferSize,
    __out   PULONG_PTR  BytesReturned);

void __stdcall Filter_Wfp_EventCallback(
    __in    WFP_NETWORK_EVENT_TYPE  EventType,
    __in    PNETWORK_EVENT_INFO     EventInfo,
    __in    PVOID                   Context);

NTSTATUS __stdcall RegisterNdisProtocol(
    __inout PDRIVER_DATA    Data);

void __stdcall Filter_ProcessWatcher_Callback(
    __in_opt    HANDLE  ParentProcessId,
    __in        HANDLE  ProcessId,
    __in        BOOLEAN NewProcess,
    __in        PVOID   Context);

void __stdcall Filter_ReEnumBindingsThreadRoutine(
    __in    PKM_TIMER_THREAD    Thread,
    __in    PVOID               Context);

DRIVER_INITIALIZE DriverEntry;

_Use_decl_annotations_
NTSTATUS
_Function_class_(DRIVER_INITIALIZE)
DriverEntry(
    PDRIVER_OBJECT      DriverObject,
    PUNICODE_STRING     RegistryPath);

_Use_decl_annotations_
void
_Function_class_(DRIVER_UNLOAD)
DriverUnload(DRIVER_OBJECT *DriverObject);

// This directive puts the DriverEntry function into the INIT segment of the
// driver.  To conserve memory, the code will be discarded when the driver's
// DriverEntry function returns.  You can declare other functions used only
// during initialization here.
#pragma NDIS_INIT_FUNCTION(DriverEntry)

//
// Global variables
//

DRIVER_DATA DriverData;

//
//  Implementations
//

NTSTATUS __stdcall Filter_GetAdapters(
    __in    PDRIVER_DATA    Data,
    __in    PVOID           Buffer,
    __in    DWORD           BufferSize,
    __out   PDWORD          BytesRead)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    DWORD       BytesCopied = 0;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Buffer),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        BufferSize >= (DWORD)sizeof(PCAP_NDIS_ADAPTER_INFO_LIST),
        STATUS_BUFFER_TOO_SMALL);

    Status = Km_List_Lock(&Data->AdaptersList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        DWORD                           BytesRequired = 0;
        ULARGE_INTEGER                  Count = { 0, };
        unsigned int                    k;
        PLIST_ENTRY                     ListEntry;
        PPCAP_NDIS_ADAPTER_INFO_LIST    List;

        Status = Km_List_GetCountEx(
            &Data->AdaptersList,
            &Count,
            FALSE,
            FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        BytesRequired =
            (DWORD)sizeof(PCAP_NDIS_ADAPTER_INFO_LIST) +
            (DWORD)((Count.QuadPart - 1) * sizeof(PCAP_NDIS_ADAPTER_INFO));

        LEAVE_IF_FALSE_SET_STATUS(
            BytesRequired <= BufferSize,
            STATUS_BUFFER_TOO_SMALL);

        RtlZeroMemory(Buffer, BufferSize);

        List = (PPCAP_NDIS_ADAPTER_INFO_LIST)Buffer;
        List->NumberOfAdapters = (unsigned int)Count.QuadPart;

        BytesCopied += sizeof(PCAP_NDIS_ADAPTER_INFO_LIST) - sizeof(PCAP_NDIS_ADAPTER_INFO);

        for (ListEntry = Data->AdaptersList.Head.Flink, k = 0;
            ListEntry != &Data->AdaptersList.Head;
            ListEntry = ListEntry->Flink, k++)
        {
            PADAPTER    Adapter = CONTAINING_RECORD(ListEntry, ADAPTER, Link);

            if (Adapter->AdapterId.Length > 0)
            {
                RtlCopyMemory(
                    List->Items[k].AdapterId.Buffer,
                    Adapter->AdapterId.Buffer,
                    Adapter->AdapterId.Length);

                List->Items[k].AdapterId.Length = Adapter->AdapterId.Length;
            }

            if (Adapter->MacAddressSize > 0)
            {
                ULONG   MacLength =
                    Adapter->MacAddressSize > PCAP_NDIS_ADAPTER_MAC_ADDRESS_SIZE ?
                    PCAP_NDIS_ADAPTER_MAC_ADDRESS_SIZE :
                    Adapter->MacAddressSize;

                RtlCopyMemory(
                    List->Items[k].MacAddress,
                    Adapter->MacAddress,
                    MacLength);
            }

            List->Items[k].MtuSize = Adapter->MtuSize;

            if (Adapter->DisplayNameSize > 0)
            {
                unsigned long   NumberOfBytes =
                    sizeof(List->Items[k].DisplayName) >= Adapter->DisplayNameSize ?
                    Adapter->DisplayNameSize :
                    sizeof(List->Items[k].DisplayName);

                if (NumberOfBytes > 0)
                {
                    RtlCopyMemory(
                        List->Items[k].DisplayName,
                        Adapter->DisplayName,
                        NumberOfBytes);
                }

                List->Items[k].DisplayNameLength = NumberOfBytes;
            }

            RtlCopyMemory(
                List->Items[k].DisplayName,
                Adapter->DisplayName,
                sizeof(Adapter->DisplayName));

            BytesCopied += sizeof(PCAP_NDIS_ADAPTER_INFO);
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->AdaptersList);
    }

cleanup:

    if (Assigned(BytesRead))
    {
        *BytesRead = BytesCopied;
    }

    return Status;
};

NTSTATUS __stdcall Filter_CreateClient(
    __in    PDRIVER_DATA            Data,
    __in    HANDLE                  ProcessId,
    __in    PVOID                   NewDataEventObject,
    __in    PADAPTER                Adapter,
    __out   PPCAP_NDIS_CLIENT_ID    ClientId)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PCAP_NDIS_CLIENT_ID NewClientId = { 0, 0 };
    PDRIVER_CLIENT      NewClient = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Adapter),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ClientId),
        STATUS_INVALID_PARAMETER_5);

    NewClient = Km_MM_AllocMemTyped(
        &Data->Ndis.MemoryManager,
        DRIVER_CLIENT);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewClient),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewClient, sizeof(DRIVER_CLIENT));

    Status = Km_MP_Initialize(
        &Data->Ndis.MemoryManager,
        (ULONG)sizeof(PACKET) + Adapter->MtuSize - 1,
        PACKETS_POOL_INITIAL_SIZE,
        TRUE,
        CLIENT_PACKET_POOL_MEMORY_TAG,
        &NewClient->PacketsPool);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_List_Initialize(&NewClient->AllocatedPackets);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    RtlCopyMemory(
        &NewClient->AdapterId,
        &Adapter->AdapterId,
        sizeof(PCAP_NDIS_ADAPTER_ID));

    NewClient->OwnerProcessId = ProcessId;

    NewClient->NewPacketEvent = NewDataEventObject;

    NewClientId.Handle = (unsigned long long)NewClient;

    Status = Km_Lock_Acquire(&Data->Clients.Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        ULONG k;

        LEAVE_IF_FALSE_SET_STATUS(
            Data->Clients.Count < DRIVER_MAX_CLIENTS,
            STATUS_INSUFFICIENT_RESOURCES);

        for (k = 0; k < DRIVER_MAX_CLIENTS; k++)
        {
            if (!Assigned(Data->Clients.Items[k]))
            {
                Data->Clients.Items[k] = NewClient;
                Data->Clients.Count++;
                NewClientId.Index = k;
                __leave;
            }
        }

        Status = STATUS_UNSUCCESSFUL;
    }
    __finally
    {
        Km_Lock_Release(&Data->Clients.Lock);
    }

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewClient))
        {
            Km_MP_Finalize(NewClient->PacketsPool);

            Km_MM_FreeMem(
                &Data->Ndis.MemoryManager,
                NewClient);
        }
    }
    else
    {
        RtlCopyMemory(
            ClientId,
            &NewClientId,
            sizeof(NewClientId));
    }

    return Status;
};

NTSTATUS __stdcall Filter_DestroyClient(
    __in    PDRIVER_DATA    Data,
    __in    PDRIVER_CLIENT  Client)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    LIST_ENTRY  TmpList;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Client),
        STATUS_INVALID_PARAMETER_2);
    
    InitializeListHead(&TmpList);

    Status = Km_List_Lock(&Client->AllocatedPackets);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        ULARGE_INTEGER Count;

        Count.QuadPart = MAXULONGLONG;

        Km_List_ExtractEntriesEx(
            &Client->AllocatedPackets,
            &TmpList,
            &Count,
            FALSE,
            FALSE);

        while (!IsListEmpty(&TmpList))
        {
            PLIST_ENTRY Entry = RemoveHeadList(&TmpList);
            PPACKET     Packet = CONTAINING_RECORD(Entry, PACKET, Link);

            Km_MP_Release(Packet);
        }
    }
    __finally
    {
        Km_List_Unlock(&Client->AllocatedPackets);
    }

    Km_MP_Finalize(Client->PacketsPool);

    if (Assigned(Client->NewPacketEvent))
    {
        ObDereferenceObject(Client->NewPacketEvent);
    }

    Km_MM_FreeMem(&Data->Ndis.MemoryManager, Client);

cleanup:
    return Status;
};

NTSTATUS __stdcall Filter_OpenAdapter(
    __in    PDRIVER_DATA                            Data,
    __in    HANDLE                                  ProcessId,
    __in    PPCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA    RequestData,
    __out   PPCAP_NDIS_CLIENT_ID                    ClientId)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PVOID       NewDataEventObject = NULL;
    LONG        AdapterRefCnt = -1;
    
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(RequestData),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        RequestData->EventHandle != 0,
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ClientId),
        STATUS_INVALID_PARAMETER_4);

    Status = KmReferenceEvent(
        (HANDLE)((ULONG_PTR)RequestData->EventHandle),
        &NewDataEventObject);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_List_Lock(&Data->AdaptersList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PADAPTER    Adapter = NULL;

        Status = FindAdapterById(
            &Data->AdaptersList,
            &RequestData->AdapterId,
            &Adapter,
            FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Status = Filter_CreateClient(
            Data,
            ProcessId,
            NewDataEventObject,
            Adapter,
            ClientId);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        AdapterRefCnt = InterlockedIncrement(&Adapter->OpenCount);

        UINT filter = NDIS_PACKET_TYPE_PROMISCUOUS;
        SendOidRequest(Adapter, TRUE, OID_GEN_CURRENT_PACKET_FILTER, &filter, sizeof(filter));
    }
    __finally
    {
        Km_List_Unlock(&Data->AdaptersList);
    }

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewDataEventObject))
        {
            ObDereferenceObject(NewDataEventObject);
        }
    }

    return Status;
};

NTSTATUS __stdcall Filter_CloseAdapter_Internal(
    __in    PDRIVER_DATA    Data,
    __in    PDRIVER_CLIENT  Client)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PCAP_NDIS_ADAPTER_ID    AdapterId;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Client),
        STATUS_INVALID_HANDLE);

    RtlCopyMemory(
        &AdapterId,
        &Client->AdapterId,
        sizeof(PCAP_NDIS_ADAPTER_ID));

    Filter_DestroyClient(Data, Client);

    Status = Km_List_Lock(&Data->AdaptersList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PADAPTER    Adapter = NULL;

        Status = FindAdapterById(
            &Data->AdaptersList,
            &AdapterId,
            &Adapter,
            FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Adapter_Dereference(Adapter);
    }
    __finally
    {
        Km_List_Unlock(&Data->AdaptersList);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Filter_CloseAdapter(
    __in    PDRIVER_DATA            Data,
    __in    PPCAP_NDIS_CLIENT_ID    ClientId)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PDRIVER_CLIENT          Client = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ClientId),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        ClientId->Handle != 0,
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        ClientId->Index < DRIVER_MAX_CLIENTS,
        STATUS_INVALID_PARAMETER_3);

    Status = Km_Lock_Acquire(&Data->Clients.Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        LEAVE_IF_FALSE_SET_STATUS(
            Data->Clients.Items[ClientId->Index] == (PDRIVER_CLIENT)((ULONG_PTR)ClientId->Handle),
            STATUS_INVALID_HANDLE);

        Client = Data->Clients.Items[ClientId->Index];
        Data->Clients.Items[ClientId->Index] = NULL;
        Data->Clients.Count--;
    }
    __finally
    {
        Km_Lock_Release(&Data->Clients.Lock);
    }

    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Filter_CloseAdapter_Internal(Data, Client);

cleanup:
    return Status;
};

NTSTATUS __stdcall Filter_CloseClientsByPID(
    __in    PDRIVER_DATA    Data,
    __in    HANDLE          ProcessId)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PDRIVER_CLIENT  *Clients = NULL;
    ULONG           k;
    ULONG           i;
    ULONG           Cnt;
    ULONG           NumberOfClientsFound = 0;
    ULONG           ClientsCount = 0; 

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);

    Status = Km_Lock_Acquire(&Data->Clients.Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        ClientsCount = Data->Clients.Count;

        LEAVE_IF_FALSE(ClientsCount > 0);

        Status = Km_MP_AllocateCheckSize(
            Data->Clients.ServicePool,
            sizeof(PDRIVER_CLIENT) * DRIVER_MAX_CLIENTS,
            (PVOID *)&Clients);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        for (k = 0, i = 0, Cnt = 0; (k < DRIVER_MAX_CLIENTS) && (Cnt < ClientsCount); k++)
        {
            CONTINUE_IF_FALSE(Assigned(Data->Clients.Items[k]));

            Cnt++;

            CONTINUE_IF_FALSE(
                (Data->Clients.Items[k]->OwnerProcessId == ProcessId) ||
                (ProcessId == (HANDLE)MAXULONG_PTR));

            Clients[i] = Data->Clients.Items[k];
            Data->Clients.Items[k] = NULL;
            
            NumberOfClientsFound++;
        }

        Data->Clients.Count -= NumberOfClientsFound;
    }
    __finally
    {
        Km_Lock_Release(&Data->Clients.Lock);
    }

    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NumberOfClientsFound > 0,
        STATUS_NOT_FOUND);

    for (k = 0; k < NumberOfClientsFound; k++)
    {
        Filter_CloseAdapter_Internal(Data, Clients[k]);
    }

cleanup:

    if (Assigned(Clients))
    {
        Km_Lock_Acquire(&Data->Clients.Lock);
        __try
        {
            Km_MP_Release((PVOID)Clients);
        }
        __finally
        {
            Km_Lock_Release(&Data->Clients.Lock);
        }
    }

    return Status;
};

NTSTATUS __stdcall Filter_ReadPackets(
    __in    PDRIVER_DATA            Data,
    __in    PPCAP_NDIS_CLIENT_ID    ClientId,
    __in    HANDLE                  ProcessId,
    __out   PVOID                   Buffer,
    __in    ULONG                   BufferSize,
    __out   PULONG                  BytesReturned)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PDRIVER_CLIENT  Client = NULL;
    ULONG           BytesCopied = 0;
    LONGLONG        BytesLeft = BufferSize;
    PUCHAR          CurrentPtr = (PUCHAR)Buffer;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        !Data->DriverUnload,
        STATUS_UNSUCCESSFUL);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ClientId),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (ClientId->Handle != 0) &&
        (ClientId->Index < DRIVER_MAX_CLIENTS),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Buffer),
        STATUS_INSUFFICIENT_RESOURCES);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        BufferSize >= sizeof(bpf_hdr2),
        STATUS_INVALID_BUFFER_SIZE);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BytesReturned),
        STATUS_INVALID_PARAMETER_5);
    
    Status = Km_Lock_Acquire(&Data->Clients.Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PLIST_ENTRY ListEntry;
        PLIST_ENTRY NextEntry;

        LEAVE_IF_FALSE_SET_STATUS(
            Data->Clients.Items[ClientId->Index] == (PDRIVER_CLIENT)((ULONG_PTR)ClientId->Handle),
            STATUS_INVALID_HANDLE);

        Client = Data->Clients.Items[ClientId->Index];

        LEAVE_IF_FALSE_SET_STATUS(
            Client->OwnerProcessId == ProcessId,
            STATUS_ACCESS_DENIED);

        for (ListEntry = Client->AllocatedPackets.Head.Flink, NextEntry = ListEntry->Flink;
            ListEntry != &Client->AllocatedPackets.Head;
            ListEntry = NextEntry, NextEntry = NextEntry->Flink)
        {
            PPACKET     Packet = CONTAINING_RECORD(ListEntry, PACKET, Link);
            USHORT      HeaderSize = (USHORT)sizeof(bpf_hdr2);
            bpf_hdr2    bpf;
            ULONG       TotalPacketSize = Packet->DataSize + HeaderSize;

            BREAK_IF_FALSE(BytesLeft >= TotalPacketSize);

            bpf.bh_caplen = Packet->DataSize;
            bpf.bh_datalen = Packet->DataSize;
            bpf.bh_hdrlen = HeaderSize;
            bpf.ProcessId = (unsigned long)Packet->ProcessId;
            bpf.bh_tstamp.tv_sec = Packet->Timestamp.Seconds;
            bpf.bh_tstamp.tv_usec = Packet->Timestamp.Microseconds;

            RtlCopyMemory(CurrentPtr, &bpf, HeaderSize);
            RtlCopyMemory(CurrentPtr + HeaderSize, Packet->Data, Packet->DataSize);

            BytesCopied += TotalPacketSize;
            CurrentPtr += TotalPacketSize;
            BytesLeft -= TotalPacketSize;

            Km_List_RemoveItemEx(
                &Client->AllocatedPackets,
                ListEntry,
                FALSE,
                FALSE);

            Km_MP_Release((PVOID)Packet);
        }

        if (Client->AllocatedPackets.Count.QuadPart == 0)
        {
            if (Assigned(Client->NewPacketEvent))
            {
                KeClearEvent(Client->NewPacketEvent);
            }
        }
    }
    __finally
    {
        Km_Lock_Release(&Data->Clients.Lock);
    }

    *BytesReturned = BytesCopied;

cleanup:
    return Status;
};

NTSTATUS __stdcall Filter_GetDiagInfo(
    __in    PDRIVER_DATA                Data,
    __out   PDRIVER_DIAG_INFORMATION    DiagInfo)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    KM_MM_STATS Stats;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DiagInfo),
        STATUS_INVALID_PARAMETER_2);

    RtlZeroMemory(&Stats, sizeof(Stats));
    RtlZeroMemory(DiagInfo, sizeof(DRIVER_DIAG_INFORMATION));

    if (NT_SUCCESS(Km_MM_QueryStats(&Data->Ndis.MemoryManager, &Stats)))
    {
        DiagInfo->NdisMMStats.AllocationsCount = Stats.CurrentAllocations.NumberOfAllocations;
        DiagInfo->NdisMMStats.TotalBytesAllocated = Stats.CurrentAllocations.TotalBytesAllocated;
        DiagInfo->NdisMMStats.UserBytesAllocated = Stats.CurrentAllocations.UserBytesAllocated;
        DiagInfo->Flags |= DRIVER_DIAG_INFORMATION_FLAG_NDIS_MM_STATS;
    }

    if (NT_SUCCESS(Km_MM_QueryStats(&Data->Wfp.MemoryManager, &Stats)))
    {
        DiagInfo->WfpMMStats.AllocationsCount = Stats.CurrentAllocations.NumberOfAllocations;
        DiagInfo->WfpMMStats.TotalBytesAllocated = Stats.CurrentAllocations.TotalBytesAllocated;
        DiagInfo->WfpMMStats.UserBytesAllocated = Stats.CurrentAllocations.UserBytesAllocated;
        DiagInfo->Flags |= DRIVER_DIAG_INFORMATION_FLAG_WFP_MM_STATS;
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Filter_IMC_IOCTL_Callback(
    __in    PVOID       Context,
    __in    ULONG       ControlCode,
    __in    PVOID       InBuffer,
    __in    ULONG       InBufferSize,
    __out   PVOID       OutBuffer,
    __in    ULONG       OutBufferSize,
    __out   PULONG_PTR  BytesReturned)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    ULONG_PTR       BytesRet = 0;
    DWORD           BytesRead = 0;
    PDRIVER_DATA    Data = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Context),
        STATUS_UNSUCCESSFUL);

    Data = (PDRIVER_DATA)Context;
    GOTO_CLEANUP_IF_TRUE_SET_STATUS(
        Data->DriverUnload,
        STATUS_UNSUCCESSFUL);

    switch (ControlCode)
    {
    case IOCTL_GET_ADAPTERS_COUNT:
        {
            ULARGE_INTEGER  NumberOfAdapters;

            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                Assigned(OutBuffer),
                STATUS_INVALID_PARAMETER);
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                OutBufferSize >= sizeof(DWORD),
                STATUS_BUFFER_TOO_SMALL);

            Status = Km_List_GetCount(&Data->AdaptersList, &NumberOfAdapters);
            if (NT_SUCCESS(Status))
            {
                *((PDWORD)OutBuffer) = (DWORD)NumberOfAdapters.QuadPart;
                BytesRet = (ULONG_PTR)sizeof(DWORD);
            }

        }break;

    case IOCTL_GET_ADAPTERS:
        {
            Status = Filter_GetAdapters(
                Data,
                OutBuffer,
                OutBufferSize,
                &BytesRead);
            if (NT_SUCCESS(Status))
            {
                BytesRet = BytesRead;
            }
        }break;

    case IOCTL_OPEN_ADAPTER:
        {
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                (Assigned(InBuffer)) &&
                (Assigned(OutBuffer)) &&
                (InBufferSize == (ULONG)sizeof(PCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA)),
                STATUS_INVALID_PARAMETER);
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                OutBufferSize >= sizeof(PCAP_NDIS_CLIENT_ID),
                STATUS_BUFFER_TOO_SMALL);

            Status = Filter_OpenAdapter(
                Data,
                PsGetCurrentProcessId(),
                (PPCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA)InBuffer,
                (PPCAP_NDIS_CLIENT_ID)OutBuffer);
            if (NT_SUCCESS(Status))
            {
                BytesRet = (ULONG_PTR)sizeof(PCAP_NDIS_CLIENT_ID);
            }

        }break;

    case IOCTL_CLOSE_ADAPTER:
        {
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                (Assigned(InBuffer)) &&
                (InBufferSize == (ULONG)sizeof(PCAP_NDIS_CLIENT_ID)),
                STATUS_INVALID_PARAMETER);

            Status = Filter_CloseAdapter(
                Data,
                (PPCAP_NDIS_CLIENT_ID)InBuffer);
        }break;

    case IOCTL_READ_PACKETS:
        {
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                (Assigned(InBuffer)) &&
                (InBufferSize == (ULONG)sizeof(PCAP_NDIS_CLIENT_ID)),
                STATUS_INVALID_PARAMETER);
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                (Assigned(OutBuffer)) &&
                (OutBufferSize > 0),
                STATUS_BUFFER_TOO_SMALL);

            Status = Filter_ReadPackets(
                Data,
                (PPCAP_NDIS_CLIENT_ID)InBuffer,
                PsGetCurrentProcessId(),
                OutBuffer,
                OutBufferSize,
                &BytesRead);
            if (NT_SUCCESS(Status))
            {
                BytesRet = BytesRead;
            }
        }break;

    case IOCTL_GET_DIAG_INFO:
        {
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                (Assigned(OutBuffer)) &&
                (OutBufferSize >= (ULONG)sizeof(DRIVER_DIAG_INFORMATION)),
                STATUS_INVALID_PARAMETER);

            Status = Filter_GetDiagInfo(
                Data,
                (PDRIVER_DIAG_INFORMATION)OutBuffer);
            if (NT_SUCCESS(Status))
            {
                BytesRead = sizeof(DRIVER_DIAG_INFORMATION);
                BytesRet = BytesRead;
            }
        }break;

    default:
        {
            Status = STATUS_NOT_SUPPORTED;
        }break;
    };

cleanup:

    if (Assigned(BytesReturned))
    {
        *BytesReturned = BytesRet;
    }

    return Status;
};

void __stdcall Filter_Wfp_EventCallback(
    __in    WFP_NETWORK_EVENT_TYPE  EventType,
    __in    PNETWORK_EVENT_INFO     EventInfo,
    __in    PVOID                   Context)
{
    PDRIVER_DATA    Data = NULL;

    RETURN_IF_FALSE(
        (Assigned(EventInfo)) &&
        (Assigned(Context)));

    Data = (PDRIVER_DATA)Context;

    switch (EventType)
    {
    case wnetNewFlow:
        {
            Km_Connections_Add(
                Data->Other.Connections,
                EventInfo);
        }break;

    case wnetFlowRemove:
        {
            Km_Connections_Remove(
                Data->Other.Connections,
                EventInfo);
        }break;
    };
};

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

    Chars.MajorDriverVersion = 1;
    Chars.MinorDriverVersion = 0;

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

void __stdcall Filter_ProcessWatcher_Callback(
    __in_opt    HANDLE  ParentProcessId,
    __in        HANDLE  ProcessId,
    __in        BOOLEAN NewProcess,
    __in        PVOID   Context)
{
    PDRIVER_DATA    Data = NULL;

    UNREFERENCED_PARAMETER(ParentProcessId);

    RETURN_IF_FALSE(Assigned(Context));

    //  We're not interested in new processes here
    //  since we need to handle process terminations only
    RETURN_IF_TRUE(NewProcess);

    Data = (PDRIVER_DATA)Context;

    Filter_CloseClientsByPID(
        Data,
        ProcessId);
};

void __stdcall Filter_ReEnumBindingsThreadRoutine(
    __in    PKM_TIMER_THREAD    Thread,
    __in    PVOID               Context)
{
    PDRIVER_DATA    Data = NULL;

    UNREFERENCED_PARAMETER(Thread);

    RETURN_IF_FALSE(Assigned(Context));

    Data = (PDRIVER_DATA)Context;

    RETURN_IF_TRUE(Data->DriverUnload);

    RETURN_IF_FALSE(Data->Ndis.ProtocolHandle != NULL);

    NdisReEnumerateProtocolBindings(Data->Ndis.ProtocolHandle);
};

_Use_decl_annotations_
NTSTATUS
_Function_class_(DRIVER_INITIALIZE)
DriverEntry(
    PDRIVER_OBJECT      DriverObject,
    PUNICODE_STRING     RegistryPath)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    UNICODE_STRING  FilterDeviceName = RTL_CONSTANT_STRING(FILTER_DEVICE_NAME_W);

    UNREFERENCED_PARAMETER(RegistryPath);

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

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

    Status = Wfp_MM_Initialize(
        &DriverData.Wfp.MemoryManager,
        HighPoolPriority,
        NonPagedPoolNx,
        WFP_FLT_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_ProcessWatcher_Initialize(&DriverData.Ndis.MemoryManager);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    DriverData.Other.DriverObject = DriverObject;

    Status = Km_List_Initialize(&DriverData.AdaptersList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_Lock_Initialize(&DriverData.Clients.Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_MP_Initialize(
        &DriverData.Ndis.MemoryManager,
        sizeof(PDRIVER_CLIENT) * DRIVER_MAX_CLIENTS,
        DRIVER_SVC_CLIENTS_POOL_SIZE,
        FALSE,
        DRIVER_CLIENTS_POOL_MEMORY_TAG,
        &DriverData.Clients.ServicePool);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_Connections_Initialize(
        &DriverData.Ndis.MemoryManager,
        &DriverData.Other.Connections);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    /*
    Status = KmTimerThread_Allocate(
        &DriverData.Ndis.MemoryManager,
        &Filter_ReEnumBindingsThreadRoutine,
        &DriverData,
        &DriverData.Ndis.ReEnumBindingsThread);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    */

    Status = Wfp_Initialize(
        DriverObject,
        &DriverData.Wfp.MemoryManager,
        Filter_Wfp_EventCallback,
        &DriverData,
        &DriverData.Wfp.Instance);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    RtlZeroMemory(
        DriverObject->MajorFunction,
        sizeof(DriverObject->MajorFunction));

    Status = Km_IMC_Initialize(
        &DriverData.Ndis.MemoryManager,
        DriverObject,
        Filter_IMC_IOCTL_Callback,
        &FilterDeviceName,
        FILE_DEVICE_TRANSPORT,
        &DriverData.Other.IMCInstance,
        &DriverData);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_ProcessWatcher_RegisterCallback(
        Filter_ProcessWatcher_Callback,
        &DriverData,
        &DriverData.Other.ProcessWather);

    /*KmTimerThread_SetInterval(
        DriverData.Ndis.ReEnumBindingsThread,
        FILTER_RE_ENUM_BINDINGS_INTERVAL);
        */

    DriverObject->DriverUnload = DriverUnload;

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (DriverData.Other.IMCInstance != NULL)
        {
            Km_IMC_Finalize(DriverData.Other.IMCInstance);
            DriverData.Other.IMCInstance = NULL;
        }

        if (DriverData.Wfp.Instance != NULL)
        {
            Wfp_Finalize(DriverData.Wfp.Instance);
            DriverData.Wfp.Instance = NULL;
        }

        Km_MM_Finalize(&DriverData.Wfp.MemoryManager);

        if (Assigned(DriverData.Ndis.ReEnumBindingsThread))
        {
            KmTimerThread_Stop(DriverData.Ndis.ReEnumBindingsThread, MAXULONG);
            KmTimerThread_Destroy(DriverData.Ndis.ReEnumBindingsThread);
            DriverData.Ndis.ReEnumBindingsThread = NULL;
        }

        if (DriverData.Other.Connections != NULL)
        {
            Km_Connections_Finalize(
                DriverData.Other.Connections);
        }

        Km_ProcessWatcher_Finalize();

        if (DriverData.Clients.ServicePool != NULL)
        {
            Km_MP_Finalize(DriverData.Clients.ServicePool);
        }

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
    UNREFERENCED_PARAMETER(DriverObject);

    InterlockedExchange(
        &DriverData.DriverUnload,
        TRUE);

    if (DriverData.Other.IMCInstance != NULL)
    {
        Km_IMC_Finalize(DriverData.Other.IMCInstance);
        DriverData.Other.IMCInstance = NULL;
    }

    if (DriverData.Wfp.Instance != NULL)
    {
        Wfp_Finalize(DriverData.Wfp.Instance);
        DriverData.Wfp.Instance = NULL;
    }

    Km_MM_Finalize(&DriverData.Wfp.MemoryManager);

    if (DriverData.Other.Connections != NULL)
    {
        Km_Connections_Finalize(
            DriverData.Other.Connections);
    }

    if (Assigned(DriverData.Ndis.ReEnumBindingsThread))
    {
        KmTimerThread_Stop(DriverData.Ndis.ReEnumBindingsThread, MAXULONG);
        KmTimerThread_Destroy(DriverData.Ndis.ReEnumBindingsThread);
    }

    Filter_CloseClientsByPID(
        &DriverData,
        (HANDLE)MAXULONG_PTR);

    Adapters_Unbind(
        &DriverData.Ndis.MemoryManager,
        &DriverData.AdaptersList);

    Km_ProcessWatcher_Finalize();

    if (DriverData.Clients.ServicePool != NULL)
    {
        Km_MP_Finalize(DriverData.Clients.ServicePool);
    }

    Km_MM_Finalize(&DriverData.Ndis.MemoryManager);

    if (DriverData.Ndis.ProtocolHandle != NULL)
    {
        NdisDeregisterProtocolDriver(DriverData.Ndis.ProtocolHandle);
        DriverData.Ndis.ProtocolHandle = NULL;
    }

    RtlZeroMemory(
        &DriverData,
        sizeof(DriverData));
};