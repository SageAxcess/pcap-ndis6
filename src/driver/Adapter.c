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

#include <ndis.h>

#include "flt_dbg.h"
#include "Adapter.h"
#include "KernelUtil.h"
#include "KmList.h"
#include "KmMemoryManager.h"
#include "KmConnections.h"
#include "KmMemoryPool.h"

#include "..\..\driver_version.h"
#include "..\shared\CommonDefs.h"

//////////////////////////////////////////////////////////////////////
// External variables
//////////////////////////////////////////////////////////////////////

extern DRIVER_DATA  DriverData;

//////////////////////////////////////////////////////////////////////
// Adapter variables
//////////////////////////////////////////////////////////////////////

UINT    SelectedMediumIndex = 0;

//////////////////////////////////////////////////////////////////////
// Forward declarations
//////////////////////////////////////////////////////////////////////
void __stdcall Adapter_WorkerThreadRoutine(
    __in    PKM_THREAD  Thread);

//////////////////////////////////////////////////////////////////////
// Adapter methods
//////////////////////////////////////////////////////////////////////

NTSTATUS __stdcall Adapter_Allocate(
    __in    PKM_MEMORY_MANAGER      MemoryManager,
    __in    PNDIS_BIND_PARAMETERS   BindParameters,
    __in    NDIS_HANDLE             BindContext,
    __out   PADAPTER                *Adapter)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PADAPTER        NewAdapter = NULL;
    DWORD           SizeRequired = sizeof(ADAPTER);
    UNICODE_STRING  TmpStr = RTL_CONSTANT_STRING(DEVICE_STR_W);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BindParameters),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Adapter),
        STATUS_INVALID_PARAMETER_4);

    NewAdapter = Km_MM_AllocMemTypedWithSize(
        MemoryManager,
        ADAPTER,
        SizeRequired);
    RETURN_VALUE_IF_FALSE(
        Assigned(NewAdapter),
        NDIS_STATUS_FAILURE);

    RtlZeroMemory(NewAdapter, sizeof(ADAPTER));

    Status = Km_List_Initialize(&NewAdapter->Packets.Allocated);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_MP_Initialize(
        MemoryManager,
        CalcRequiredPacketSize(BindParameters->MtuSize),
        PACKETS_POOL_INITIAL_SIZE,
        TRUE,
        ADAPTER_PACKET_POOL_MEMORY_TAG,
        &NewAdapter->Packets.Pool);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    KeInitializeEvent(&NewAdapter->Packets.NewPacketEvent, NotificationEvent, FALSE);

    Status = KmThreads_CreateThread(
        MemoryManager,
        &NewAdapter->WorkerThread,
        Adapter_WorkerThreadRoutine,
        NewAdapter);

    if (BindParameters->AdapterName->Length > 0)
    {
        ULONG   IdLength = BindParameters->AdapterName->Length;
        ULONG   IdOffset = 0;

        if (StringStartsWith(
            BindParameters->AdapterName,
            &TmpStr))
        {
            IdOffset += TmpStr.Length / sizeof(wchar_t);
            IdLength -= TmpStr.Length;
        }

        if (IdLength > PCAP_NDIS_ADAPTER_ID_SIZE_MAX * sizeof(wchar_t))
        {
            IdLength = PCAP_NDIS_ADAPTER_ID_SIZE_MAX * sizeof(wchar_t);
        }

        if (IdLength > 0)
        {
            RtlCopyMemory(
                NewAdapter->AdapterId.Buffer,
                BindParameters->AdapterName->Buffer + IdOffset,
                IdLength);
        }

        NewAdapter->AdapterId.Length = IdLength;
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

    KmGetStartTime(&NewAdapter->BindTimestamp);

    NewAdapter->BindContext = BindContext;

cleanup:

    if (NT_SUCCESS(Status))
    {
        *Adapter = NewAdapter;
    }
    else
    {
        if (Assigned(NewAdapter))
        {
            if (Assigned(NewAdapter->WorkerThread))
            {
                KmThreads_StopThread(NewAdapter->WorkerThread, MAXULONG);
                KmThreads_DestroyThread(NewAdapter->WorkerThread);
            }

            if (NewAdapter->Packets.Pool != NULL)
            {
                Km_MP_Finalize(NewAdapter->Packets.Pool);
            }

            Km_MM_FreeMem(MemoryManager, NewAdapter);
        }
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
    PNDIS_OID_REQUEST   Request = NULL;

    RETURN_VALUE_IF_FALSE(
        (Assigned(adapter)) &&
        (Assigned(data)) &&
        (size > 0),
        FALSE);

    RETURN_VALUE_IF_FALSE(
        Assigned(adapter->DriverData),
        FALSE);
    Request = Km_MM_AllocMemTyped(
        &adapter->DriverData->Ndis.MemoryManager,
        NDIS_OID_REQUEST);

    RETURN_VALUE_IF_FALSE(
        Assigned(Request),
        FALSE);
    
    NdisZeroMemory(Request, sizeof(NDIS_OID_REQUEST));

    Request->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    Request->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    Request->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;

    if(set)
    {
        Request->RequestType = NdisRequestSetInformation;
        Request->DATA.SET_INFORMATION.Oid = oid;
        Request->DATA.SET_INFORMATION.InformationBuffer = Km_MM_AllocMem(
            &adapter->DriverData->Ndis.MemoryManager,
            size);

        if(!Request->DATA.SET_INFORMATION.InformationBuffer)
        {
            Km_MM_FreeMem(
                &adapter->DriverData->Ndis.MemoryManager,
                Request);
            return FALSE;
        }

        RtlCopyMemory(
            Request->DATA.SET_INFORMATION.InformationBuffer,
            data,
            size);

        Request->DATA.SET_INFORMATION.InformationBufferLength = size;
    }
    else
    {
        Request->RequestType = NdisRequestQueryInformation;
        Request->DATA.QUERY_INFORMATION.Oid = oid;
        Request->DATA.QUERY_INFORMATION.InformationBuffer = data;
        Request->DATA.QUERY_INFORMATION.InformationBufferLength = size;
    }

    RETURN_VALUE_IF_FALSE(
        adapter->AdapterHandle != NULL,
        FALSE);

    InterlockedIncrement((volatile LONG *)&adapter->PendingOidRequests);

    NDIS_STATUS ret = NdisOidRequest(adapter->AdapterHandle, Request);
    if(ret != NDIS_STATUS_PENDING)
    {
        if (ret == NDIS_STATUS_SUCCESS)
        {
            adapter->DisplayNameSize = Request->DATA.QUERY_INFORMATION.BytesWritten;
        }

        InterlockedDecrement((volatile LONG *)&adapter->PendingOidRequests);

        if (set)
        {
            Km_MM_FreeMem(
                &adapter->DriverData->Ndis.MemoryManager,
                Request->DATA.SET_INFORMATION.InformationBuffer);
        }

        Km_MM_FreeMem(
            &adapter->DriverData->Ndis.MemoryManager,
            Request);
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

    if (Assigned(Adapter->WorkerThread))
    {
        KmThreads_StopThread(Adapter->WorkerThread, MAXULONG);
        KmThreads_DestroyThread(Adapter->WorkerThread);
    }

    if (Adapter->Packets.Pool != NULL)
    {
        Km_MP_Finalize(Adapter->Packets.Pool);
    }

    MemoryManager = &Adapter->DriverData->Ndis.MemoryManager;

    Km_MM_FreeMem(
        MemoryManager,
        Adapter);

    return TRUE;
};

int __stdcall UnbindAdapter_SearchCallback(
    __in    PKM_LIST    List,
    __in    PVOID       ItemDefinition,
    __in    PLIST_ENTRY Item)
{
    UNREFERENCED_PARAMETER(List);

    return (ItemDefinition == Item) ? 0 : 1;
};

// Returns timestamp in milliseconds since adapter started
NTSTATUS GetAdapterTime(
    __in    PADAPTER    Adapter,
    __out   PKM_TIME    Time)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    LARGE_INTEGER   BootTime;
    LARGE_INTEGER   Frequency;
    long            TimeIncrement;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Adapter),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Time),
        STATUS_INVALID_PARAMETER_2);

    BootTime = KeQueryPerformanceCounter(&Frequency);
    TimeIncrement = (long)(BootTime.QuadPart / Frequency.QuadPart);

    Time->Seconds = Adapter->BindTimestamp.Seconds + (long)TimeIncrement;
    Time->Microseconds =
        Adapter->BindTimestamp.Microseconds +
        (long)((BootTime.QuadPart % Frequency.QuadPart) * MicrosecondsInASecond / Frequency.QuadPart);

    if (Time->Microseconds >= MicrosecondsInASecond)
    {
        Time->Seconds++;
        Time->Microseconds -= MicrosecondsInASecond;
    }

cleanup:
    return Status;
};

NTSTATUS FindAdapterById(
    __in        PKM_LIST                AdapterList,
    __in        PPCAP_NDIS_ADAPTER_ID   AdapterId,
    __out_opt   PADAPTER                *Adapter,
    __in        BOOLEAN                 LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PLIST_ENTRY Entry = NULL;
    PADAPTER    ExistingAdapter = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(AdapterList),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(AdapterId),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        AdapterId->Length >= sizeof(wchar_t),
        STATUS_INVALID_PARAMETER_2);

    if (LockList)
    {
        Status = Km_List_Lock(AdapterList);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        for (Entry = AdapterList->Head.Flink;
            Entry != &AdapterList->Head;
            Entry = Entry->Flink)
        {
            PADAPTER    Tmp = CONTAINING_RECORD(Entry, ADAPTER, Link);

            if (EqualAdapterIds(AdapterId, &Tmp->AdapterId))
            {
                ExistingAdapter = Tmp;
                break;
            }
        }
    }
    __finally
    {
        if (LockList)
        {
            Km_List_Unlock(AdapterList);
        }
    }

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ExistingAdapter),
        STATUS_NOT_FOUND);

    if (Assigned(Adapter))
    {
        *Adapter = ExistingAdapter;
    }

cleanup:
    return Status;
};

NTSTATUS Adapter_Reference(
    __in    PADAPTER    Adapter)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Adapter),
        STATUS_INVALID_PARAMETER_1);

    Status = Km_Lock_Acquire(&Adapter->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Adapter->OpenCount++;
        if ((Adapter->OpenCount == 1) &&
            (!Adapter->PacketsInterceptionEnabled))
        {
            UINT PacketFilter = NDIS_PACKET_TYPE_PROMISCUOUS;

            SendOidRequest(
                Adapter,
                TRUE,
                OID_GEN_CURRENT_PACKET_FILTER,
                &PacketFilter,
                sizeof(PacketFilter));

            Adapter->PacketsInterceptionEnabled = TRUE;
        }
    }
    __finally
    {
        Km_Lock_Release(&Adapter->Lock);
    }

cleanup:
    return Status;
};

NTSTATUS Adapter_Dereference(
    __in    PADAPTER    Adapter)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Adapter),
        STATUS_INVALID_PARAMETER_1);

    Status = Km_Lock_Acquire(&Adapter->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        if (Adapter->OpenCount > 0)
        {
            Adapter->OpenCount--;
        }
    }
    __finally
    {
        Km_Lock_Release(&Adapter->Lock);
    }

cleanup:
    return Status;
};

void __stdcall Adapter_WorkerThreadRoutine(
    __in    PKM_THREAD  Thread)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PADAPTER        Adapter = NULL;
    PVOID           WaitArray[2];
    BOOL            StopThread = FALSE;
    LIST_ENTRY      TmpList;
    ULARGE_INTEGER  Count;
    
    RETURN_IF_FALSE(Assigned(Thread));
    RETURN_IF_FALSE(Assigned(Thread->Context));
    
    Adapter = (PADAPTER)Thread->Context;
    RETURN_IF_FALSE(Assigned(Adapter->DriverData));

    WaitArray[0] = (PVOID)&Thread->StopEvent;
    WaitArray[1] = (PVOID)&Adapter->Packets.NewPacketEvent;

    InitializeListHead(&TmpList);

    while (!StopThread)
    {
        Status = KeWaitForMultipleObjects(
            2,
            WaitArray,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL);

        switch (Status)
        {
        case STATUS_WAIT_0:
            {
                StopThread = TRUE;
            }break;

        case STATUS_WAIT_1:
            {
                Km_List_Lock(&Adapter->Packets.Allocated);
                __try
                {
                    Count.QuadPart = MAXULONGLONG;

                    Km_List_ExtractEntriesEx(
                        &Adapter->Packets.Allocated,
                        &TmpList,
                        &Count,
                        FALSE,
                        FALSE);

                    KeClearEvent(&Adapter->Packets.NewPacketEvent);
                }
                __finally
                {
                    Km_List_Unlock(&Adapter->Packets.Allocated);
                }

                while (!IsListEmpty(&TmpList))
                {
                    PLIST_ENTRY Entry = RemoveHeadList(&TmpList);
                    PPACKET     Packet = CONTAINING_RECORD(Entry, PACKET, Link);
                    __try
                    {
                        Km_Lock_Acquire(&Adapter->DriverData->Clients.Lock);
                        __try
                        {
                            ULONG   k;
                            ULONG   Cnt;

                            for (k = 0, Cnt = 0;
                                (k < DRIVER_MAX_CLIENTS) && (Cnt < Adapter->DriverData->Clients.Count);
                                k++)
                            {
                                CONTINUE_IF_FALSE(Assigned(Adapter->DriverData->Clients.Items[k]));

                                if (EqualAdapterIds(
                                    &Adapter->DriverData->Clients.Items[k]->AdapterId,
                                    &Adapter->AdapterId))
                                {
                                    ULARGE_INTEGER  ClientPacketsCount;
                                    PPACKET NewPacket = NULL;
                                    Status = Km_MP_AllocateCheckSize(
                                        Adapter->DriverData->Clients.Items[k]->PacketsPool,
                                        sizeof(PACKET) + Packet->DataSize - 1,
                                        (PVOID *)&NewPacket);
                                    Cnt++;

                                    if (Status == STATUS_NO_MORE_ENTRIES)
                                    {
                                        PLIST_ENTRY TmpEntry = NULL;

                                        Status = Km_List_RemoveListHeadEx(
                                            &Adapter->DriverData->Clients.Items[k]->AllocatedPackets,
                                            &TmpEntry,
                                            FALSE,
                                            FALSE);
                                        CONTINUE_IF_FALSE(NT_SUCCESS(Status));

                                        NewPacket = CONTAINING_RECORD(TmpEntry, PACKET, Link);
                                    }

                                    CONTINUE_IF_FALSE(NT_SUCCESS(Status));

                                    RtlCopyMemory(
                                        NewPacket,
                                        Packet,
                                        sizeof(PACKET) + Packet->DataSize - 1);

                                    Km_List_Lock(&Adapter->DriverData->Clients.Items[k]->AllocatedPackets);
                                    __try
                                    {
                                        Km_List_GetCountEx(
                                            &Adapter->DriverData->Clients.Items[k]->AllocatedPackets,
                                            &ClientPacketsCount,
                                            FALSE,
                                            FALSE);

                                        Status = Km_List_AddItemEx(
                                            &Adapter->DriverData->Clients.Items[k]->AllocatedPackets,
                                            &NewPacket->Link,
                                            FALSE,
                                            FALSE);
                                        if (!NT_SUCCESS(Status))
                                        {
                                            Km_MP_Release(NewPacket);
                                            __leave;
                                        }

                                        if ((Assigned(Adapter->DriverData->Clients.Items[k]->NewPacketEvent)) &&
                                            (ClientPacketsCount.QuadPart == 0))
                                        {
                                            KeSetEvent(Adapter->DriverData->Clients.Items[k]->NewPacketEvent, 0, FALSE);
                                        }
                                    }
                                    __finally
                                    {
                                        Km_List_Unlock(&Adapter->DriverData->Clients.Items[k]->AllocatedPackets);
                                    }
                                }
                            }
                        }
                        __finally
                        {
                            Km_Lock_Release(&Adapter->DriverData->Clients.Lock);
                        }
                    }
                    __finally
                    {
                        Km_MP_Release((PVOID)Packet);
                    }
                }
            }break;
        };
    }

    Count.QuadPart = MAXULONGLONG;

    Km_List_ExtractEntriesEx(
        &Adapter->Packets.Allocated, 
        &TmpList, 
        &Count, 
        FALSE, 
        TRUE);

    while (!IsListEmpty(&TmpList))
    {
        PLIST_ENTRY Entry = RemoveHeadList(&TmpList);
        Km_MP_Release(CONTAINING_RECORD(Entry, PACKET, Link));
    }
};

NTSTATUS Adapter_AllocateAndFillPacket(
    __in    PADAPTER    Adapter,
    __in    PVOID       PacketData,
    __in    ULONG       PacketDataSize,
    __in    ULONGLONG   ProcessId,
    __in    PKM_TIME    Timestamp,
    __out   PPACKET     *Packet)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PPACKET     NewPacket = NULL;
    SIZE_T      SizeRequired = sizeof(PACKET) + PacketDataSize - 1;
    PETH_HEADER EthHeader = (PETH_HEADER)PacketData;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Adapter),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(PacketData),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        PacketDataSize > 0,
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Timestamp),
        STATUS_INVALID_PARAMETER_5);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Packet),
        STATUS_INVALID_PARAMETER_6);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (EthHeader->EthType == ETH_TYPE_IP) ||
        (EthHeader->EthType == ETH_TYPE_IP6) ||
        (EthHeader->EthType == ETH_TYPE_IP_BE) ||
        (EthHeader->EthType == ETH_TYPE_IP6_BE),
        STATUS_NOT_SUPPORTED);

    Status = Km_MP_AllocateCheckSize(
        Adapter->Packets.Pool,
        SizeRequired,
        (PVOID *)&NewPacket);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    RtlZeroMemory(
        NewPacket,
        SizeRequired);

    NewPacket->DataSize = PacketDataSize;
    RtlCopyMemory(
        &NewPacket->Timestamp,
        Timestamp,
        sizeof(KM_TIME));
    RtlCopyMemory(
        &NewPacket->Data,
        PacketData,
        PacketDataSize);

    NewPacket->ProcessId = ProcessId;

    *Packet = NewPacket;

cleanup:
    return Status;
};

NTSTATUS Adapters_Unbind(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PKM_LIST            AdaptersList)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PKEVENT         CompletionEvent = NULL;
    PADAPTER        *AdaptersArray = NULL;
    PLIST_ENTRY     TmpEntry = NULL;
    ULONG           k = 0;
    ULARGE_INTEGER  Count = { 0 };

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(AdaptersList),
        STATUS_INVALID_PARAMETER_2);

    CompletionEvent = Km_MM_AllocMemTyped(
        MemoryManager,
        KEVENT);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CompletionEvent),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        KeInitializeEvent(
            CompletionEvent,
            NotificationEvent,
            FALSE);

        Status = Km_List_Lock(AdaptersList);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));
        __try
        {
            Km_List_GetCountEx(AdaptersList, &Count, FALSE, FALSE);

            if (Count.QuadPart > 0)
            {
                AdaptersArray = Km_MM_AllocArray(
                    MemoryManager,
                    PADAPTER,
                    (SIZE_T)Count.QuadPart);
                LEAVE_IF_FALSE_SET_STATUS(
                    Assigned(AdaptersArray),
                    STATUS_INSUFFICIENT_RESOURCES);

                RtlZeroMemory(
                    AdaptersArray, 
                    (SIZE_T)(sizeof(PADAPTER) * Count.QuadPart));

                for (TmpEntry = AdaptersList->Head.Flink, k = 0;
                    TmpEntry != &AdaptersList->Head;
                    TmpEntry = TmpEntry->Flink, k++)
                {
                    AdaptersArray[k] = CONTAINING_RECORD(TmpEntry, ADAPTER, Link);
                }
            }

            Km_List_ClearEx(AdaptersList, NULL, FALSE, FALSE);
        }
        __finally
        {
            Km_List_Unlock(AdaptersList);
        }

        for (k = 0; k < Count.QuadPart; k++)
        {
            Km_Lock_Acquire(&AdaptersArray[k]->Lock);
            __try
            {
                AdaptersArray[k]->AdapterUnbindCompletionEvent = CompletionEvent;
            }
            __finally
            {
                Km_Lock_Release(&AdaptersArray[k]->Lock);
            }

            NdisUnbindAdapter(AdaptersArray[k]->AdapterHandle);

            KeWaitForSingleObject(
                CompletionEvent,
                Executive,
                KernelMode,
                FALSE,
                NULL);

            KeClearEvent(CompletionEvent);
        }
    }
    __finally
    {
        Km_MM_FreeMem(
            MemoryManager,
            CompletionEvent);
    }
cleanup:
    return Status;
};

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

    DbgPrint(
        "%s: ProtocolDriverContext = %p, BindContext = %p, BindParameters = %p\n",
        __FUNCTION__,
        ProtocolDriverContext,
        BindContext,
        BindParameters);

    if (DriverData.DriverUnload)
    {
        DbgPrint(
            "%s: DriverUnload flag is TRUE\n",
            __FUNCTION__);
        Status = NDIS_STATUS_FAILURE;
        goto cleanup;
    }

    if ((ProtocolDriverContext == NULL) ||
        (!Assigned(BindParameters)))
    {
        DbgPrint(
            "%: ProtocolDriverContext = %p, BindParameters = %p\n",
            __FUNCTION__,
            ProtocolDriverContext,
            BindParameters);
        Status = NDIS_STATUS_FAILURE;
        goto cleanup;
    }

    DbgPrint(
        "%s: BindParameters --> MediaType = %d, MacAddrLen = %d, AccessType = %d, DirType = %d, ConnType = %d\n",
        __FUNCTION__,
        BindParameters->MediaType,
        BindParameters->MacAddressLength,
        BindParameters->AccessType,
        BindParameters->DirectionType,
        BindParameters->ConnectionType);

    Data = (PDRIVER_DATA)ProtocolDriverContext;

    Status2 = Adapter_Allocate(
        &Data->Ndis.MemoryManager,
        BindParameters,
        BindContext,
        &Adapter);
    DbgPrint(
        "%s: Adapter_Allocate --> %x\n",
        __FUNCTION__,
        Status2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NT_SUCCESS(Status2),
        NDIS_STATUS_RESOURCES);

    MediumArray = BindParameters->MediaType;

    Adapter->DriverData = Data;

    RtlZeroMemory(&OpenParameters, sizeof(OpenParameters));

    OpenParameters.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
    OpenParameters.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
    OpenParameters.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVISION_1;

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
    DbgPrint(
        "%s: NdisOpenAdapterEx --> %x\n",
        __FUNCTION__,
        Status);

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
    PADAPTER                Adapter = (PADAPTER)ProtocolBindingContext;
    NDIS_HANDLE             AdapterHandle = NULL;
    PADAPTER_CLOSE_CONTEXT  CloseContext = NULL;
    PKEVENT                 UnbindCompletionEvent = NULL;

    AdapterHandle = Adapter->AdapterHandle;

    Adapter->AdapterHandle = NULL;
    Adapter->UnbindContext = UnbindContext;

    if (Assigned(Adapter->DriverData))
    {
        if (NT_SUCCESS(Km_List_FindItem(
            &Adapter->DriverData->AdaptersList,
            Adapter,
            UnbindAdapter_SearchCallback,
            NULL)))
        {
            Km_List_RemoveItem(
                &Adapter->DriverData->AdaptersList,
                &Adapter->Link);
        }
    }

    Km_Lock_Acquire(&Adapter->Lock);
    __try
    {
        UnbindCompletionEvent = Adapter->AdapterUnbindCompletionEvent;
    }
    __finally
    {
        Km_Lock_Release(&Adapter->Lock);
    }

    while ((Adapter->PendingOidRequests > 0) ||
        (Adapter->PendingSendPackets > 0))
    {
        DriverSleep(50);
    }

    CloseContext = Km_MM_AllocMemTyped(
        &Adapter->DriverData->Ndis.MemoryManager,
        ADAPTER_CLOSE_CONTEXT);
    if (Assigned(CloseContext))
    {
        KeInitializeEvent(
            &CloseContext->CompletionEvent,
            NotificationEvent,
            FALSE);
        CloseContext->MemoryManager = &Adapter->DriverData->Ndis.MemoryManager;
        Adapter->CloseContext = CloseContext;
    }

    NDIS_STATUS NdisStatus = NdisCloseAdapterEx(AdapterHandle);

    if (Assigned(CloseContext))
    {
        KeWaitForSingleObject(
            (PVOID)(&CloseContext->CompletionEvent),
            Executive,
            KernelMode,
            FALSE,
            NULL);
        Km_MM_FreeMem(
            CloseContext->MemoryManager,
            CloseContext);
    }

    if (NdisStatus == NDIS_STATUS_PENDING)
    {
        NdisStatus = NDIS_STATUS_SUCCESS;
    }

    if (Assigned(UnbindCompletionEvent))
    {
        KeSetEvent(UnbindCompletionEvent, 0, FALSE);
    }

    return NdisStatus;
};

void
_Function_class_(PROTOCOL_OPEN_ADAPTER_COMPLETE_EX)
Protocol_OpenAdapterCompleteHandlerEx(
    __in    NDIS_HANDLE ProtocolBindingContext,
    __in    NDIS_STATUS Status)
{
    PADAPTER    Adapter = (PADAPTER)ProtocolBindingContext;

    if (Status == NDIS_STATUS_SUCCESS)
    {
        SendOidRequest(
            Adapter,
            FALSE,
            OID_GEN_VENDOR_DESCRIPTION,
            Adapter->DisplayName,
            sizeof(Adapter->DisplayName) - 1);

        if (Assigned(Adapter->DriverData))
        {
            Km_List_AddItem(
                &Adapter->DriverData->AdaptersList,
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
    PADAPTER    Adapter = (PADAPTER)ProtocolBindingContext;

    DEBUGP_FUNC_ENTER(DL_TRACE);

    if (Assigned(Adapter->UnbindContext))
    {
        NdisCompleteUnbindAdapterEx(Adapter->UnbindContext);
    }

    if (Assigned(Adapter->CloseContext))
    {
        KeSetEvent(
            &Adapter->CloseContext->CompletionEvent,
            0,
            FALSE);
    }

    FreeAdapter(Adapter);

    DEBUGP_FUNC_LEAVE(DL_TRACE);
};

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
        if (Status == NDIS_STATUS_SUCCESS)
        {
            Adapter->DisplayNameSize = OidRequest->DATA.QUERY_INFORMATION.BytesWritten;
        }

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

void
_Function_class_(PROTOCOL_RECEIVE_NET_BUFFER_LISTS)
Protocol_ReceiveNetBufferListsHandler(
    NDIS_HANDLE             ProtocolBindingContext,
    PNET_BUFFER_LIST        NetBufferLists,
    NDIS_PORT_NUMBER        PortNumber,
    ULONG                   NumberOfNetBufferLists,
    ULONG                   ReceiveFlags)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PADAPTER    Adapter = (PADAPTER)ProtocolBindingContext;
    ULONG       ReturnFlags = 0;
    LIST_ENTRY  TmpPacketList;

    UNREFERENCED_PARAMETER(PortNumber);

    RETURN_IF_TRUE(DriverData.DriverUnload);

    RETURN_IF_FALSE(
        (Assigned(NetBufferLists)) &&
        (NumberOfNetBufferLists > 0));

    if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
    {
        NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
    }

    RETURN_IF_FALSE(
        (Assigned(Adapter)) &&
        (Adapter->AdapterHandle != NULL));

    RETURN_IF_FALSE_EX(
        (Adapter->Ready) &&
        (Assigned(Adapter->WorkerThread)),
        NdisReturnNetBufferLists(
            Adapter->AdapterHandle,
            NetBufferLists, 
            ReturnFlags));

    InitializeListHead(&TmpPacketList);

    Status = Km_Lock_Acquire(&Adapter->Lock);
    RETURN_IF_FALSE_EX(
        NT_SUCCESS(Status),
        NdisReturnNetBufferLists(
            Adapter->AdapterHandle,
            NetBufferLists,
            ReturnFlags));
    __try
    {
        PNET_BUFFER_LIST    CurrentNbl;
        KM_TIME             PacketTimeStamp = { 0, };

        GetAdapterTime(
            Adapter,
            &PacketTimeStamp);

        for (CurrentNbl = NetBufferLists;
            Assigned(CurrentNbl);
            CurrentNbl = NET_BUFFER_LIST_NEXT_NBL(CurrentNbl))
        {
            PUCHAR              MdlVA = NULL;
            PNET_BUFFER         NB = NET_BUFFER_LIST_FIRST_NB(CurrentNbl);
            PMDL                Mdl = NET_BUFFER_CURRENT_MDL(NB);
            ULONG               Offset = NET_BUFFER_DATA_OFFSET(NB);
            ULONG               BufferLength = 0;

            if (Assigned(Mdl))
            {
                PPACKET     NewPacket = NULL;

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

                NetEventInfo_FillFromBuffer(
                    (PVOID)(MdlVA + Offset),
                    BufferLength,
                    &Adapter->CurrentEventInfo);

                Km_Connections_GetPIDForPacket(
                    Adapter->DriverData->Other.Connections,
                    &Adapter->CurrentEventInfo,
                    &Adapter->CurrentEventInfo.Process.Id);

                //  We may loose certain extra-large packets here
                //  (the ones exceeding the size of the mem pool entry

                Status = Adapter_AllocateAndFillPacket(
                    Adapter,
                    MdlVA + Offset,
                    BufferLength,
                    Adapter->CurrentEventInfo.Process.Id,
                    &PacketTimeStamp,
                    &NewPacket);

                CONTINUE_IF_FALSE(NT_SUCCESS(Status));

                InsertTailList(
                    &TmpPacketList,
                    &NewPacket->Link);
            }
        }

        LEAVE_IF_TRUE(IsListEmpty(&TmpPacketList));

        Km_List_Lock(&Adapter->Packets.Allocated);
        __try
        {
            ULARGE_INTEGER  NumberOfPacketsInQueue = { 0 };

            Km_List_GetCountEx(
                &Adapter->Packets.Allocated, 
                &NumberOfPacketsInQueue, 
                FALSE, 
                FALSE);
            
            Km_List_AddLinkedListEx(
                &Adapter->Packets.Allocated,
                &TmpPacketList,
                TRUE,
                FALSE);

            if (NumberOfPacketsInQueue.QuadPart == 0)
            {
                KeSetEvent(&Adapter->Packets.NewPacketEvent, 0, FALSE);
            }
        }
        __finally
        {
            Km_List_Unlock(&Adapter->Packets.Allocated);
        }
    }
    __finally
    {
        Km_Lock_Release(&Adapter->Lock);
    }
    
    if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
    {
        NdisReturnNetBufferLists(Adapter->AdapterHandle, NetBufferLists, ReturnFlags);
    }
};

void
_Function_class_(PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE)
Protocol_SendNetBufferListsCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    PNET_BUFFER_LIST    NetBufferList,
    __in    ULONG               SendCompleteFlags)
{
    PNET_BUFFER_LIST    CurrentNBL = NetBufferList;
    PNET_BUFFER_LIST    NextNBL = NULL;
    PNET_BUFFER         NetBuffer = NULL;

    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(SendCompleteFlags);

    DEBUGP_FUNC_ENTER(DL_TRACE);

    while (Assigned(CurrentNBL))
    {
        __try
        {
            NextNBL = NET_BUFFER_LIST_NEXT_NBL(CurrentNBL);

            NetBuffer = NET_BUFFER_LIST_FIRST_NB(CurrentNBL);

            if (NET_BUFFER_LIST_INFO(CurrentNBL, Ieee8021QNetBufferListInfo) != 0)
            {
                DEBUGP(DL_TRACE, "!!! 802.11Q !!!\n");
            }

            if (Assigned(NetBuffer))
            {
                ULONG   NBDataSize = NET_BUFFER_DATA_LENGTH(NetBuffer);
                NdisAdvanceNetBufferDataStart(NetBuffer, NBDataSize, FALSE, NULL);
            }
        }
        __finally
        {
            NdisFreeNetBufferList(CurrentNBL);
            CurrentNBL = NextNBL;
        }
    };

    DEBUGP_FUNC_LEAVE(DL_TRACE);
};

NDIS_STATUS
_Function_class_(SET_OPTIONS)
Protocol_SetOptionsHandler(
    __in    NDIS_HANDLE NdisDriverHandle,
    __in    NDIS_HANDLE DriverContext)
{
    UNREFERENCED_PARAMETER(NdisDriverHandle);
    UNREFERENCED_PARAMETER(DriverContext);
    return NDIS_STATUS_SUCCESS;
};

NDIS_STATUS
_Function_class_(PROTOCOL_NET_PNP_EVENT)
Protocol_NetPnPEventHandler(
    __in    NDIS_HANDLE                 ProtocolBindingContext,
    __in    PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);

    DEBUGP_FUNC_ENTER(DL_TRACE);

    GOTO_CLEANUP_IF_FALSE(Assigned(NetPnPEventNotification));

    DEBUGP(
        DL_TRACE,
        "    NetEvent: %s",
        NetEventString(NetPnPEventNotification->NetPnPEvent.NetEvent));

    switch (NetPnPEventNotification->NetPnPEvent.NetEvent)
    {
    case NetEventBindsComplete:
        {
            DEBUGP(DL_TRACE, "    finished binding adapters!\n");
        }break;

    case NetEventSetPower:
        {
            DEBUGP(DL_TRACE, "    power up adapter\n");
        }break;

    case NetEventReconfigure:
        {
            DEBUGP(
                DL_TRACE, 
                "    reconfiguration event, context = %p\n", 
                (PVOID)ProtocolBindingContext);

            if ((ProtocolBindingContext == NULL) &&
                (DriverData.Ndis.ProtocolHandle != NULL) &&
                (!DriverData.DriverUnload))
            {
                NdisReEnumerateProtocolBindings(DriverData.Ndis.ProtocolHandle);
            }
            
        }break;

    case NetEventBindFailed:
        {
            DEBUGP(DL_TRACE, "    binding failed\n");
        }break;
    };

cleanup:

    DEBUGP_FUNC_LEAVE(DL_TRACE);

    return NDIS_STATUS_SUCCESS;
};

void
_Function_class_(PROTOCOL_UNINSTALL)
Protocol_UninstallHandler()
{
};

void
_Function_class_(PROTOCOL_STATUS_EX)
Protocol_StatusHandlerEx(
    __in    NDIS_HANDLE             ProtocolBindingContext,
    __in    PNDIS_STATUS_INDICATION StatusIndication)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(StatusIndication);
};

void
_Function_class_(PROTOCOL_DIRECT_OID_REQUEST_COMPLETE)
Protocol_DirectOidRequestCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    PNDIS_OID_REQUEST   OidRequest,
    __in    NDIS_STATUS         Status)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(OidRequest);
    UNREFERENCED_PARAMETER(Status);
};