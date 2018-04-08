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
        FALSE,
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

void __stdcall ClearAdaptersList_ItemCallback(
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
NTSTATUS GetAdapterTime(
    __in    PADAPTER    Adapter,
    __out   PKM_TIME    Time)
{
    NTSTATUS    Status = STATUS_SUCCESS;
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
        Adapter->OpenCount--;
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
    __in    PKM_LIST    AdaptersList)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    LIST_ENTRY  TmpList;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(AdaptersList),
        STATUS_INVALID_PARAMETER_1);

    InitializeListHead(&TmpList);

    Status = Km_List_Lock(AdaptersList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        ULARGE_INTEGER  Count;
        Count.QuadPart = MAXULONGLONG;

        Km_List_ExtractEntriesEx(
            AdaptersList,
            &TmpList,
            &Count,
            FALSE,
            FALSE);
    }
    __finally
    {
        Km_List_Unlock(AdaptersList);
    }

    while (!IsListEmpty(&TmpList))
    {
        PLIST_ENTRY Entry = RemoveHeadList(&TmpList);
        PADAPTER    Adapter = CONTAINING_RECORD(Entry, ADAPTER, Link);

        NdisUnbindAdapter(Adapter->AdapterHandle);
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

    GOTO_CLEANUP_IF_TRUE_SET_STATUS(
        DriverData.DriverUnload,
        NDIS_STATUS_FAILURE);

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
        NDIS_STATUS_FAILURE);

    Data = (PDRIVER_DATA)ProtocolDriverContext;

    Status2 = Adapter_Allocate(
        &Data->Ndis.MemoryManager,
        BindParameters,
        BindContext,
        &Adapter);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NT_SUCCESS(Status2),
        NDIS_STATUS_RESOURCES);

    Adapter->DriverData = Data;

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
    NDIS_HANDLE AdapterHandle = NULL;

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
    PADAPTER    adapter = (PADAPTER)ProtocolBindingContext;

    DEBUGP(DL_TRACE, "===>Protocol_CloseAdapterCompleteHandlerEx...\n");

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
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(SendCompleteFlags);

    DEBUGP(DL_TRACE, "===>Protocol_SendNetBufferListsCompleteHandler...\n");

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