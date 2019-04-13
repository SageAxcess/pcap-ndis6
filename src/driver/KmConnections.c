//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2019 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include "KmConnections.h"
#include "KmTypes.h"
#include "KmMemoryPool.h"
#include "KmThreads.h"

#include "KmMemoryTags.h"

#define KM_CONNECTIONS_ITEM_LIFETIME    300

typedef struct _KM_CONNECTIONS_ITEM
{
    LIST_ENTRY          Link;

    LARGE_INTEGER       LastAccessTime;

    NET_EVENT_INFO      Info;

} KM_CONNECTIONS_ITEM, *PKM_CONNECTIONS_ITEM;

typedef struct _KM_CONNECTIONS_DATA
{
    KM_LIST             List;

    PKM_MEMORY_MANAGER  MemoryManager;

    HANDLE              MemoryPool;

    PKM_THREAD          TimeoutWatcher;

} KM_CONNECTIONS_DATA, *PKM_CONNECTIONS_DATA;

NTSTATUS __stdcall Km_Connections_CleanupOldEntries(
    __in    PKM_CONNECTIONS_DATA    Data)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    LARGE_INTEGER   CurrentTime = { 0 };

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);

    KeQuerySystemTime(&CurrentTime);

    Km_List_Lock(&Data->List);
    __try
    {
        PLIST_ENTRY     Entry;
        PLIST_ENTRY     NextEntry;
        LARGE_INTEGER   TimeDiff;
        LARGE_INTEGER   TimeInSeconds;

        for (Entry = Data->List.Head.Flink, NextEntry = Entry->Flink;
            Entry != &Data->List.Head;
            Entry = NextEntry, NextEntry = NextEntry->Flink)
        {
            PKM_CONNECTIONS_ITEM    Item = 
                CONTAINING_RECORD(
                    Entry, 
                    KM_CONNECTIONS_ITEM, 
                    Link);

            TimeDiff = RtlLargeIntegerSubtract(CurrentTime, Item->LastAccessTime);

            //  Note:
            //  The time difference is not in nanoseconds, but in 100 nanosecond intervals.
            //  In other word if TimeInSeconds == 1, then it should be treated as 100.
            TimeInSeconds.QuadPart = NanosecondsToMiliseconds(TimeDiff.QuadPart);

            if (TimeInSeconds.QuadPart > KM_CONNECTIONS_ITEM_LIFETIME)
            {
                Km_List_RemoveItemEx(
                    &Data->List,
                    Entry,
                    FALSE,
                    FALSE);
                Km_MP_Release(Entry);
            }
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

cleanup:
    return Status;
};

void __stdcall Km_Connections_TimeoutWatcher_ThreadProc(
    __in    PKM_THREAD  Thread)
{
    PKM_CONNECTIONS_DATA    Data = NULL;
    BOOLEAN                 StopThread = FALSE;
    NTSTATUS                WaitStatus = STATUS_SUCCESS;
    LARGE_INTEGER           Timeout;

    GOTO_CLEANUP_IF_FALSE(Assigned(Thread));
    GOTO_CLEANUP_IF_FALSE(Assigned(Thread->Context));

    Data = (PKM_CONNECTIONS_DATA)Thread->Context;

    //  The interval is in 100-nanoseconds
    Timeout.QuadPart = (-1) * (MilisecondsToNanoseconds(30000) / 100);

    while (!StopThread)
    {
        WaitStatus = KeWaitForSingleObject(
            &Thread->StopEvent,
            Executive,
            KernelMode,
            FALSE,
            &Timeout);

        switch (WaitStatus)
        {
            case STATUS_TIMEOUT:
            {
                Km_Connections_CleanupOldEntries(Data);
            }break;

            default:
            {
                StopThread = TRUE;
            }break;
        };
    }

cleanup:
    return;
};

int __stdcall Km_Connections_GetPID_ItemCmpCallback(
    __in    PKM_LIST    List,
    __in    PVOID       ItemDefinition,
    __in    PLIST_ENTRY Item)
{
    PKM_CONNECTIONS_ITEM    ConnItem = CONTAINING_RECORD(Item, KM_CONNECTIONS_ITEM, Link);
    PNET_EVENT_INFO         EventInfo = (PNET_EVENT_INFO)ItemDefinition;

    UNREFERENCED_PARAMETER(List);

    if ((Assigned(ConnItem)) &&
        (Assigned(EventInfo)))
    {
        int CmpRes = COMPARE_VALUES(EventInfo->EthType, ConnItem->Info.EthType);
        if (CmpRes == 0)
        {
            CmpRes = COMPARE_VALUES(EventInfo->IpProtocol, ConnItem->Info.IpProtocol);
            if (CmpRes == 0)
            {
                //  1st pass

                #pragma region STD_COMPARE
                CmpRes = COMPARE_VALUES(EventInfo->Local.TransportSpecific, ConnItem->Info.Local.TransportSpecific);
                if (CmpRes == 0)
                {
                    CmpRes = COMPARE_VALUES(EventInfo->Remote.TransportSpecific, ConnItem->Info.Remote.TransportSpecific);
                    if (CmpRes == 0)
                    {
                        size_t  CmpSize = 
                            EthTypeToAddressFamily(EventInfo->EthType) == AF_INET ?
                            sizeof(IP_ADDRESS_V4) :
                            sizeof(IP_ADDRESS_V6);

                        CmpRes = memcmp(
                            &EventInfo->Local.IpAddress,
                            &ConnItem->Info.Local.IpAddress,
                            CmpSize);

                        if (CmpRes == 0)
                        {
                            CmpRes = memcmp(
                                &EventInfo->Remote.IpAddress,
                                &ConnItem->Info.Remote.IpAddress,
                                CmpSize);
                        }
                    }
                }
                #pragma endregion

                //  2nd pass

                #pragma region REVERESE_COMPARE
                if (CmpRes != 0)
                {
                    CmpRes = COMPARE_VALUES(EventInfo->Remote.TransportSpecific, ConnItem->Info.Local.TransportSpecific);
                    if (CmpRes == 0)
                    {
                        CmpRes = COMPARE_VALUES(EventInfo->Local.TransportSpecific, ConnItem->Info.Remote.TransportSpecific);
                        if (CmpRes == 0)
                        {
                            size_t  CmpSize =
                                EthTypeToAddressFamily(EventInfo->EthType) == AF_INET ? 
                                sizeof(IP_ADDRESS_V4) :
                                sizeof(IP_ADDRESS_V6);

                            CmpRes = memcmp(
                                &EventInfo->Remote.IpAddress,
                                &ConnItem->Info.Local.IpAddress,
                                CmpSize);

                            if (CmpRes == 0)
                            {
                                CmpRes = memcmp(
                                    &EventInfo->Local.IpAddress,
                                    &ConnItem->Info.Remote.IpAddress,
                                    CmpSize);
                            }
                        }
                    }
                }
                #pragma endregion
            }
        }

        return CmpRes;
    }

    return COMPARE_VALUES(ItemDefinition, (PVOID)Item);
};

int __stdcall Km_Connections_ItemCmpCallback(
    __in    PKM_LIST    List,
    __in    PVOID       ItemDefinition,
    __in    PLIST_ENTRY Item)
{
    PKM_CONNECTIONS_ITEM    ConnItem = CONTAINING_RECORD(Item, KM_CONNECTIONS_ITEM, Link);
    PNET_EVENT_INFO         EventInfo = (PNET_EVENT_INFO)ItemDefinition;

    UNREFERENCED_PARAMETER(List);

    if ((Assigned(ConnItem)) &&
        (Assigned(EventInfo)))
    {
        int CmpRes = COMPARE_VALUES(EventInfo->EthType, ConnItem->Info.EthType);
        if (CmpRes == 0)
        {
            CmpRes = COMPARE_VALUES(EventInfo->IpProtocol, ConnItem->Info.IpProtocol);
            if (CmpRes == 0)
            {
                CmpRes = COMPARE_VALUES(EventInfo->Local.TransportSpecific, ConnItem->Info.Local.TransportSpecific);
                if (CmpRes == 0)
                {
                    CmpRes = COMPARE_VALUES(EventInfo->Remote.TransportSpecific, ConnItem->Info.Remote.TransportSpecific);
                    if (CmpRes == 0)
                    {
                        size_t  CmpSize =
                            EthTypeToAddressFamily(EventInfo->EthType) == AF_INET ?
                            sizeof(IP_ADDRESS_V4) :
                            sizeof(IP_ADDRESS_V6);

                        CmpRes = memcmp(
                            &EventInfo->Local.IpAddress,
                            &ConnItem->Info.Local.IpAddress,
                            CmpSize);
                        if (CmpRes == 0)
                        {
                            return memcmp(
                                &EventInfo->Remote.IpAddress,
                                &ConnItem->Info.Remote.IpAddress,
                                CmpSize);
                        }
                    }
                }
            }
        }

        return CmpRes;
    }

    return COMPARE_VALUES(ItemDefinition, (PVOID)Item);
};

NTSTATUS __stdcall Km_Connections_AllocateItem(
    __in    HANDLE                  MemoryPool,
    __in    PNET_EVENT_INFO         Info,
    __out   PKM_CONNECTIONS_ITEM    *Item)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_ITEM    NewItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        MemoryPool != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Item),
        STATUS_INVALID_PARAMETER_3);

    Status = Km_MP_Allocate(
        MemoryPool,
        sizeof(KM_CONNECTIONS_ITEM),
        (PVOID *)&NewItem);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    RtlZeroMemory(
        NewItem,
        sizeof(KM_CONNECTIONS_ITEM));

    RtlCopyMemory(
        &NewItem->Info,
        Info,
        sizeof(NET_EVENT_INFO));

    KeQuerySystemTime(&NewItem->LastAccessTime);

    *Item = NewItem;

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PHANDLE             Instance)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA            NewData = NULL;
    KM_MEMORY_POOL_BLOCK_DEFINITION MPBlockDef;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Instance),
        STATUS_INVALID_PARAMETER_2);

    NewData = Km_MM_AllocMemTypedWithTag(
        MemoryManager,
        KM_CONNECTIONS_DATA,
        KM_CONNECTIONS_OBJECT_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewData),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewData,
        sizeof(KM_CONNECTIONS_DATA));

    Status = Km_List_Initialize(&NewData->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = KmThreads_CreateThread(
        MemoryManager,
        &NewData->TimeoutWatcher,
        Km_Connections_TimeoutWatcher_ThreadProc,
        NewData);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    RtlZeroMemory(
        &MPBlockDef,
        sizeof(MPBlockDef));

    MPBlockDef.BlockSize = (ULONG)sizeof(KM_CONNECTIONS_ITEM);
    MPBlockDef.BlockCount = KM_CONNECTIONS_INITIAL_POOL_SIZE;
    MPBlockDef.Type = LookasideList;
    MPBlockDef.MemoryTag = KM_CONNECTIONS_MEMORY_POOL_TAG;

    Status = Km_MP_Initialize(
        MemoryManager,
        &MPBlockDef,
        1,
        KM_MEMORY_POOL_FLAG_DEFAULT,
        KM_CONNECTIONS_MEMORY_POOL_TAG,
        &NewData->MemoryPool);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewData->MemoryManager = MemoryManager;

    *Instance = (HANDLE)NewData;

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewData))
        {
            if (NewData->MemoryPool != NULL)
            {
                Km_MP_Finalize(NewData->MemoryPool);
            }

            if (Assigned(NewData->TimeoutWatcher))
            {
                KmThreads_StopThread(NewData->TimeoutWatcher, (ULONG)(-1));
                KmThreads_WaitForThread(NewData->TimeoutWatcher);
                KmThreads_DestroyThread(NewData->TimeoutWatcher);
            }

            Km_MM_FreeMem(
                MemoryManager,
                NewData);
        }
    }

    return Status;
};

NTSTATUS __stdcall Km_Connections_Finalize(
    __in    HANDLE  Instance)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    ULARGE_INTEGER          Count;
    PKM_CONNECTIONS_DATA    Data = NULL;
    LIST_ENTRY              TmpList;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    InitializeListHead(&TmpList);

    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Count.QuadPart = MAXULONGLONG;
        Km_List_ExtractEntriesEx(
            &Data->List,
            &TmpList,
            &Count,
            FALSE,
            FALSE);
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

    while (!IsListEmpty(&TmpList))
    {
        PKM_CONNECTIONS_ITEM Item = CONTAINING_RECORD(
            RemoveHeadList(&TmpList),
            KM_CONNECTIONS_ITEM,
            Link);

        Km_MP_Release(Item);
    }

    if (Data->MemoryPool != NULL)
    {
        Km_MP_Finalize(Data->MemoryPool);
    }

    if (Assigned(Data->TimeoutWatcher))
    {
        KmThreads_StopThread(Data->TimeoutWatcher, (ULONG)(-1));
        KmThreads_WaitForThread(Data->TimeoutWatcher);
        KmThreads_DestroyThread(Data->TimeoutWatcher);
    }

    Km_MM_FreeMem(Data->MemoryManager, Data);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_Add(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA    Data = NULL;
    PKM_CONNECTIONS_ITEM    NewItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_FindItemEx(
            &Data->List,
            (PVOID)Info,
            Km_Connections_ItemCmpCallback,
            NULL,
            FALSE,
            FALSE);
        if (Status == STATUS_NOT_FOUND)
        {
            Status = Km_Connections_AllocateItem(
                Data->MemoryPool,
                Info,
                &NewItem);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            Status = Km_List_AddItemEx(
                &Data->List,
                &NewItem->Link,
                FALSE,
                FALSE);
            if (!NT_SUCCESS(Status))
            {
                Km_MP_Release(NewItem);
            }
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_Remove(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA    Data = NULL;
    PLIST_ENTRY             FoundItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);

    Data = (PKM_CONNECTIONS_DATA)Instance;
    
    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_FindItemEx(
            &Data->List,
            (PVOID)Info,
            Km_Connections_ItemCmpCallback,
            &FoundItem,
            FALSE,
            FALSE);

        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Status = Km_List_RemoveItemEx(
            &Data->List,
            FoundItem,
            FALSE,
            FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Km_MP_Release(
            CONTAINING_RECORD(
                FoundItem,
                KM_CONNECTIONS_ITEM,
                Link));
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_GetPIDForPacket(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info,
    __out   PULONGLONG      ProcessId)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA    Data = NULL;
    PLIST_ENTRY             FoundItem = NULL;
    PKM_CONNECTIONS_ITEM    ConnItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ProcessId),
        STATUS_INVALID_PARAMETER_3);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_FindItemEx(
            &Data->List,
            Info,
            Km_Connections_GetPID_ItemCmpCallback,
            &FoundItem,
            FALSE,
            FALSE);
        if (NT_SUCCESS(Status))
        {
            ConnItem = CONTAINING_RECORD(FoundItem, KM_CONNECTIONS_ITEM, Link);
            *ProcessId = ConnItem->Info.Process.Id;
            KeQuerySystemTime(&ConnItem->LastAccessTime);
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

cleanup:
    return Status;
};