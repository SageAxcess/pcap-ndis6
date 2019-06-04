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
#include "KmTree.h"
#include "KmMREWLock.h"

#include "KmMemoryTags.h"

#define KM_CONNECTIONS_ITEM_LIFETIME    300

typedef struct _KM_CONNECTIONS_ITEM
{
    LIST_ENTRY          Link;

    LARGE_INTEGER       LastAccessTime;

    NET_EVENT_INFO      Info;

} KM_CONNECTIONS_ITEM, *PKM_CONNECTIONS_ITEM;

typedef struct _KM_CONNECTIONS_TREE_INDEX
{
    LIST_ENTRY  Link;

    int         First;

    int         Second;

} KM_CONNECTIONS_TREE_INDEX, *PKM_CONNECTIONS_TREE_INDEX;

typedef struct _KM_CONNECTIONS_DATA
{
    KM_MREW_LOCK        Lock;

    PKM_MEMORY_MANAGER  MemoryManager;

    HANDLE              MemoryPool;

    PKM_THREAD          TimeoutWatcher;

    struct _TREES
    {
        /*
            The first dimension represents the eth protocol type
            0 Index means ETH_P_IP and 1 means ETH_P_IP6.

            The second dimension represents the IP protocol type
            (one of IPPROTO_XXX values).
        */
        PKM_TREE            Items[2][IPPROTO_COUNT];

        struct _INDEXES
        {
            //  Memory pool for the list items
            HANDLE      MemoryPool;

            //  List of indexes
            LIST_ENTRY  List;

            /*
                Contains a linked list with indexes of allocated data trees
            */
        } Indexes;

    } Trees;

} KM_CONNECTIONS_DATA, *PKM_CONNECTIONS_DATA;

#define EthTypeToIndex(Value)   \
    ((((Value) == ETH_TYPE_IP) || (Value) == ETH_TYPE_IP_BE) ? 0 : \
     (((Value) == ETH_TYPE_IP6) || (Value) == ETH_TYPE_IP6_BE) ? 1 : \
     -1)

#define EthIndexValid(Value)        (((Value) >= 0) && ((Value) < 1))
#define IpProtoIndexValid(Value)    (((Value) >= 0) && ((Value) < IPPROTO_COUNT))

void __stdcall Km_Connections_OnTreeItemRemove(
    __in    PKM_TREE    Tree,
    __in    PVOID       TreeContext,
    __in    PVOID       Buffer,
    __in    ULONG       BufferSize)
{
    PKM_CONNECTIONS_ITEM    Item = NULL;

    UNREFERENCED_PARAMETER(Tree);
    UNREFERENCED_PARAMETER(TreeContext);
    UNREFERENCED_PARAMETER(BufferSize);

    RETURN_IF_FALSE(Assigned(Buffer));

    Item = CONTAINING_RECORD(
        Buffer, 
        KM_CONNECTIONS_ITEM, 
        Info);

    Km_MP_Release(Item);
};

int __stdcall Km_Connections_OnTreeItemCompare(
    __in    PKM_TREE        Tree,
    __in    PVOID           TreeContext,
    __in    PVOID           Buffer1,
    __in    ULONG           BufferSize1,
    __in    PVOID           Buffer2,
    __in    ULONG           BufferSize2)
{
    UNREFERENCED_PARAMETER(Tree);
    UNREFERENCED_PARAMETER(TreeContext);
    UNREFERENCED_PARAMETER(BufferSize1);
    UNREFERENCED_PARAMETER(BufferSize2);

    if ((Assigned(Buffer1)) &&
        (Assigned(Buffer2)))
    {
        PNET_EVENT_INFO Info1 = (PNET_EVENT_INFO)Buffer1;
        PNET_EVENT_INFO Info2 = (PNET_EVENT_INFO)Buffer2;
        int             CmpRes;

        CmpRes = KmTree_CompareValues(Info1->Local.TransportSpecific, Info2->Local.TransportSpecific);
        if (CmpRes == GenericEqual)
        {
            CmpRes = KmTree_CompareValues(Info1->Remote.TransportSpecific, Info2->Remote.TransportSpecific);
            if (CmpRes == GenericEqual)
            {
                size_t  CmpSize =
                    EthTypeToAddressFamily(Info1->EthType) == AF_INET ?
                    sizeof(IP_ADDRESS_V4) :
                    sizeof(IP_ADDRESS_V6);

                int     MemCmpRes = memcmp(
                    &Info1->Local.IpAddress,
                    &Info2->Local.IpAddress,
                    CmpSize);
                CmpRes = KmTree_StdCmpResToGeneric(MemCmpRes);

                if (CmpRes == GenericEqual)
                {
                    MemCmpRes = memcmp(
                        &Info1->Remote.IpAddress,
                        &Info2->Remote.IpAddress,
                        CmpSize);
                    CmpRes = KmTree_StdCmpResToGeneric(MemCmpRes);
                }
            }
        }

        return CmpRes;
    }

    return KmTree_CompareValues(Buffer1, Buffer2);
};

NTSTATUS __stdcall Km_Connections_AddNewTree(
    __in        PKM_CONNECTIONS_DATA    Data,
    __in        int                     EthIndex,
    __in        int                     IpProtoIndex,
    __out_opt   PKM_TREE                *Tree)
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    PKM_TREE                    NewTree = NULL;
    PKM_CONNECTIONS_TREE_INDEX  IndexItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        EthIndexValid(EthIndex),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        IpProtoIndexValid(IpProtoIndex),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_TRUE_SET_STATUS(
        Assigned(Data->Trees.Items[EthIndex][IpProtoIndex]),
        STATUS_UNSUCCESSFUL);

    Status = Km_MP_Allocate(
        Data->Trees.Indexes.MemoryPool,
        sizeof(KM_CONNECTIONS_TREE_INDEX),
        (PVOID *)&IndexItem);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = KmTree_InitializeEx(
            Data->MemoryManager,
            Km_Connections_OnTreeItemCompare,
            Km_Connections_OnTreeItemRemove,
            FALSE,
            Data,
            0,
            &NewTree);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Data->Trees.Items[EthIndex][IpProtoIndex] = NewTree;

        LEAVE_IF_FALSE(Assigned(Tree));

        *Tree = NewTree;
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            Km_MP_Release(IndexItem);
        }
        else
        {
            IndexItem->First = EthIndex;
            IndexItem->Second = IpProtoIndex;
            InsertTailList(
                &Data->Trees.Indexes.List,
                &IndexItem->Link);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_CleanupOldEntries(
    __in    PKM_CONNECTIONS_DATA    Data)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    LARGE_INTEGER   CurrentTime = { 0 };

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);

    KeQuerySystemTime(&CurrentTime);

    Status = Km_MREW_Lock_AcquireWrite(&Data->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PKM_CONNECTIONS_ITEM        ConnItem;
        LARGE_INTEGER               TimeDiff;
        LARGE_INTEGER               TimeInSeconds;
        PLIST_ENTRY                 Entry = NULL;
        PVOID                       Item = NULL;
        PKM_CONNECTIONS_TREE_INDEX  IndexItem = NULL;
        PKM_TREE                    Tree;

        for (Entry = Data->Trees.Indexes.List.Flink;
            Entry != &Data->Trees.Indexes.List;
            Entry = Entry->Flink)
        {
            IndexItem = CONTAINING_RECORD(
                Entry,
                KM_CONNECTIONS_TREE_INDEX,
                Link);

            Tree = Data->Trees.Items[IndexItem->First][IndexItem->Second];

            CONTINUE_IF_FALSE(Assigned(Tree));

            for (Status = KmTree_EnumerateEntries_NoLock(Tree, &Item);
                NT_SUCCESS(Status) && (Item != NULL);
                Status = KmTree_EnumerateEntries_NoLock(Tree, &Item))
            {
                ConnItem = CONTAINING_RECORD(Item, KM_CONNECTIONS_ITEM, Info);

                TimeDiff = RtlLargeIntegerSubtract(CurrentTime, ConnItem->LastAccessTime);

                //  Note:
                //  The time difference is not in nanoseconds, but in 100 nanosecond intervals.
                //  In other word if TimeInSeconds == 1, then it should be treated as 100.
                TimeInSeconds.QuadPart = NanosecondsToMiliseconds(TimeDiff.QuadPart);

                if (TimeInSeconds.QuadPart > KM_CONNECTIONS_ITEM_LIFETIME)
                {
                    KmTree_DeleteItem_NoLock(Tree, Item);
                }
            }
        }
    }
    __finally
    {
        Km_MREW_Lock_ReleaseWrite(&Data->Lock);
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

    InitializeListHead(&NewData->Trees.Indexes.List);

    MPBlockDef.BlockCount = 0xF;
    MPBlockDef.BlockSize = sizeof(KM_CONNECTIONS_TREE_INDEX);
    MPBlockDef.MemoryTag = KM_CONNECTIONS_SVC_MEMORY_TAG;
    MPBlockDef.Type = LookasideList;

    Status = Km_MP_Initialize(
        MemoryManager,
        &MPBlockDef,
        1,
        KM_MEMORY_POOL_FLAG_DEFAULT,
        KM_CONNECTIONS_SVC_MEMORY_TAG,
        &NewData->Trees.Indexes.MemoryPool);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    MPBlockDef.BlockCount = KM_CONNECTIONS_INITIAL_POOL_SIZE;
    MPBlockDef.BlockSize = sizeof(KM_CONNECTIONS_ITEM);
    MPBlockDef.MemoryTag = KM_CONNECTIONS_MEMORY_POOL_TAG;
    MPBlockDef.Type = LookasideList;

    Status = Km_MP_Initialize(
        MemoryManager,
        &MPBlockDef,
        1,
        KM_MEMORY_POOL_FLAG_DYNAMIC | KM_MEMORY_POOL_FLAG_LOOKASIDE,
        KM_CONNECTIONS_MEMORY_POOL_TAG,
        &NewData->MemoryPool);
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

    NewData->MemoryManager = MemoryManager;

    *Instance = (HANDLE)NewData;

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewData))
        {
            if (Assigned(NewData->TimeoutWatcher))
            {
                KmThreads_StopThread(NewData->TimeoutWatcher, (ULONG)(-1));
                KmThreads_WaitForThread(NewData->TimeoutWatcher);
                KmThreads_DestroyThread(NewData->TimeoutWatcher);
            }

            if (NewData->Trees.Indexes.MemoryPool != NULL)
            {
                Km_MP_Finalize(NewData->Trees.Indexes.MemoryPool);
            }

            if (NewData->MemoryPool != NULL)
            {
                Km_MP_Finalize(NewData->MemoryPool);
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
    NTSTATUS                    Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA        Data = NULL;
    PKM_CONNECTIONS_TREE_INDEX  IndexItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    Status = Km_MREW_Lock_AcquireWrite(&Data->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        if (Assigned(Data->TimeoutWatcher))
        {
            KmThreads_StopThread(Data->TimeoutWatcher, (ULONG)(-1));
            KmThreads_WaitForThread(Data->TimeoutWatcher);
            KmThreads_DestroyThread(Data->TimeoutWatcher);
        }

        while (!IsListEmpty(&Data->Trees.Indexes.List))
        {
            IndexItem = CONTAINING_RECORD(
                RemoveHeadList(&Data->Trees.Indexes.List),
                KM_CONNECTIONS_TREE_INDEX,
                Link);
            __try
            {
                KmTree_Clear_NoLock(Data->Trees.Items[IndexItem->First][IndexItem->Second]);
                KmTree_Finalize(Data->Trees.Items[IndexItem->First][IndexItem->Second]);
            }
            __finally
            {
                Km_MP_Release(IndexItem);
            }
        };

        if (Data->Trees.Indexes.MemoryPool != NULL)
        {
            Km_MP_Finalize(Data->Trees.Indexes.MemoryPool);
        }

        if (Data->MemoryPool != NULL)
        {
            Km_MP_Finalize(Data->MemoryPool);
        }
    }
    __finally
    {
        Km_MREW_Lock_ReleaseWrite(&Data->Lock);
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
    PKM_TREE                Tree = NULL;
    int                     EthIndex;
    int                     IpProtoIndex;
    BOOLEAN                 TreeAdded = FALSE;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);

    EthIndex = EthTypeToIndex(Info->EthType);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        EthIndexValid(EthIndex),
        STATUS_NOT_SUPPORTED);

    IpProtoIndex = Info->IpProtocol;
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        IpProtoIndexValid(IpProtoIndex),
        STATUS_NOT_SUPPORTED);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    Status = Km_MREW_Lock_AcquireWrite(&Data->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Tree = Data->Trees.Items[EthIndex][IpProtoIndex];

        if (!Assigned(Tree))
        {
            Status = Km_Connections_AddNewTree(
                Data,
                EthIndex,
                IpProtoIndex,
                &Tree);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            TreeAdded = TRUE;
        }

        if (!TreeAdded)
        {
            Status = KmTree_FindItem_NoLock(
                Tree,
                Info,
                sizeof(NET_EVENT_INFO),
                NULL,
                NULL);
            LEAVE_IF_TRUE_SET_STATUS(
                NT_SUCCESS(Status),
                STATUS_UNSUCCESSFUL);
        }

        Status = Km_Connections_AllocateItem(
            Data->MemoryPool,
            Info,
            &NewItem);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Status = KmTree_AddItem_NoLock(
            Tree, 
            &NewItem->Info, 
            sizeof(NET_EVENT_INFO));
        if (!NT_SUCCESS(Status))
        {
            Km_MP_Release(NewItem);
        }
    }
    __finally
    {
        Km_MREW_Lock_ReleaseWrite(&Data->Lock);
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
    PKM_TREE                Tree = NULL;
    int                     EthIndex;
    int                     IpProtoIndex;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);
    
    EthIndex = EthTypeToIndex(Info->EthType);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        EthIndexValid(EthIndex),
        STATUS_NOT_SUPPORTED);

    IpProtoIndex = Info->IpProtocol;
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        IpProtoIndexValid(IpProtoIndex),
        STATUS_NOT_SUPPORTED);

    Data = (PKM_CONNECTIONS_DATA)Instance;
    
    Status = Km_MREW_Lock_AcquireWrite(&Data->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Tree = Data->Trees.Items[EthIndex][IpProtoIndex];
        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_NOT_FOUND);

        Status = KmTree_DeleteItem_NoLock(Tree, Info);
    }
    __finally
    {
        Km_MREW_Lock_ReleaseWrite(&Data->Lock);
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
    PNET_EVENT_INFO         FoundInfo = NULL;
    PKM_CONNECTIONS_ITEM    Item = NULL;
    NET_EVENT_INFO          RevInfo;
    PKM_TREE                Tree;
    int                     EthIndex;
    int                     IpProtoIndex;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ProcessId),
        STATUS_INVALID_PARAMETER_3);

    EthIndex = EthTypeToIndex(Info->EthType);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        EthIndexValid(EthIndex),
        STATUS_NOT_SUPPORTED);

    IpProtoIndex = Info->IpProtocol;
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        IpProtoIndexValid(IpProtoIndex),
        STATUS_NOT_SUPPORTED);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    Status = Km_MREW_Lock_AcquireRead(&Data->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Tree = Data->Trees.Items[EthIndex][IpProtoIndex];
        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_NOT_FOUND);

        Status = KmTree_FindItem_NoLock(
            Tree,
            Info,
            sizeof(NET_EVENT_INFO),
            &FoundInfo,
            NULL);

        if (Status == STATUS_NOT_FOUND)
        {
            RevInfo.EthType = Info->EthType;
            RevInfo.IpProtocol = Info->IpProtocol;
            RevInfo.Local = Info->Remote;
            RevInfo.Remote = Info->Local;

            Status = KmTree_FindItem_NoLock(
                Tree,
                &RevInfo,
                sizeof(NET_EVENT_INFO),
                &FoundInfo,
                NULL);
        };

        if (NT_SUCCESS(Status))
        {
            *ProcessId = FoundInfo->Process.Id;

            Item = CONTAINING_RECORD(FoundInfo, KM_CONNECTIONS_ITEM, Info);

            KeQuerySystemTime(&Item->LastAccessTime);
        }
    }
    __finally
    {
        Km_MREW_Lock_ReleaseRead(&Data->Lock);
    }

cleanup:
    return Status;
};