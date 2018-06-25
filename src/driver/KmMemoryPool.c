//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 ChangeDynamix, LLC
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include "KmMemoryPool.h"
#include "KmLock.h"
#include "..\shared\CommonDefs.h"

typedef struct _KM_MEMORY_POOL KM_MEMORY_POOL, *PKM_MEMORY_POOL;

typedef struct _KM_MEMORY_POOL_BLOCK_HEADER
{
    //  List link
    LIST_ENTRY  Link;

    //  Memory pool the block belongs to
    PKM_MEMORY_POOL Pool;

} KM_MEMORY_POOL_BLOCK_HEADER, *PKM_MEMORY_POOL_BLOCK_HEADER;

typedef struct _KM_MEMORY_POOL
{
    //  Memory manager
    PKM_MEMORY_MANAGER  MemoryManager;

    //  Structure lock
    KM_LOCK             Lock;

    //  Boolean flag that identifies whether
    //  the pool object should be freed if its 
    //  reference count (RefCnt field) goes to zero.
    BOOLEAN             Referencable;

    //  Indicates whether the pool should
    //  fail any new allocations if the AvailableBlocks
    //  list is empty.
    BOOLEAN             FixedSize;

    //  Number of pool object references.
    //  If this value goes to zero and 
    //  Referencable field is TRUE the pool object gets freed automatically.
    ULARGE_INTEGER      RefCnt;

    //  The size of the data block requested
    //  upon initialization of the pool.
    ULONG               BlockSize;

    struct AvailableBlocks
    {
        //  List head
        LIST_ENTRY      List;

        //  Number of items in the list
        ULARGE_INTEGER  Count;

    } AvailableBlocks;

    struct AllocatedBlocks
    {
        //  List head
        LIST_ENTRY      List;

        //  Number of items in the list
        ULARGE_INTEGER  Count;

    } AllocatedBlocks;

} KM_MEMORY_POOL, *PKM_MEMORY_POOL;

NTSTATUS __stdcall Km_MP_CreateBlock(
    __in    PKM_MEMORY_POOL                 Pool,
    __out   PKM_MEMORY_POOL_BLOCK_HEADER    *BlockHeader)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL_BLOCK_HEADER    NewBlockHeader = NULL;
    ULONG                           SizeRequired;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Pool),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader),
        STATUS_INVALID_PARAMETER_1);

    SizeRequired = (ULONG)sizeof(KM_MEMORY_POOL_BLOCK_HEADER) + Pool->BlockSize;

    NewBlockHeader = Km_MM_AllocMemTypedWithSize(
        Pool->MemoryManager,
        KM_MEMORY_POOL_BLOCK_HEADER,
        SizeRequired);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewBlockHeader),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewBlockHeader,
        SizeRequired);

    NewBlockHeader->Pool = Pool;

    *BlockHeader = NewBlockHeader;

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_DestroyBlock(
    __in    PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader->Pool),
        STATUS_INVALID_PARAMETER_1);

    Km_MM_FreeMem(
        BlockHeader->Pool->MemoryManager,
        BlockHeader);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    ULONG               BlockSize,
    __in    ULONG               InitialBlockCount,
    __in    BOOLEAN             FixedSize,
    __in    BOOLEAN             Referencable,
    __out   PHANDLE             InstanceHandle)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL NewPool = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        BlockSize > 0,
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InstanceHandle),
        STATUS_INVALID_PARAMETER_5);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (InitialBlockCount > 0) || (!FixedSize),
        STATUS_INVALID_PARAMETER_MIX);

    NewPool = Km_MM_AllocMemTyped(
        MemoryManager,
        KM_MEMORY_POOL);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewPool),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewPool, sizeof(KM_MEMORY_POOL));

    InitializeListHead(&NewPool->AllocatedBlocks.List);
    InitializeListHead(&NewPool->AvailableBlocks.List);

    Status = Km_Lock_Initialize(&NewPool->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewPool->MemoryManager = MemoryManager;

    NewPool->FixedSize = FixedSize;

    NewPool->BlockSize = BlockSize;

    if (InitialBlockCount > 0)
    {
        ULONG                           k;
        PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader = NULL;

        for (k = 0; k < InitialBlockCount; k++)
        {
            Status = Km_MP_CreateBlock(NewPool, &BlockHeader);
            GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

            InsertTailList(
                &NewPool->AvailableBlocks.List,
                &BlockHeader->Link);
            NewPool->AvailableBlocks.Count.QuadPart++;
        }
    }

    *InstanceHandle = (HANDLE)NewPool;

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewPool))
        {
            while (!IsListEmpty(&NewPool->AllocatedBlocks.List))
            {
                PLIST_ENTRY Entry = RemoveHeadList(&NewPool->AllocatedBlocks.List);
                NewPool->AllocatedBlocks.Count.QuadPart--;
                
                Km_MP_DestroyBlock(
                    CONTAINING_RECORD(
                        Entry,
                        KM_MEMORY_POOL_BLOCK_HEADER,
                        Link));
            }

            Km_MM_FreeMem(
                MemoryManager,
                NewPool);
        }
    }

    return Status;
};

NTSTATUS __stdcall Km_MP_Finalize(
    __in    HANDLE  Instance)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL Pool = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);

    Pool = (PKM_MEMORY_POOL)Instance;

    Status = Km_Lock_Acquire(&Pool->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        LEAVE_IF_FALSE_SET_STATUS(
            IsListEmpty(&Pool->AllocatedBlocks.List),
            STATUS_UNSUCCESSFUL);

        while (!IsListEmpty(&Pool->AvailableBlocks.List))
        {
            PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader;
            PLIST_ENTRY                     Entry;
            
            Entry = RemoveHeadList(&Pool->AvailableBlocks.List);
            Pool->AvailableBlocks.Count.QuadPart--;

            BlockHeader = CONTAINING_RECORD(Entry, KM_MEMORY_POOL_BLOCK_HEADER, Link);

            Km_MP_DestroyBlock(BlockHeader);
        }
    }
    __finally
    {
        Km_Lock_Release(&Pool->Lock);
    }

    Km_MM_FreeMem(
        Pool->MemoryManager,
        Pool);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_Allocate(
    __in    HANDLE  Instance,
    __out   PVOID   *Block)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL                 Pool = NULL;
    PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Block),
        STATUS_INVALID_PARAMETER_2);

    Pool = (PKM_MEMORY_POOL)Instance;

    Status = Km_Lock_Acquire(&Pool->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        if (!IsListEmpty(&Pool->AvailableBlocks.List))
        {
            PLIST_ENTRY Entry = RemoveHeadList(&Pool->AvailableBlocks.List);
            Pool->AvailableBlocks.Count.QuadPart--;
            BlockHeader = CONTAINING_RECORD(Entry, KM_MEMORY_POOL_BLOCK_HEADER, Link);
        }
        else
        {
            LEAVE_IF_TRUE_SET_STATUS(
                Pool->FixedSize,
                STATUS_NO_MORE_ENTRIES);

            Status = Km_MP_CreateBlock(Pool, &BlockHeader);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));
        }

        if (Assigned(BlockHeader))
        {
            InsertTailList(
                &Pool->AllocatedBlocks.List,
                &BlockHeader->Link);
            Pool->AllocatedBlocks.Count.QuadPart++;
        }
    }
    __finally
    {
        Km_Lock_Release(&Pool->Lock);
    }

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader),
        STATUS_UNSUCCESSFUL);

    *Block = (PVOID)((PUCHAR)BlockHeader + sizeof(KM_MEMORY_POOL_BLOCK_HEADER));

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_AllocateCheckSize(
    __in    HANDLE  Instance,
    __in    SIZE_T  Size,
    __out   PVOID   *Block)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL                 Pool = NULL;
    PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Size > 0,
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Block),
        STATUS_INVALID_PARAMETER_3);

    Pool = (PKM_MEMORY_POOL)Instance;

    Status = Km_Lock_Acquire(&Pool->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        LEAVE_IF_FALSE_SET_STATUS(
            Size <= Pool->BlockSize,
            STATUS_BUFFER_TOO_SMALL);

        if (!IsListEmpty(&Pool->AvailableBlocks.List))
        {
            PLIST_ENTRY Entry = RemoveHeadList(&Pool->AvailableBlocks.List);
            Pool->AvailableBlocks.Count.QuadPart--;
            BlockHeader = CONTAINING_RECORD(Entry, KM_MEMORY_POOL_BLOCK_HEADER, Link);
        }
        else
        {
            LEAVE_IF_TRUE_SET_STATUS(
                Pool->FixedSize,
                STATUS_NO_MORE_ENTRIES);

            Status = Km_MP_CreateBlock(Pool, &BlockHeader);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));
        }

        if (Assigned(BlockHeader))
        {
            InsertTailList(
                &Pool->AllocatedBlocks.List,
                &BlockHeader->Link);
            Pool->AllocatedBlocks.Count.QuadPart++;
        }
    }
    __finally
    {
        Km_Lock_Release(&Pool->Lock);
    }

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader),
        Status == STATUS_SUCCESS ? STATUS_UNSUCCESSFUL : Status);

    *Block = (PVOID)((PUCHAR)BlockHeader + sizeof(KM_MEMORY_POOL_BLOCK_HEADER));

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_Release(
    __in    PVOID   Block)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Block),
        STATUS_INVALID_PARAMETER_1);

    BlockHeader = (PKM_MEMORY_POOL_BLOCK_HEADER)((PUCHAR)Block - sizeof(KM_MEMORY_POOL_BLOCK_HEADER));

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader->Pool),
        STATUS_INVALID_PARAMETER_1);

    Status = Km_Lock_Acquire(&BlockHeader->Pool->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        RemoveEntryList(&BlockHeader->Link);
        BlockHeader->Pool->AllocatedBlocks.Count.QuadPart--;

        InsertTailList(
            &BlockHeader->Pool->AvailableBlocks.List,
            &BlockHeader->Link);
        BlockHeader->Pool->AvailableBlocks.Count.QuadPart++;
    }
    __finally
    {
        Km_Lock_Release(&BlockHeader->Pool->Lock);
    }

cleanup:
    return Status;
};