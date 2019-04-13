//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include "KmMemoryPool.h"
#include "KmLock.h"
#include "KmMemoryTags.h"
#include "..\shared\CommonDefs.h"

typedef struct _KM_MEMORY_POOL      KM_MEMORY_POOL, *PKM_MEMORY_POOL;
typedef struct _KM_MEMORY_POOL_SITE KM_MEMORY_POOL_SITE, *PKM_MEMORY_POOL_SITE;

typedef __declspec(align(8)) struct _KM_MEMORY_POOL_BLOCK_HEADER
{
    //  List link
    LIST_ENTRY              Link;

    //  Memory pool the block belongs to
    PKM_MEMORY_POOL         Pool;

    //  Allocation site the block belongs to
    PKM_MEMORY_POOL_SITE    Site;

    //  Data size
    SIZE_T                  Size;

    //  Data start
    unsigned char           Data;

} KM_MEMORY_POOL_BLOCK_HEADER, *PKM_MEMORY_POOL_BLOCK_HEADER;

typedef struct _KM_MEMORY_POOL_SITE
{
    //  List link
    LIST_ENTRY      Link;

    //  Back-reference to the pool
    PKM_MEMORY_POOL Pool;

    KM_MEMORY_POOL_BLOCK_DEFINITION Definition;

    struct _SITE_ITEMS
    {
        LIST_ENTRY      Items;

        ULARGE_INTEGER  Count;

    } Available, Allocated;

} KM_MEMORY_POOL_SITE, *PKM_MEMORY_POOL_SITE;

typedef struct _KM_MEMORY_POOL
{
    //  Memory manager
    PKM_MEMORY_MANAGER  MemoryManager;

    //  Structure lock
    KM_LOCK             Lock;

    //  Memory tag to use when allocating the blocks.
    ULONG               MemoryTag;

    //  Pool flags
    ULONG               Flags;

    struct _SITES
    {
        //  Items
        LIST_ENTRY  Items;

        //  Count
        ULONG       Count;

    } Sites;

} KM_MEMORY_POOL, *PKM_MEMORY_POOL;

NTSTATUS __stdcall Km_MP_CreateBlock(
    __in    PKM_MEMORY_POOL                 Pool,
    __in    PKM_MEMORY_POOL_SITE            Site,
    __out   PKM_MEMORY_POOL_BLOCK_HEADER    *BlockHeader);

NTSTATUS __stdcall Km_MP_DestroyBlock(
    __in    PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader);

NTSTATUS __stdcall Km_MP_DestroyAllocationSite(
    __in    PKM_MEMORY_POOL_SITE    Site);

NTSTATUS __stdcall Km_MP_CreateAllocationSite(
    __in            PKM_MEMORY_POOL                     Pool,
    __in    const   PKM_MEMORY_POOL_BLOCK_DEFINITION    Definition,
    __out           PKM_MEMORY_POOL_SITE                *Site)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL_SITE            NewSite = NULL;
    PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader = NULL;
    ULONG                           k;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Pool),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Pool->MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Definition),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Site),
        STATUS_INVALID_PARAMETER_3);

    NewSite = Km_MM_AllocMemTypedWithTag(
        Pool->MemoryManager,
        KM_MEMORY_POOL_SITE,
        KM_MEMORY_POOL_SVC_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewSite),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        RtlZeroMemory(
            NewSite,
            sizeof(KM_MEMORY_POOL_SITE));

        RtlCopyMemory(
            &NewSite->Definition,
            Definition,
            sizeof(KM_MEMORY_POOL_BLOCK_DEFINITION));

        InitializeListHead(&NewSite->Allocated.Items);

        InitializeListHead(&NewSite->Available.Items);

        NewSite->Pool = Pool;

        switch (Definition->Type)
        {
            case Generic:
            case NonGrowable:
            case LookasideList:
            {
                if (Definition->BlockCount > 0)
                {
                    for (k = 0; k < Definition->BlockCount; k++)
                    {
                        Status = Km_MP_CreateBlock(
                            Pool,
                            NewSite,
                            &BlockHeader);
                        LEAVE_IF_FALSE(NT_SUCCESS(Status));

                        InsertTailList(
                            &NewSite->Available.Items,
                            &BlockHeader->Link);
                        NewSite->Available.Count.QuadPart++;
                    }
                }
            }break;

            case GenericGuessSize:
            {
                //  Nothing to do here.
                //  Everything will be done upon allocating first suitable block
            }break;
        };
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            if (Assigned(NewSite))
            {
                Km_MM_FreeMem(
                    Pool->MemoryManager,
                    NewSite);
            }
        }
        else
        {
            *Site = NewSite;
        }
    }


cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_DestroyAllocationSite(
    __in    PKM_MEMORY_POOL_SITE    Site)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Site),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Site->Pool),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Site->Pool->MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Site->Allocated.Count.QuadPart == 0,
        STATUS_UNSUCCESSFUL);

    while (!IsListEmpty(&Site->Available.Items))
    {
        PLIST_ENTRY Entry = RemoveHeadList(&Site->Available.Items);

        Site->Available.Count.QuadPart--;

        Km_MP_DestroyBlock(
            CONTAINING_RECORD(
                Entry, 
                KM_MEMORY_POOL_BLOCK_HEADER, 
                Link));
    }

    Km_MM_FreeMem(
        Site->Pool->MemoryManager,
        Site);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_CreateBlock(
    __in    PKM_MEMORY_POOL                 Pool,
    __in    PKM_MEMORY_POOL_SITE            Site,
    __out   PKM_MEMORY_POOL_BLOCK_HEADER    *BlockHeader)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL_BLOCK_HEADER    NewBlockHeader = NULL;
    SIZE_T                          SizeRequired;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Pool),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Site),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader),
        STATUS_INVALID_PARAMETER_4);

    SizeRequired = 
        sizeof(KM_MEMORY_POOL_BLOCK_HEADER) + //    Size of the header structure
        Site->Definition.BlockSize - // Size of the blocks of the allocation site
        1; // -1 byte which is already present in the header (Data field)

    NewBlockHeader = Km_MM_AllocMemTypedWithSizeAndTag(
        Pool->MemoryManager,
        KM_MEMORY_POOL_BLOCK_HEADER,
        SizeRequired,
        Site->Definition.MemoryTag == 0 ? Pool->MemoryTag : Site->Definition.MemoryTag);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewBlockHeader),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewBlockHeader,
        SizeRequired);

    NewBlockHeader->Pool = Pool;

    NewBlockHeader->Site = Site;

    NewBlockHeader->Size = Site->Definition.BlockSize;

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
    __in                PKM_MEMORY_MANAGER                  MemoryManager,
    __in_opt    const   PKM_MEMORY_POOL_BLOCK_DEFINITION    BlockDefinitions,
    __in        const   ULONG                               NumberOfDefinitions,
    __in        const   ULONG                               Flags,
    __in_opt    const   ULONG                               Tag,
    __out               PHANDLE                             InstanceHandle)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL NewPool = NULL;
    ULONG           k;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Km_MP_ValidateFlags(Flags),
        STATUS_INVALID_PARAMETER_4);

    if (Flags == KM_MEMORY_POOL_FLAG_DEFAULT)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(BlockDefinitions),
            STATUS_INVALID_PARAMETER_2);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            NumberOfDefinitions > 0,
            STATUS_INVALID_PARAMETER_3);
    }
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InstanceHandle),
        STATUS_INVALID_PARAMETER_6);

    NewPool = Km_MM_AllocMemTypedWithTag(
        MemoryManager,
        KM_MEMORY_POOL,
        KM_MEMORY_POOL_OBJECT_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewPool),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewPool, sizeof(KM_MEMORY_POOL));

    Status = Km_Lock_Initialize(&NewPool->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewPool->MemoryManager = MemoryManager;

    NewPool->MemoryTag = Tag;

    NewPool->Flags = Flags;

    InitializeListHead(&NewPool->Sites.Items);

    for (k = 0; k < NumberOfDefinitions; k++)
    {
        PKM_MEMORY_POOL_SITE    NewAllocationSite = NULL;

        Status = Km_MP_CreateAllocationSite(
            NewPool,
            &BlockDefinitions[k],
            &NewAllocationSite);
        BREAK_IF_FALSE(NT_SUCCESS(Status));

        InsertTailList(
            &NewPool->Sites.Items,
            &NewAllocationSite->Link);
        NewPool->Sites.Count++;
    };

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewPool))
        {
            while (!IsListEmpty(&NewPool->Sites.Items))
            {
                PLIST_ENTRY Entry = RemoveHeadList(&NewPool->Sites.Items);

                NewPool->Sites.Count--;

                Km_MP_DestroyAllocationSite(
                    CONTAINING_RECORD(
                        Entry,
                        KM_MEMORY_POOL_SITE,
                        Link));
            }

            Km_MM_FreeMem(
                MemoryManager,
                NewPool);
        }
    }
    else
    {
        *InstanceHandle = (HANDLE)NewPool;
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
        PLIST_ENTRY Entry = NULL;

        //  First of all we need to check whether there're any allocated blocks

        for (Entry = Pool->Sites.Items.Flink;
            Entry != &Pool->Sites.Items;
            Entry = Entry->Flink)
        {
            PKM_MEMORY_POOL_SITE    Site = CONTAINING_RECORD(Entry, KM_MEMORY_POOL_SITE, Link);

            LEAVE_IF_FALSE_SET_STATUS(
                IsListEmpty(&Site->Allocated.Items),
                STATUS_UNSUCCESSFUL);
        }

        //  Now lets cleanup the allocation sites

        while (!IsListEmpty(&Pool->Sites.Items))
        {
            Entry = RemoveHeadList(&Pool->Sites.Items);

            Pool->Sites.Count--;

            Km_MP_DestroyAllocationSite(
                CONTAINING_RECORD(
                    Entry,
                    KM_MEMORY_POOL_SITE,
                    Link));
        }
    }
    __finally
    {
        Km_Lock_Release(&Pool->Lock);
    }

    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    //  Finally, lets free the memory occupied by the memory pool object

    Km_MM_FreeMem(
        Pool->MemoryManager,
        Pool);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_Allocate(
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
        PLIST_ENTRY             Entry = NULL;

        //  This is the allocation site that suites the size requested
        PKM_MEMORY_POOL_SITE    SmallestFittingSite = NULL;

        //  This is the allocation site that can be configured to the requested size
        PKM_MEMORY_POOL_SITE    FirstDynamicSite = NULL;

        //  This is the allocation site we will create if there's no 
        //  suiteable one already in the pool and if the pool allows 
        //  new sites to be created (when Flags field contains KM_MEMORY_POOL_FLAG_DYNAMIC value)
        PKM_MEMORY_POOL_SITE    NewSite = NULL;

        //  This is the pointer to the resulting allocation site (if any)
        PKM_MEMORY_POOL_SITE    AllocationSite = NULL;

        //  First of all lets find the allocation size that fits our requested size
        //  In other words - a site with smallest block size, yet with large enough to 
        //  hold the number of bytes requested.

        for (Entry = Pool->Sites.Items.Flink;
            Entry != &Pool->Sites.Items;
            Entry = Entry->Flink)
        {
            PKM_MEMORY_POOL_SITE    Site = CONTAINING_RECORD(
                Entry,
                KM_MEMORY_POOL_SITE,
                Link);

            if ((Site->Definition.BlockSize >= Size) &&
                ((Site->Available.Count.QuadPart > 0) || (Site->Definition.Type != NonGrowable)))
            {
                if (Assigned(SmallestFittingSite))
                {
                    if (SmallestFittingSite->Definition.BlockSize > Site->Definition.BlockSize)
                    {
                        SmallestFittingSite = Site;
                    }
                }
                else
                {
                    SmallestFittingSite = Site;
                }
            }

            //  We don't need a dynamic allocation site, since we've got a standard one
            CONTINUE_IF_TRUE(Assigned(SmallestFittingSite));

            CONTINUE_IF_TRUE(Assigned(FirstDynamicSite));

            if ((Site->Definition.Type == GenericGuessSize) &&
                (Site->Definition.BlockSize == 0) &&
                (IsListEmpty(&Site->Available.Items) && (IsListEmpty(&Site->Allocated.Items))))
            {
                FirstDynamicSite = Site;
            }
        };

        if (Assigned(SmallestFittingSite))
        {
            //  Great, we found an allocation site that suites the requested size
            AllocationSite = SmallestFittingSite;
        }
        else
        {
            //  Do we have a so-called dynamic allocation site ?
            if (Assigned(FirstDynamicSite))
            {
                //  If so - lets initialize it to the size requested

                PKM_MEMORY_POOL_BLOCK_HEADER    TmpBlockHeader = NULL;

                FirstDynamicSite->Definition.BlockSize = Size;
                FirstDynamicSite->Definition.Type = Generic;
                __try
                {
                    if (FirstDynamicSite->Definition.BlockCount > 0)
                    {
                        ULONG k;

                        for (k = 0; k < FirstDynamicSite->Definition.BlockCount; k++)
                        {
                            TmpBlockHeader = NULL;

                            Status = Km_MP_CreateBlock(
                                Pool,
                                FirstDynamicSite,
                                &TmpBlockHeader);
                            LEAVE_IF_FALSE(NT_SUCCESS(Status));

                            InsertTailList(&FirstDynamicSite->Available.Items, &TmpBlockHeader->Link);

                            FirstDynamicSite->Available.Count.QuadPart++;
                        }
                    }
                }
                __finally
                {
                    if (!NT_SUCCESS(Status))
                    {
                        //  Something went wrong... lets cleanup the allocation site

                        //  Removing memory blocks (if any)
                        while (!IsListEmpty(&FirstDynamicSite->Available.Items))
                        {
                            TmpBlockHeader = CONTAINING_RECORD(
                                RemoveHeadList(&FirstDynamicSite->Available.Items),
                                KM_MEMORY_POOL_BLOCK_HEADER,
                                Link);
                            Km_MP_DestroyBlock(BlockHeader);
                        }

                        //  Resetting block size.
                        //  This is required, so the allocation site can be used in future
                        FirstDynamicSite->Definition.BlockSize = 0;
                    }
                }
                LEAVE_IF_FALSE(NT_SUCCESS(Status));

                //  This is our allocation site, lets use it
                AllocationSite = FirstDynamicSite;
            }
        }

        //  In case there was no allocation site found, lets check 
        //  if we can create a new allocation site
        if ((!Assigned(AllocationSite)) &&
            (IsBitFlagSet(Pool->Flags, KM_MEMORY_POOL_FLAG_DYNAMIC)))
        {
            KM_MEMORY_POOL_BLOCK_DEFINITION Definition;

            //  Initializing block definition
            Definition.BlockCount = 0;
            Definition.BlockSize = Size;
            Definition.MemoryTag = Pool->MemoryTag;
            Definition.Type = 
                IsBitFlagSet(Pool->Flags, KM_MEMORY_POOL_FLAG_LOOKASIDE) ? 
                LookasideList : 
                Generic;

            //  Creating new allocation site
            Status = Km_MP_CreateAllocationSite(
                Pool,
                &Definition,
                &NewSite);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            //  Adding the newly created allocation site to the list
            InsertTailList(
                &Pool->Sites.Items,
                &NewSite->Link);
            Pool->Sites.Count++;

            AllocationSite = NewSite;
        }

        //  If there was no site found nor we created a new one - we failed.
        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(AllocationSite),
            STATUS_UNSUCCESSFUL);
        
        //  If the site got an available block - lets use it
        if (!IsListEmpty(&AllocationSite->Available.Items))
        {
            Entry = RemoveHeadList(&AllocationSite->Available.Items);
            AllocationSite->Available.Count.QuadPart--;
            BlockHeader = CONTAINING_RECORD(Entry, KM_MEMORY_POOL_BLOCK_HEADER, Link);
        }
        else
        {
            // Otherwise - lets create one (if permited to)
            LEAVE_IF_FALSE_SET_STATUS(
                AllocationSite->Definition.Type != NonGrowable,
                STATUS_NO_MORE_ENTRIES);

            Status = Km_MP_CreateBlock(Pool, AllocationSite, &BlockHeader);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));
        }

        if (Assigned(BlockHeader))
        {
            InsertTailList(
                &AllocationSite->Allocated.Items,
                &BlockHeader->Link);
            AllocationSite->Allocated.Count.QuadPart++;
        }
    }
    __finally
    {
        Km_Lock_Release(&Pool->Lock);
    }

    *Block = (PVOID)&BlockHeader->Data;

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MP_Release(
    __in    PVOID   Block)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_MEMORY_POOL_BLOCK_HEADER    BlockHeader = NULL;
    PKM_LOCK                        Lock = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Block),
        STATUS_INVALID_PARAMETER_1);

    BlockHeader = CONTAINING_RECORD(Block, KM_MEMORY_POOL_BLOCK_HEADER, Data);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader->Pool),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(BlockHeader->Site),
        STATUS_INVALID_PARAMETER_1);

    Lock = &BlockHeader->Pool->Lock;

    Status = Km_Lock_Acquire(Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PKM_MEMORY_POOL_SITE    Site = BlockHeader->Site;

        RemoveEntryList(&BlockHeader->Link);
        Site->Allocated.Count.QuadPart--;

        if ((Site->Definition.Type == LookasideList) && 
            (Site->Available.Count.QuadPart + Site->Allocated.Count.QuadPart > Site->Definition.BlockCount))
        {
            Km_MP_DestroyBlock(BlockHeader);
        }
        else
        {
            InsertHeadList(
                &Site->Available.Items,
                &BlockHeader->Link);
            Site->Available.Count.QuadPart++;
        }
    }
    __finally
    {
        Km_Lock_Release(Lock);
    }

cleanup:
    return Status;
};