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

#include "KmTree.h"
#include "KmLock.h"
#include "KmMemoryTags.h"
#include "KmMemoryPool.h"
#include "..\shared\CommonDefs.h"

typedef struct _KM_TREE_FIND_MATCH_DATA
{
    PVOID                   MatchData;

    PKM_TREE_MATCH_ROUTINE  MatchRoutine;

} KM_TREE_FIND_MATCH_DATA, *PKM_TREE_FIND_MATCH_DATA;

typedef struct _KM_TREE_FIND_DATA
{
    PKM_TREE                Tree;

    ULONG                   NextFlag;

    PVOID                   RestartKey;

    ULONG                   DeleteCount;

    PVOID                   Buffer;

    KM_TREE_SEARCH_RECORD   SearchRecord;

    KM_TREE_FIND_MATCH_DATA MatchData;

} KM_TREE_FIND_DATA, *PKM_TREE_FIND_DATA;

typedef struct _KM_TREE_ITEM
{
    //  Client-supplied pointer
    PVOID   Data;

    //  Size of client-supplied data pointed to by "Data" field.
    ULONG   Size;

} KM_TREE_ITEM, *PKM_TREE_ITEM;

typedef struct _KM_TREE_ITEM_MEMORY_BLOCK
{
    //  Tree item pointer
    PKM_TREE_ITEM   TreeItem;

    //  Start of the data
    unsigned long   Data;

} KM_TREE_ITEM_MEMORY_BLOCK, *PKM_TREE_ITEM_MEMORY_BLOCK;

typedef struct _KM_TREE
{
    struct _MEMORY
    {
        PKM_MEMORY_MANAGER  Manager;

        HANDLE              ItemMemPool;

        ULONG               ServiceTag;

        HANDLE              FindDataMemPool;

    } Memory;

    RTL_AVL_TABLE                       AvlTable;

    struct _CALLBACKS
    {
        PKM_TREE_ITEM_COMPARISON_CALLBACK   ItemComparison;

        PKM_TREE_ITEM_REMOVE_CALLBACK       ItemRemove;

    } Callbacks;
    
    PVOID                               TreeContext;

    PKM_LOCK                            Lock;

    KM_TREE_ITEM                        TempItem;

} KM_TREE, *PKM_TREE;

PVOID KmTree_AVLAllocateRoutine(
    __in    PRTL_AVL_TABLE  Table,
    __in    ULONG           ByteSize)
{
    PKM_TREE                    Tree = NULL;
    PKM_TREE_ITEM_MEMORY_BLOCK  NewBlock = NULL;
    NTSTATUS                    Status = STATUS_SUCCESS;
    SIZE_T                      SizeRequired;

    RETURN_VALUE_IF_FALSE(
        Assigned(Table),
        NULL);
    RETURN_VALUE_IF_FALSE(
        Assigned(Table->TableContext),
        NULL);

    Tree = (PKM_TREE)Table->TableContext;

    SizeRequired =
        sizeof(KM_TREE_ITEM_MEMORY_BLOCK) -
        FIELD_SIZE(KM_TREE_ITEM_MEMORY_BLOCK, Data) +
        ByteSize;

    Status = Km_MP_Allocate(
        Tree->Memory.ItemMemPool,
        ByteSize,
        &NewBlock);
    RETURN_VALUE_IF_FALSE(
        NT_SUCCESS(Status),
        NULL);

    NewBlock->TreeItem = (PKM_TREE_ITEM)(((PUCHAR)&NewBlock->Data) + ByteSize - sizeof(KM_TREE_ITEM));
        
    return &NewBlock->Data;
};

void KmTree_AVLFreeRoutine(
    __in    PRTL_AVL_TABLE  Table,
    __in    PVOID           Buffer)
{
    PKM_TREE                    Tree = NULL;
    PKM_TREE_ITEM_MEMORY_BLOCK  MemoryBlock = NULL;

    RETURN_IF_FALSE(
        (Assigned(Table)) &&
        (Assigned(Buffer)));
    RETURN_IF_FALSE(Assigned(Table->TableContext));
    
    Tree = (PKM_TREE)Table->TableContext;

    MemoryBlock = CONTAINING_RECORD(Buffer, KM_TREE_ITEM_MEMORY_BLOCK, Data);

    if (Assigned(Tree->Callbacks.ItemRemove))
    {
        /*
            Actual item pointer is at block address + block size - sizeof(KM_TREE_ITEM)
        */

        Tree->Callbacks.ItemRemove(
            Tree,
            Tree->TreeContext,
            MemoryBlock->TreeItem->Data,
            MemoryBlock->TreeItem->Size);
    }

    Km_MP_Release(MemoryBlock);
};

RTL_GENERIC_COMPARE_RESULTS KmTree_AVLCompareRoutine(
    __in    PRTL_AVL_TABLE  Table,
    __in    PVOID           Item1,
    __in    PVOID           Item2)
{
    PKM_TREE        Tree = NULL;
    PKM_TREE_ITEM   TreeItem1 = NULL;
    PKM_TREE_ITEM   TreeItem2 = NULL;

    RETURN_VALUE_IF_FALSE(
        Assigned(Table),
        GenericEqual);
    RETURN_VALUE_IF_FALSE(
        Assigned(Table->TableContext),
        GenericEqual);

    RETURN_VALUE_IF_FALSE(
        (Assigned(Item1)) &&
        (Assigned(Item2)),
        Assigned(Item1) ? GenericGreaterThan :
        Assigned(Item2) ? GenericLessThan : GenericEqual);

    Tree = (PKM_TREE)Table->TableContext;

    RETURN_VALUE_IF_FALSE(
        Assigned(Tree->Callbacks.ItemComparison),
        Item1 > Item2 ? GenericGreaterThan :
        Item1 < Item2 ? GenericLessThan :
        GenericEqual);

    TreeItem1 = (PKM_TREE_ITEM)Item1;
    TreeItem2 = (PKM_TREE_ITEM)Item2;

    return Tree->Callbacks.ItemComparison(
        Tree,
        Tree->TreeContext,
        TreeItem1->Data,
        TreeItem1->Size,
        TreeItem2->Data,
        TreeItem2->Size);
};

NTSTATUS __stdcall KmTree_InitializeEx(
    __in        PKM_MEMORY_MANAGER                  MemoryManager,
    __in        PKM_TREE_ITEM_COMPARISON_CALLBACK   ItemComparisonCallback,
    __in_opt    PKM_TREE_ITEM_REMOVE_CALLBACK       ItemRemoveCallback,
    __in_opt    BOOLEAN                             ThreadSafe,
    __in_opt    PVOID                               TreeContext,
    __in_opt    ULONG                               InitialCapacity,
    __out       PKM_TREE                            *Tree)
{
    NTSTATUS                        Status = STATUS_SUCCESS;
    PKM_TREE                        NewTree = NULL;
    KM_MEMORY_POOL_BLOCK_DEFINITION MemoryPoolBlockDefs;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ItemComparisonCallback),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Tree),
        STATUS_INVALID_PARAMETER_7);

    NewTree = (PKM_TREE)Km_MM_AllocMemTypedWithTag(
        MemoryManager,
        KM_TREE,
        KM_TREE_OBJECT_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewTree),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        RtlZeroMemory(
            NewTree,
            sizeof(KM_TREE));

        RtlZeroMemory(
            &MemoryPoolBlockDefs,
            sizeof(KM_MEMORY_POOL_BLOCK_DEFINITION));

        MemoryPoolBlockDefs.BlockCount = InitialCapacity;
        MemoryPoolBlockDefs.Type = GenericGuessSize;
        MemoryPoolBlockDefs.MemoryTag = KM_TREE_ITEM_MEMORY_TAG;
        MemoryPoolBlockDefs.BlockSize = 0;

        Status = Km_MP_Initialize(
            MemoryManager,
            &MemoryPoolBlockDefs,
            1,
            KM_MEMORY_POOL_FLAG_DEFAULT,
            KM_TREE_SVC_MEMORY_TAG,
            &NewTree->Memory.ItemMemPool);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));
        __try
        {
            MemoryPoolBlockDefs.BlockCount = 1;
            MemoryPoolBlockDefs.Type = LookasideList;
            MemoryPoolBlockDefs.MemoryTag = KM_TREE_SVC_MEMORY_TAG;
            MemoryPoolBlockDefs.BlockSize = sizeof(KM_TREE_FIND_DATA);

            Status = Km_MP_Initialize(
                MemoryManager,
                &MemoryPoolBlockDefs,
                1,
                KM_MEMORY_POOL_FLAG_DEFAULT,
                KM_TREE_SVC_MEMORY_TAG,
                &NewTree->Memory.FindDataMemPool);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));
            __try
            {

                NewTree->Memory.Manager = MemoryManager;

                NewTree->Callbacks.ItemRemove = ItemRemoveCallback;

                NewTree->Memory.ServiceTag = KM_TREE_SVC_MEMORY_TAG;

                NewTree->Callbacks.ItemComparison = ItemComparisonCallback;

                NewTree->TreeContext = TreeContext;

                if (ThreadSafe)
                {
                    NewTree->Lock = Km_MM_AllocMemTypedWithTag(
                        MemoryManager,
                        KM_LOCK,
                        NewTree->Memory.ServiceTag);
                    LEAVE_IF_FALSE_SET_STATUS(
                        Assigned(NewTree->Lock),
                        STATUS_INSUFFICIENT_RESOURCES);
                    __try
                    {
                        Status = Km_Lock_Initialize(NewTree->Lock);
                    }
                    __finally
                    {
                        if (!NT_SUCCESS(Status))
                        {
                            Km_MM_FreeMem(
                                MemoryManager,
                                NewTree->Lock);
                        }
                    }
                }

                RtlInitializeGenericTableAvl(
                    &NewTree->AvlTable,
                    KmTree_AVLCompareRoutine,
                    KmTree_AVLAllocateRoutine,
                    KmTree_AVLFreeRoutine,
                    NewTree);
            }
            __finally
            {
                if (!NT_SUCCESS(Status))
                {
                    Km_MP_Finalize(NewTree->Memory.FindDataMemPool);
                }
            }
        }
        __finally
        {
            if (!NT_SUCCESS(Status))
            {
                Km_MP_Finalize(NewTree->Memory.ItemMemPool);
            }
        }
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            Km_MM_FreeMem(
                MemoryManager,
                NewTree);
        }
        else
        {
            *Tree = NewTree;
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_Finalize(
    __in	PKM_TREE	Tree)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Tree),
        STATUS_INVALID_PARAMETER_1);

    Status = KmTree_Clear(Tree);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_MP_Finalize(Tree->Memory.ItemMemPool);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_MP_Finalize(Tree->Memory.FindDataMemPool);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    if (Assigned(Tree->Lock))
    {
        Km_MM_FreeMem(
            Tree->Memory.Manager,
            Tree->Lock);
        Tree->Lock = NULL;
    }

    Km_MM_FreeMem(
        Tree->Memory.Manager, 
        Tree);

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_ClearEx(
    __in        PKM_TREE    Tree,
    __in_opt    BOOLEAN     CheckParams,
    __in_opt    BOOLEAN     LockTree)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }
    
    if ((Assigned(Tree->Lock)) &&
        (LockTree))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        while (!RtlIsGenericTableEmptyAvl(&Tree->AvlTable))
        {
            PVOID   Element = RtlGetElementGenericTableAvl(&Tree->AvlTable, 0);
            BREAK_IF_FALSE(Assigned(Element));
            RtlDeleteElementGenericTableAvl(&Tree->AvlTable, Element);
        }
    }
    __finally
    {
        if ((Assigned(Tree->Lock)) &&
            (LockTree))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_AddItemEx(
    __in    PKM_TREE    Tree,
    __in    PVOID       Buffer,
    __in    ULONG       BufferSize,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    KM_TREE_ITEM    Item;
    BOOLEAN         NewElement = FALSE;
    PVOID           TreeElement = NULL;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }

    if ((Assigned(Tree->Lock)) &&
        (LockTree))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        Item.Data = Buffer;
        Item.Size = BufferSize;

        TreeElement = RtlInsertElementGenericTableAvl(
            &Tree->AvlTable,
            &Item,
            (LONG)sizeof(Item),
            &NewElement);

        LEAVE_IF_FALSE_SET_STATUS(
            (Assigned(TreeElement)) &&
            (NewElement),
            STATUS_UNSUCCESSFUL);
    }
    __finally
    {
        if ((Assigned(Tree->Lock)) &&
            (LockTree))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_DeleteItemEx(
    __in    PKM_TREE    Tree,
    __in    PVOID       Buffer,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }
    if ((Assigned(Tree->Lock)) &&
        (LockTree))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        Tree->TempItem.Data = Buffer;
        Tree->TempItem.Size = 0;

        if (!RtlDeleteElementGenericTableAvl(
            &Tree->AvlTable,
            &Tree->TempItem))
        {
            Status = STATUS_UNSUCCESSFUL;
        }

    }
    __finally
    {
        if ((Assigned(Tree->Lock)) &&
            (LockTree))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }


cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_FindItemEx(
    __in        PKM_TREE    Tree,
    __in        PVOID       Buffer,
    __in        ULONG       BufferSize,
    __out_opt   PVOID       *FoundBuffer,
    __out_opt   PULONG      FoundBufferSize,
    __in        BOOLEAN     CheckParams,
    __in        BOOLEAN     LockTree)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }

    if ((Assigned(Tree->Lock)) &&
        (LockTree))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        PKM_TREE_ITEM   TreeItem = NULL;

        Tree->TempItem.Data = Buffer;
        Tree->TempItem.Size = BufferSize;
        
        TreeItem = (PKM_TREE_ITEM)RtlLookupElementGenericTableAvl(&Tree->AvlTable, &Tree->TempItem);

        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(TreeItem),
            STATUS_NOT_FOUND);

        if (Assigned(FoundBuffer))
        {
            *FoundBuffer = TreeItem->Data;
        }

        if (Assigned(FoundBufferSize))
        {
            *FoundBufferSize = TreeItem->Size;
        }
    }
    __finally
    {
        if ((Assigned(Tree->Lock)) &&
            (LockTree))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_GetCountEx(
    __in    PKM_TREE    Tree,
    __out   PULONG      Count,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Count),
            STATUS_INVALID_PARAMETER_2);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }

    if ((Assigned(Tree->Lock)) &&
        (LockTree))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        *Count = RtlNumberGenericTableElementsAvl(&Tree->AvlTable);
    }
    __finally
    {
        if ((Assigned(Tree->Lock)) &&
            (LockTree))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_EnumerateEntriesEx(
    __in    PKM_TREE    Tree,
    __inout PVOID       *Item,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree)
{
    NTSTATUS    Status = STATUS_SUCCESS;


    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Item),
            STATUS_INVALID_PARAMETER_2);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }

    if ((Assigned(Tree->Lock)) &&
        (LockTree))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        *Item = RtlEnumerateGenericTableAvl(&Tree->AvlTable, *Item == NULL);
    }
    __finally
    {
        if ((Assigned(Tree->Lock)) &&
            (LockTree))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_FindX_MatchFunction(
    __in    PRTL_AVL_TABLE  Table,
    __in    PVOID           UserData,
    __in    PVOID           MatchData)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_TREE_FIND_DATA  FindData = NULL;
    PKM_TREE_ITEM       Item = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Table),
        STATUS_NO_MORE_MATCHES);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(UserData),
        STATUS_NO_MORE_MATCHES);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MatchData),
        STATUS_NO_MORE_MATCHES);

    FindData = (PKM_TREE_FIND_DATA)MatchData;
    
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(FindData->MatchData.MatchRoutine),
        STATUS_SUCCESS);

    Item = (PKM_TREE_ITEM)UserData;
    
    Status = FindData->MatchData.MatchRoutine(
        FindData->Tree,
        FindData->Tree->TreeContext,
        Item->Data,
        FindData->MatchData.MatchData);

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_FindFirstEx(
    __in        PKM_TREE                Tree,
    __in_opt    PKM_TREE_MATCH_ROUTINE  MatchRoutine,
    __in_opt    PVOID                   MatchRoutineData,
    __out       PKM_TREE_SEARCH_RECORD  *SearchRecord,
    __in        BOOLEAN                 CheckParams,
    __in        BOOLEAN                 LockTree)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_TREE_FIND_DATA  NewFindData = NULL;
    PKM_TREE_ITEM       TreeItem = NULL;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Tree),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(SearchRecord),
            STATUS_INVALID_PARAMETER_4);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }

    if ((LockTree) &&
        (Assigned(Tree->Lock)))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        Status = Km_MP_Allocate(
            Tree->Memory.FindDataMemPool,
            sizeof(KM_TREE_FIND_DATA),
            &NewFindData);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));
        __try
        {
            RtlZeroMemory(
                NewFindData,
                sizeof(KM_TREE_FIND_DATA));

            NewFindData->Tree = Tree;
            NewFindData->MatchData.MatchData = MatchRoutineData;
            NewFindData->MatchData.MatchRoutine = MatchRoutine;

            TreeItem = (PKM_TREE_ITEM)RtlEnumerateGenericTableLikeADirectory(
                &Tree->AvlTable,
                KmTree_FindX_MatchFunction,
                NewFindData,
                NewFindData->NextFlag,
                &NewFindData->RestartKey,
                &NewFindData->DeleteCount,
                NewFindData->Buffer);

            if (Assigned(TreeItem))
            {
                NewFindData->SearchRecord.FindResult.Buffer = TreeItem->Data;
                NewFindData->SearchRecord.FindResult.BufferSize = TreeItem->Size;
                NewFindData->SearchRecord.Status = STATUS_SUCCESS;
            }
            else
            {
                NewFindData->SearchRecord.Status = STATUS_NO_MATCH;
            }

            *SearchRecord = &NewFindData->SearchRecord;
        }
        __finally
        {
            if (!NT_SUCCESS(Status))
            {
                Km_MP_Release(NewFindData);
            }
        }
    }
    __finally
    {
        if ((LockTree) &&
            (Assigned(Tree->Lock)))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_FindNextEx(
    __in    PKM_TREE_SEARCH_RECORD  SearchRecord,
    __in    BOOLEAN                 CheckParams,
    __in    BOOLEAN                 LockTree)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_TREE            Tree = NULL;
    PKM_TREE_FIND_DATA  FindData = NULL;
    PKM_TREE_ITEM       Item = NULL;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(SearchRecord),
            STATUS_INVALID_PARAMETER_1);

        FindData = CONTAINING_RECORD(SearchRecord, KM_TREE_FIND_DATA, SearchRecord);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(FindData->Tree),
            STATUS_INVALID_PARAMETER_1);

        Tree = FindData->Tree;

        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            ((Assigned(Tree->Lock)) && (LockTree)) ||
            (!LockTree),
            STATUS_INVALID_PARAMETER_MIX);
    }
    else
    {
        FindData = CONTAINING_RECORD(SearchRecord, KM_TREE_FIND_DATA, SearchRecord);
        Tree = FindData->Tree;
    }

    if ((LockTree) &&
        (Assigned(Tree->Lock)))
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        FindData->NextFlag = TRUE;

        Item = (PKM_TREE_ITEM)RtlEnumerateGenericTableLikeADirectory(
            &Tree->AvlTable,
            &KmTree_FindX_MatchFunction,
            FindData,
            FindData->NextFlag,
            &FindData->RestartKey,
            &FindData->DeleteCount,
            FindData->Buffer);
        if (Assigned(Item))
        {
            FindData->SearchRecord.Status = STATUS_SUCCESS;
            FindData->SearchRecord.FindResult.Buffer = Item->Data;
            FindData->SearchRecord.FindResult.BufferSize = Item->Size;
        }
        else
        {
            FindData->SearchRecord.Status = STATUS_NO_MORE_ENTRIES;
            Status = STATUS_NO_MORE_ENTRIES;
        }
    }
    __finally
    {
        if ((LockTree) &&
            (Assigned(Tree->Lock)))
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTree_FindCloseEx(
    __in    PKM_TREE_SEARCH_RECORD  SearchRecord,
    __in    BOOLEAN                 LockTree)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_TREE            Tree = NULL;
    PKM_TREE_FIND_DATA  FindData = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(SearchRecord),
        STATUS_INVALID_PARAMETER_1);

    FindData = CONTAINING_RECORD(SearchRecord, KM_TREE_FIND_DATA, SearchRecord);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(FindData->Tree),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        ((Assigned(FindData->Tree->Lock)) && (LockTree)) ||
        (!LockTree),
        STATUS_INVALID_PARAMETER_MIX);

    Tree = FindData->Tree;

    if (LockTree)
    {
        Status = Km_Lock_Acquire(Tree->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        Km_MP_Release(FindData);
    }
    __finally
    {
        if (LockTree)
        {
            Km_Lock_Release(Tree->Lock);
        }
    }

cleanup:
    return Status;
};