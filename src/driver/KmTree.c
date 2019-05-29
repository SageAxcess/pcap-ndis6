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

typedef struct _KM_TREE_ITEM
{
    //  Client-supplied pointer
    PVOID   Data;

    //  Size of client-supplied data pointed to by "Data" field.
    ULONG   Size;

} KM_TREE_ITEM, *PKM_TREE_ITEM;

typedef struct _KM_TREE
{
    struct _MEMORY
    {
        PKM_MEMORY_MANAGER  Manager;

        HANDLE              ItemMemPool;

        ULONG               ServiceTag;

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
    PKM_TREE    Tree = NULL;
    PVOID       NewItem = NULL;
    NTSTATUS    Status = STATUS_SUCCESS;

    RETURN_VALUE_IF_FALSE(
        Assigned(Table),
        NULL);
    RETURN_VALUE_IF_FALSE(
        Assigned(Table->TableContext),
        NULL);

    Tree = (PKM_TREE)Table->TableContext;

    Status = Km_MP_Allocate(
        Tree->Memory.ItemMemPool,
        ByteSize,
        &NewItem);
    RETURN_VALUE_IF_FALSE(
        NT_SUCCESS(Status),
        NULL);

    return NewItem;
};

void KmTree_AVLFreeRoutine(
    __in    PRTL_AVL_TABLE  Table,
    __in    PVOID           Buffer)
{
    PKM_TREE        Tree = NULL;
    PKM_TREE_ITEM   Item = NULL;

    RETURN_IF_FALSE(
        (Assigned(Table)) &&
        (Assigned(Buffer)));
    RETURN_IF_FALSE(Assigned(Table->TableContext));
    
    Tree = (PKM_TREE)Table->TableContext;

    Item = (PKM_TREE_ITEM)Buffer;
    
    if (Assigned(Tree->Callbacks.ItemRemove))
    {
        Tree->Callbacks.ItemRemove(
            Tree,
            Tree->TreeContext,
            Item->Data,
            Item->Size);
    }

    Km_MP_Release(Buffer);
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
        if (!RtlDeleteElementGenericTableAvl(
            &Tree->AvlTable,
            Buffer))
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