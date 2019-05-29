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

#ifndef KM_TREE_H
#define KM_TREE_H

#include "KmMemoryManager.h"

typedef struct _KM_TREE KM_TREE, *PKM_TREE;

typedef void(__stdcall _KM_TREE_ITEM_REMOVE_CALLBACK)(
    __in    PKM_TREE    Tree,
    __in    PVOID       TreeContext,
    __in    PVOID       Buffer,
    __in    ULONG       BufferSize);

typedef _KM_TREE_ITEM_REMOVE_CALLBACK KM_TREE_ITEM_REMOVE_CALLBACK, *PKM_TREE_ITEM_REMOVE_CALLBACK;

typedef int(__stdcall _KM_TREE_ITEM_COMPARISON_CALLBACK)(
    __in    PKM_TREE        Tree,
    __in    PVOID           TreeContext,
    __in    PVOID           Buffer1,
    __in    ULONG           BufferSize1,
    __in    PVOID           Buffer2,
    __in    ULONG           BufferSize2);

typedef _KM_TREE_ITEM_COMPARISON_CALLBACK KM_TREE_ITEM_COMPARISON_CALLBACK, *PKM_TREE_ITEM_COMPARISON_CALLBACK;

NTSTATUS __stdcall KmTree_InitializeEx(
    __in        PKM_MEMORY_MANAGER                  MemoryManager,
    __in        PKM_TREE_ITEM_COMPARISON_CALLBACK   ItemComparisonCallback,
    __in_opt    PKM_TREE_ITEM_REMOVE_CALLBACK       ItemRemoveCallback,
    __in_opt    BOOLEAN                             ThreadSafe,
    __in_opt    PVOID                               TreeContext,
    __in_opt    ULONG                               InitialCapacity,
    __out       PKM_TREE                            *Tree);

NTSTATUS __stdcall KmTree_Finalize(
    __in    PKM_TREE    Tree);

NTSTATUS __stdcall KmTree_ClearEx(
    __in    PKM_TREE    Tree,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree);

NTSTATUS __stdcall KmTree_AddItemEx(
    __in    PKM_TREE    Tree,
    __in    PVOID       Buffer,
    __in    ULONG       BufferSize,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree);

NTSTATUS __stdcall KmTree_DeleteItemEx(
    __in    PKM_TREE    Tree,
    __in    PVOID       Buffer,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree);

NTSTATUS __stdcall KmTree_FindItemEx(
    __in        PKM_TREE    Tree,
    __in        PVOID       Buffer,
    __in        ULONG       BufferSize,
    __out_opt   PVOID       *FoundBuffer,
    __out_opt   PULONG      FoundBufferSize,
    __in        BOOLEAN     CheckParams,
    __in        BOOLEAN     LockTree);

NTSTATUS __stdcall KmTree_GetCountEx(
    __in    PKM_TREE    Tree,
    __out   PULONG      Count,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree);

NTSTATUS __stdcall KmTree_EnumerateEntriesEx(
    __in    PKM_TREE    Tree,
    __inout PVOID       *Item,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockTree);

#define KmTree_Clear(Tree)                                                                      KmTree_ClearEx((Tree), TRUE, TRUE)
#define KmTree_Clear_NoLock(Tree)                                                               KmTree_ClearEx((Tree), TRUE, FALSE)
#define KmTree_AddItem(Tree, Buffer, BufferSize)                                                KmTree_AddItemEx((Tree), (Buffer), (BufferSize), TRUE, TRUE)
#define KmTree_AddItem_NoLock(Tree, Buffer, BufferSize)                                         KmTree_AddItemEx((Tree), (Buffer), (BufferSize), TRUE, FALSE)
#define KmTree_DeleteItem(Tree, Buffer)                                                         KmTree_DeleteItemEx((Tree), (Buffer), TRUE, TRUE)
#define KmTree_DeleteItem_NoLock(Tree, Buffer)                                                  KmTree_DeleteItemEx((Tree), (Buffer), TRUE, FALSE)
#define KmTree_FindItem(Tree, Buffer, BufferSize, FoundBufferPtr, FoundBufferSizePtr)           KmTree_FindItemEx((Tree), (Buffer), (BufferSize), (FoundBufferPtr), (FoundBufferSizePtr), TRUE, TRUE)
#define KmTree_FindItem_NoLock(Tree, Buffer, BufferSize, FoundBufferPtr, FoundBufferSizePtr)    KmTree_FindItemEx((Tree), (Buffer), (BufferSize), (FoundBufferPtr), (FoundBufferSizePtr), TRUE, FALSE)
#define KmTree_GetCount(Tree, Count)                                                            KmTree_GetCountEx((Tree), (Count), TRUE, TRUE)
#define KmTree_GetCount_NoLock(Tree, Count)                                                     KmTree_GetCountEx((Tree), (Count), TRUE, FALSE)
#define KmTree_EnumerateEntries(Tree, ItemPtr)                                                  KmTree_EnumerateEntriesEx((Tree), (ItemPtr), TRUE, TRUE)
#define KmTree_EnumerateEntries_NoLock(Tree, ItemPtr)                                           KmTree_EnumerateEntriesEx((Tree), (ItemPtr), TRUE, FALSE)

#define KmTree_CompareValues(Value1, Value2) \
    ((Value1) > (Value2) ? GenericGreaterThan : \
     (Value1) < (Value2) ? GenericLessThan : \
     GenericEqual)

#define KmTree_StdCmpResToGeneric(Value) \
    ((Value) > 0 ? GenericGreaterThan : \
     (Value) < 0 ? GenericLessThan : \
     GenericEqual)

#endif