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
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef KM_LIST_H
#define KM_LIST_H

#include "KmLock.h"

typedef struct _KM_LIST
{
    KM_LOCK         Lock;
    LIST_ENTRY      Head;
    ULARGE_INTEGER  Count;
} KM_LIST, *PKM_LIST;

typedef void(__stdcall _KM_LIST_ITEM_CALLBACK)(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item);
typedef _KM_LIST_ITEM_CALLBACK  KM_LIST_ITEM_CALLBACK, *PKM_LIST_ITEM_CALLBACK;

typedef int(__stdcall _KM_LIST_ITEM_COMPARISON_CALLBACK)(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY ItemDefinition,
    __in    PLIST_ENTRY Item);
typedef _KM_LIST_ITEM_COMPARISON_CALLBACK KM_LIST_ITEM_COMPARISON_CALLBACK, *PKM_LIST_ITEM_COMPARISON_CALLBACK;

NTSTATUS __stdcall Km_List_Initialize(
    __in    PKM_LIST    List);

NTSTATUS __stdcall Km_List_AddItemEx(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockList);

NTSTATUS __stdcall Km_List_RemoveItemEx(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockList);

NTSTATUS __stdcall Km_List_GetCountEx(
    __in    PKM_LIST        List,
    __out   PULARGE_INTEGER Count,
    __in    BOOLEAN         CheckParams,
    __in    BOOLEAN         LockList);

NTSTATUS __stdcall Km_List_ClearEx(
    __in        PKM_LIST                List,
    __in_opt    PKM_LIST_ITEM_CALLBACK  ItemCallback,
    __in        BOOLEAN                 CheckParams,
    __in        BOOLEAN                 LockList);

NTSTATUS __stdcall Km_List_FindItemEx(
    __in        PKM_LIST                            List,
    __in        PLIST_ENTRY                         ItemDefinition,
    __in        PKM_LIST_ITEM_COMPARISON_CALLBACK   CmpCallback,
    __out_opt   PLIST_ENTRY                         *FoundItem,
    __in        BOOLEAN                             CheckParams,
    __in        BOOLEAN                             LockList);

#define Km_List_AddItem(List, Item)         Km_List_AddItemEx(List, Item, TRUE, TRUE)
#define Km_List_RemoveItem(List, Item)      Km_List_RemoveItem(List, Item, TRUE, TRUE)
#define Km_List_GetCount(List, CountPtr)    Km_List_GetCountEx(List, CountPtr, TRUE, TRUE)
#define Km_List_Clear(List, ItemCallback)   Km_List_ClearEx(List, ItemCallback, TRUE, TRUE)

#define Km_List_FindItem(List, ItemDefinition, CmpCallback, FoundItemPtr) \
    Km_List_FindItemEx( \
        List, \
        ItemDefinition, \
        CmpCallback, \
        FoundItemPtr, \
        TRUE, \
        TRUE)

#endif