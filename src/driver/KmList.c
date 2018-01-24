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

#include "..\shared\CommonDefs.h"
#include "KmList.h"

NTSTATUS __stdcall Km_List_Initialize(
    __in    PKM_LIST    List)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(List),
        STATUS_INVALID_PARAMETER);

    RtlZeroMemory(List, sizeof(KM_LIST));

    Status = Km_Lock_Initialize(&List->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    InitializeListHead(&List->Head);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_AddItemEx(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(List),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Item),
            STATUS_INVALID_PARAMETER_2);
    }

    if (LockList)
    {
        Status = Km_Lock_Acquire(&List->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        InsertTailList(&List->Head, Item);
        List->Count.QuadPart++;
    }
    __finally
    {
        if (LockList)
        {
            Km_Lock_Release(&List->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_RemoveItemEx(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(List),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Item),
            STATUS_INVALID_PARAMETER_2);
    }

    if (LockList)
    {
        Status = Km_Lock_Acquire(&List->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        if (List->Count.QuadPart > 0)
        {
            RemoveEntryList(Item);
            List->Count.QuadPart--;
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    __finally
    {
        if (LockList)
        {
            Km_Lock_Release(&List->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_GetCountEx(
    __in    PKM_LIST        List,
    __out   PULARGE_INTEGER Count,
    __in    BOOLEAN         CheckParams,
    __in    BOOLEAN         LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(List),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Count),
            STATUS_INVALID_PARAMETER_2);
    }

    if (LockList)
    {
        Status = Km_Lock_Acquire(&List->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        Count->QuadPart = List->Count.QuadPart;
    }
    __finally
    {
        if (LockList)
        {
            Km_Lock_Release(&List->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_ClearEx(
    __in        PKM_LIST                List,
    __in_opt    PKM_LIST_ITEM_CALLBACK  ItemCallback,
    __in        BOOLEAN                 CheckParams,
    __in        BOOLEAN                 LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    LIST_ENTRY  TmpList;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(List),
            STATUS_INVALID_PARAMETER_1);
    }

    InitializeListHead(&TmpList);

    if (LockList)
    {
        Status = Km_Lock_Acquire(&List->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        if (List->Count.QuadPart > 0)
        {
            List->Head.Blink->Flink = &TmpList;
            List->Head.Flink->Blink = &TmpList;

            TmpList.Blink = List->Head.Blink;
            TmpList.Flink = List->Head.Flink;

            List->Count.QuadPart = 0;
            InitializeListHead(&List->Head);
        }
    }
    __finally
    {
        if (LockList)
        {
            Km_Lock_Release(&List->Lock);
        }
    }

    if (Assigned(ItemCallback))
    {
        while (!IsListEmpty(&TmpList))
        {
            PLIST_ENTRY Entry = RemoveHeadList(&TmpList);
            ItemCallback(List, Entry);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_FindItemEx(
    __in        PKM_LIST                            List,
    __in        PVOID                               ItemDefinition,
    __in        PKM_LIST_ITEM_COMPARISON_CALLBACK   CmpCallback,
    __out_opt   PLIST_ENTRY                         *FoundItem,
    __in        BOOLEAN                             CheckParams,
    __in        BOOLEAN                             LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PLIST_ENTRY FoundEntry = NULL;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(List),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(CmpCallback),
            STATUS_INVALID_PARAMETER_3);
    }

    if (LockList)
    {
        Status = Km_Lock_Acquire(&List->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        PLIST_ENTRY TmpEntry;

        for (TmpEntry = List->Head.Flink;
             TmpEntry != &List->Head;
             TmpEntry = TmpEntry->Flink)
        { 
            if (CmpCallback(List, ItemDefinition, TmpEntry) == 0)
            {
                FoundEntry = TmpEntry;
                break;
            }
        };

        if (!Assigned(FoundEntry))
        {
            Status = STATUS_NOT_FOUND;
        }
    }
    __finally
    {
        if (LockList)
        {
            Km_Lock_Release(&List->Lock);
        }
    }

    if (Assigned(FoundItem))
    {
        *FoundItem = FoundEntry;
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_ExtractEntriesEx(
    __in    PKM_LIST        List,
    __in    PLIST_ENTRY     DestinationList,
    __inout PULARGE_INTEGER Count,
    __in    BOOLEAN         CheckParams,
    __in    BOOLEAN         LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(List),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(DestinationList),
            STATUS_INVALID_PARAMETER_2);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Count),
            STATUS_INVALID_PARAMETER_3);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Count->QuadPart > 0,
            STATUS_INVALID_PARAMETER_3);
    }

    if (LockList)
    {
        Status = Km_Lock_Acquire(&List->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        if (Count->QuadPart < MAXULONGLONG)
        {
            ULONGLONG   ItemsRemoved = 0;
            ULONGLONG   ItemsToRemove =
                List->Count.QuadPart > Count->QuadPart ?
                Count->QuadPart :
                List->Count.QuadPart;
            LIST_ENTRY  TmpList;

            InitializeListHead(&TmpList);

            while (ItemsRemoved < ItemsToRemove)
            {
                PLIST_ENTRY Entry = RemoveHeadList(&List->Head);
                InsertTailList(&TmpList, Entry);
                ItemsRemoved++;
            }

            List->Count.QuadPart -= ItemsRemoved;

            DestinationList->Blink->Flink = TmpList.Flink;
            TmpList.Flink->Blink = DestinationList->Blink;

            TmpList.Blink->Flink = DestinationList;
            DestinationList->Blink = TmpList.Blink;

            Count->QuadPart = ItemsRemoved;
        }
        else
        {
            DestinationList->Blink->Flink = List->Head.Flink;
            List->Head.Flink->Blink = DestinationList->Blink;

            List->Head.Blink->Flink = DestinationList;
            DestinationList->Blink = List->Head.Blink;

            Count->QuadPart = List->Count.QuadPart;
            List->Count.QuadPart = 0;
        }

        if (List->Count.QuadPart == 0)
        {
            InitializeListHead(&List->Head);
        }

    }
    __finally
    {
        if (LockList)
        {
            Km_Lock_Release(&List->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_RemoveListHeadEx(
    __in    PKM_LIST    List,
    __out   PLIST_ENTRY *Entry,
    __in    BOOLEAN     CheckParams,
    __in    BOOLEAN     LockList)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    if (CheckParams)
    {
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(List),
            STATUS_INVALID_PARAMETER_1);
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Entry),
            STATUS_INVALID_PARAMETER_2);
    }

    if (LockList)
    {
        Status = Km_Lock_Acquire(&List->Lock);
        GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    }
    __try
    {
        LEAVE_IF_FALSE_SET_STATUS(
            List->Count.QuadPart > 0,
            STATUS_NO_MORE_ENTRIES);
        
        *Entry = RemoveHeadList(&List->Head);

        List->Count.QuadPart--;
    }
    __finally
    {
        if (LockList)
        {
            Km_Lock_Release(&List->Lock);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_List_Lock(
    __in    PKM_LIST    List)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(List),
        STATUS_INVALID_PARAMETER);

    return Km_Lock_Acquire(&List->Lock);
};

NTSTATUS __stdcall Km_List_Unlock(
    __in    PKM_LIST    List)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(List),
        STATUS_INVALID_PARAMETER);

    return Km_Lock_Release(&List->Lock);
};