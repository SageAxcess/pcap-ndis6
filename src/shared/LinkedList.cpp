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

#include "LinkedList.h"
#include "CommonDefs.h"

__forceinline void UTILS::LISTS::Initialize(
    __in    LPENTRY ListHead)
{
    THROW_EXCEPTION_IF_FALSE(
        Assigned(ListHead),
        LIST_EXCEPTION_INVALID_PARAMETER);

    ListHead->Flink = ListHead->Blink = ListHead;
};

__forceinline BOOL UTILS::LISTS::IsEmpty(
    __in    LPENTRY ListHead)
{
    THROW_EXCEPTION_IF_FALSE(
        Assigned(ListHead),
        LIST_EXCEPTION_INVALID_PARAMETER);

    return
        (ListHead->Flink == ListHead) &&
        (ListHead->Blink == ListHead);
};

__forceinline UTILS::LISTS::LPENTRY UTILS::LISTS::RemoveHead(
    __in    LPENTRY ListHead)
{
    LPENTRY Result = nullptr;

    RETURN_VALUE_IF_FALSE(
        IsEmpty(ListHead),
        nullptr);

    Result = ListHead->Flink;

    ListHead->Flink = Result->Flink;
    ListHead->Flink->Blink = ListHead;

    return Result;
};

template <typename T>
__forceinline T * UTILS::LISTS::RemoveHeadAs(
    __in    LPENTRY ListHead)
{
    return reinterpret_cast<T *>(RemoveHead(ListHead));
};

__forceinline UTILS::LISTS::LPENTRY UTILS::LISTS::RemoveTail(
    __in    LPENTRY ListHead)
{
    LPENTRY Result = nullptr;

    RETURN_VALUE_IF_FALSE(
        IsEmpty(ListHead),
        nullptr);

    Result = ListHead->Blink;

    ListHead->Blink = Result->Blink;
    ListHead->Blink->Flink = ListHead;

    return Result;
};

__forceinline BOOL UTILS::LISTS::RemoveEntry(
    __in    LPENTRY Entry)
{
    LPENTRY PreviousEntry = nullptr;
    LPENTRY NextEntry = nullptr;

    NextEntry = Entry->Flink;
    PreviousEntry = Entry->Blink;

    if ((NextEntry->Blink != Entry) || (PreviousEntry->Flink != Entry))
    {
        return FALSE;
    }

    PreviousEntry->Flink = NextEntry;
    NextEntry->Blink = PreviousEntry;

    return TRUE;
};

__forceinline BOOL UTILS::LISTS::InsertHead(
    __in    LPENTRY ListHead,
    __in    LPENTRY Entry)
{
    RETURN_VALUE_IF_FALSE(
        (Assigned(ListHead)) &&
        (Assigned(Entry)),
        FALSE);

    Entry->Flink = ListHead->Flink;
    ListHead->Flink->Blink = Entry;
    Entry->Blink = ListHead;
    ListHead->Flink = Entry;

    return TRUE;
};

__forceinline BOOL UTILS::LISTS::InsertTail(
    __in    LPENTRY ListHead,
    __in    LPENTRY Entry)
{
    RETURN_VALUE_IF_FALSE(
        (Assigned(ListHead)) &&
        (Assigned(Entry)),
        FALSE);

    Entry->Blink = ListHead->Blink;
    ListHead->Blink->Flink = Entry;
    Entry->Flink = ListHead;
    ListHead->Blink = Entry;

    return TRUE;
};