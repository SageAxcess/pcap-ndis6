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

#include "UmMemoryPool.h"
#include "UmMemoryManager.h"

template <typename T>
typename CMemoryPool<T>::LPITEM CMemoryPool<T>::InternalCreateEntry()
{
    LPITEM  Result = UMM_AllocTypedWithSize<LPITEM>(FEntrySize);
    
    if (Assigned(Result))
    {
        RtlZeroMemory(Result, FEntrySize);
    }

    return Result;
};

template <typename T>
void CMemoryPool<T>::InternalDestroyEntry(
    __in    LPITEM  Item)
{
    RETURN_IF_FALSE(Assigned(Item));

    UMM_FreeMem(reinterpret_cast<LPVOID>(Item));
};

template <typename T>
T * CMemoryPool<T>::InternalAllocate()
{
    LPITEM  Item = nullptr;
    T       *Result = nullptr;

    if (!UTILS::LISTS::IsEmpty(&FAvailableEntries))
    {
        Item = CONTAINING_RECORD(
            UTILS::LISTS::RemoveHead(&FAvailableEntries),
            ITEM,
            Link);
        ListEntry = UTILS::LISTS::RemoveHead(&FAvailableEntries);
        FAvailableEntriesCount--;
    }
    else
    {
        if (!FFixedSize)
        {
            Item = InternalCreateItem();
        }
    }

    if (Assigned(Item))
    {
        if (UTILS::LISTS::InsertHead(
            &FAllocatedEntries,
            &Item->Link))
        {
            Result = reinterpret_cast<T *>(Item->Data);
            FAllocatedEntriesCount++;
        }
    }

    return Result;
};

template <typename T>
void CMemoryPool<T>::InternalRelease(
    __in    T   *Entry)
{
    LPITEM  Item = nullptr;

    RETURN_IF_FALSE(Assigned(Entry));

    Item = CONTAINING_RECORD(Entry, ITEM, Data);

    RETURN_IF_FALSE(
        UTILS::LISTS::RemoveEntry(&Item->Link));
    FAllocatedEntriesCount--;

    if (UTILS::LISTS::InsertTail(
        &FAvailableEntries,
        &Item->Link))
    {
        FAvailableEntriesCount++
    }
    else
    {
        InternalDestroyEntry(Item);
    }
};

template <typename T>
SIZE_T CMemoryPool<T>::InternalGetPoolSize() const
{
    return
        InternalGetAllocationsCount() +
        InternalGetAvailableEntriesCount();
};

template <typename T>
SIZE_T CMemoryPool<T>::InternalGetAllocationsCount() const
{
    return FAllocatedEntriesCount;
};

template <typename T>
SIZE_T CMemoryPool<T>::InternalGetAvailableEntriesCount() const
{
    return FAvailableEntriesCount;
};

template <typename T>
CMemoryPool<T>::CMemoryPool(
    __in_opt    LPVOID  Owner = nullptr,
    __in_opt    BOOL    FixedSize = FALSE,
    __in_opt    SIZE_T  EntrySize = sizeof(T)):
    CCSObject(Owner)
{
    FFixedSize = FixedSize;
    FEntrySize = ItemSize;

    UTILS::LISTS::Initialize(&FAllocatedEntries);
    UTILS::LISTS::Initialize(&FAvailableEntries);

    THROW_EXCEPTION_IF_FALSE(
        FEntrySize > 0,
        MEMORY_POOL_EXCEPTION_INVALID_PARAMS);
};

template <typename T>
CMemoryPool<T>::~CMemoryPool()
{
    Enter();
    InternalCleanup();
    Leave();
};

template <typename T>
T * CMemoryPool<T>::Allocate()
{
    T   *Result = nullptr;

    Enter();
    __try
    {
        Result = InternalAllocate();
    }
    __finally
    {
        Leave();
    }

    return Result;
};

template <typename T>
void CMemoryPool<T>::Release(
    __in    T   *Entry)
{
    RETURN_IF_FALSE(Assigned(Entry));

    Enter();
    __try
    {
        InternalRelease();
    }
    __finally
    {
        Leave();
    }
};

template <typename T>
SIZE_T CMemoryPool<T>::GetPoolSize() const
{
    SIZE_T  Result = 0;

    (const_cast<CMemoryPool<T> *>(this))->Enter();
    __try
    {
        Result = InternalGetPoolSize();
    }
    __finally
    {
        (const_cast<CMemoryPool<T> *>(this))->Leave();
    }

    return Result;
};

template <typename T>
SIZE_T CMemoryPool<T>::GetAllocationsCount() const
{
    SIZE_T  Result = 0;

    (const_cast<CMemoryPool<T> *>(this))->Enter();
    __try
    {
        Result = InternalGetAllocationsCount();
    }
    __finally
    {
        (const_cast<CMemoryPool<T> *>(this))->Leave();
    }

    return Result;
};

template <typename T>
SIZE_T CMemoryPool<T>::GetAvailableEntriesCount() const
{
    SIZE_T  Result = 0;

    (const_cast<CMemoryPool<T> *>(this))->Enter();
    __try
    {
        Result = InternalGetAvailableEntriesCount();
    }
    __finally
    {
        (const_cast<CMemoryPool<T> *>(this))->Leave();
    }

    return Result;
};

template <typename T>
SIZE_T CMemoryPool<T>::GetEntrySize() const
{
    SIZE_T  Result = 0;

    Enter();
    __try
    {
        Result = InternalGetEntrySize();
    }
    __finally
    {
        Leave();
    }

    return Result;
};