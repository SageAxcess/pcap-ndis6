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

#pragma once

#include "CommonDefs.h"
#include "BaseObject.h"
#include "LinkedList.h"
#include "CSObject.h"

#define MEMORY_POOL_EXCEPTION_INVALID_PARAMS    L"Memory pool exception: invalid parameters"

template <typename T> class CMemoryPool:
    virtual public CCSObject
{
protected:
    typedef struct _ITEM
    {
        UTILS::LISTS::ENTRY Link;
        
        unsigned char       Data[1];

    } ITEM, *PITEM, *LPITEM;

private:
    UTILS::LISTS::ENTRY FAvailableEntries;
    SIZE_T              FAvailableEntriesCount = 0;

    UTILS::LISTS::ENTRY FAllocatedEntries;
    SIZE_T              FAllocatedEntriesCount = 0;

    BOOL                FFixedSize = FALSE;

    SIZE_T              FEntrySize = sizeof(T);

protected:

    virtual LPITEM InternalCreateEntry();

    virtual void InternalDestroyEntry(
        __in    LPITEM  Item);

    virtual T * InternalAllocate();

    virtual void InternalRelease(
        __in    T   *Entry);

    virtual SIZE_T InternalGetPoolSize() const;

    virtual SIZE_T InternalGetAllocationsCount() const;

    virtual SIZE_T InternalGetAvailableEntriesCount() const;

public:
    explicit CMemoryPool(
        __in_opt    LPVOID  Owner = nullptr,
        __in_opt    BOOL    FixedSize = FALSE,
        __in_opt    SIZE_T  EntrySize = sizeof(T));

    virtual ~CMemoryPool();

    virtual T * Allocate();

    virtual void Release(
        __in    T   *Entry);

    virtual SIZE_T GetPoolSize() const;

    virtual SIZE_T GetAllocationsCount() const;

    virtual SIZE_T GetAvailableEntriesCount() const;

    virtual SIZE_T GetEntrySize() const;

    CLASS_READ_ONLY_PROPERTY(SIZE_T, PoolSize);
    CLASS_READ_ONLY_PROPERTY(SIZE_T, AllocationsCount);
    CLASS_READ_ONLY_PROPERTY(SIZE_T, AvailableEntriesCount);
    CLASS_READ_ONLY_PROPERTY(SIZE_T, EntrySize);
};
