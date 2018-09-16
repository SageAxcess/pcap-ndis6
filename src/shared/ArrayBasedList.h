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

#include "UmMemoryManager.h"
#include "BaseObject.h"

class CArrayBasedList:
    virtual public CBaseObject
{
private:
    LPVOID      *FItems = nullptr;
    SIZE_T      FCapacity = 0;
    SIZE_T      FCount = 0;

protected:
    virtual SSIZE_T InternalAdd(
        __in    const   LPVOID  Item);

    virtual BOOL InternalDelete(
        __in    const   SSIZE_T Index);

    virtual BOOL InternalFind(
        __in        const   LPVOID      Item,
        __out_opt           PSSIZE_T    Index) const;

    virtual SSIZE_T InternalIndexOf(
        __in    const   LPVOID  Item) const;

    virtual BOOL InternalExtract(
        __in    const   SSIZE_T Index,
        __out           LPVOID  *Item);

    virtual LPVOID InternalGetItems(
        __in    const   SSIZE_T Index) const;

public:
    explicit CArrayBasedList(
        __in_opt    LPVOID  Owner);
    virtual ~CArrayBasedList();

    virtual SSIZE_T Add(
        __in    const   LPVOID  Item);

    virtual BOOL Delete(
        __in    const   SSIZE_T Index);

    virtual BOOL Find(
        __in        const   LPVOID      Item,
        __out_opt           PSSIZE_T    Index) const;

    virtual SSIZE_T IndexOf(
        __in    const   LPVOID  Item);

    virtual BOOL Extract(
        __in    const   SSIZE_T Index,
        __out           LPVOID  *Item);

    virtual LPVOID GetItems(
        __in    const   SSIZE_T Index) const;

    __declspec(property(get = GetItems)) LPVOID Items[];
};
