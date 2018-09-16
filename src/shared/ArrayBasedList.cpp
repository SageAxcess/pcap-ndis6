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

#include "ArrayBasedList.h"

SSIZE_T CArrayBasedList::InternalAdd(
    __in    const   LPVOID  Item)
{
};

BOOL CArrayBasedList::InternalDelete(
    __in    const   SSIZE_T Index)
{
};

BOOL CArrayBasedList::InternalFind(
    __in        const   LPVOID      Item,
    __out_opt           PSSIZE_T    Index) const
{
};

SSIZE_T CArrayBasedList::InternalIndexOf(
    __in    const   LPVOID  Item) const
{
};

BOOL CArrayBasedList::InternalExtract(
    __in    const   SSIZE_T Index,
    __out           LPVOID  *Item)
{
};

LPVOID CArrayBasedList::InternalGetItems(
    __in    const   SSIZE_T Index) const
{

};

CArrayBasedList::CArrayBasedList(
    __in_opt    LPVOID  Owner)
{
};

CArrayBasedList::~CArrayBasedList()
{
};

SSIZE_T CArrayBasedList::Add(
    __in    const   LPVOID  Item)
{
    return InternalAdd(Item);
};

BOOL CArrayBasedList::Delete(
    __in    const   SSIZE_T Index)
{
    return InternalDelete(Index);
};

BOOL CArrayBasedList::Find(
    __in        const   LPVOID      Item,
    __out_opt           PSSIZE_T    Index) const
{
    return InternalFind(Item, Index);
};

SSIZE_T CArrayBasedList::IndexOf(
    __in    const   LPVOID  Item)
{
    return InternalIndexOf(Item);
};

BOOL CArrayBasedList::Extract(
    __in    const   SSIZE_T Index,
    __out           LPVOID  *Item)
{
    return InternalExtract(Index, Item);
};

LPVOID CArrayBasedList::GetItems(
    __in    const   SSIZE_T Index) const
{
    return InternalGetItems(Index);
};
