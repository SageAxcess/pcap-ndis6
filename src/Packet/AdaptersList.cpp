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

#include "AdaptersList.h"

void CAdaptersList::InternalRefresh()
{
};

void CAdaptersList::ThreadRoutine()
{
    HANDLE  WaitArray[] = 
    {
        InternalGetStopEvent(),
        FRefreshRequestEvent
    };
};

CAdaptersList::CAdaptersList(
    __in_opt    LPVOID  Owner):
    CCSObject(Owner),
    CThread(Owner)
{
    
};

void CAdaptersList::Refresh()
{
};

DWORD CAdaptersList::GetCount() const
{
};