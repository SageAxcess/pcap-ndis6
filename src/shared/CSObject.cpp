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

#include "CSObject.h"

CCSObject::CCSObject(
    __in_opt    LPVOID  Owner):
    CBaseObject(Owner)
{
    InitializeCriticalSection(&FCriticalSection);
};

CCSObject::~CCSObject()
{
    DeleteCriticalSection(&FCriticalSection);
};

void CCSObject::Enter()
{
    EnterCriticalSection(&FCriticalSection);
};

BOOL CCSObject::TryEnter()
{
    return TryEnterCriticalSection(&FCriticalSection);
};

void CCSObject::Leave()
{
    LeaveCriticalSection(&FCriticalSection);
};