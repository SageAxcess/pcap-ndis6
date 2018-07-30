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
#pragma once

#include "BaseObject.h"
#include <windows.h>

class CCSObject:
    virtual public CBaseObject
{
private:
    CRITICAL_SECTION    FCriticalSection;

public:
    explicit CCSObject(
        __in_opt    LPVOID  Owner = nullptr);
    virtual ~CCSObject();

    virtual void Enter();
    virtual BOOL TryEnter();
    virtual void Leave();
};