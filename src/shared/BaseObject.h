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
#include <Windows.h>

class CBaseObject
{
private:
    LPVOID  FOwner = nullptr;

public:
    CBaseObject(
        __in_opt    LPVOID  Owner = nullptr);
    virtual ~CBaseObject();

    template <typename T> 
    T *GetOwnerAs() const;

    virtual LPVOID GetOwner() const;
    virtual void SetOwner(
        __in    LPVOID  Value);

    CLASS_PROPERTY(LPVOID, Owner);
};