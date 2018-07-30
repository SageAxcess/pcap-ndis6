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

class CBaseComObject :
    virtual public CBaseObject,
    virtual public IUnknown
{
protected:
    ULONG   FRefCnt = 0;

public:
    explicit CBaseComObject(
        __in_opt    LPVOID  Owner = nullptr);

    virtual ~CBaseComObject();

    virtual HRESULT __stdcall IUnknown::QueryInterface(
        __in    REFIID  riid,
        __out   LPVOID  *ppvObject);

    virtual ULONG __stdcall IUnknown::AddRef();

    virtual ULONG __stdcall IUnknown::Release();

};
