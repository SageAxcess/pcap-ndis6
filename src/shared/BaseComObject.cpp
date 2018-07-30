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

#include "BaseComObject.h"

CBaseComObject::CBaseComObject(
    __in_opt    LPVOID  Owner) :
    CBaseObject(Owner)
{
};

CBaseComObject::~CBaseComObject()
{
};

HRESULT __stdcall CBaseComObject::QueryInterface(
    __in    REFIID  riid,
    __out   LPVOID  *ppvObject)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(ppvObject),
        E_INVALIDARG);

    *ppvObject = nullptr;

    if (riid == IID_IUnknown)
    {
        *ppvObject =
            reinterpret_cast<LPVOID>(
                reinterpret_cast<IUnknown *>(this));
        return NOERROR;
    }

    return E_NOINTERFACE;
};

ULONG __stdcall CBaseComObject::AddRef()
{
    InterlockedIncrement(&FRefCnt);
    return FRefCnt;
};

ULONG __stdcall CBaseComObject::Release()
{
    ULONG Result = InterlockedDecrement(&FRefCnt);

    if (Result == 0)
    {
        delete this;
    }

    return Result;
};