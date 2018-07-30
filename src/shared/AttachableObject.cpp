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

#include "AttachableObject.h"
#include "StrUtils.h"

REFIID CAttachableObject::InternalGetConnectionPointRIID()
{
    return GUID_NULL;
};

BOOL CAttachableObject::InternalInitialize()
{
    RETURN_VALUE_IF_FALSE(
        Assigned(FConnectionPointContainer),
        FALSE);

    FSelfInterface = static_cast<IUnknown *>(this);

    REFIID          ConnectionPointRIID = InternalGetConnectionPointRIID();

    HRESULT hResult = FConnectionPointContainer->FindConnectionPoint(
        ConnectionPointRIID,
        &FConnectionPoint);
    RETURN_VALUE_IF_FALSE(
        SUCCEEDED(hResult),
        FALSE);

    return TRUE;
};

BOOL CAttachableObject::InternalFinalize()
{
    BOOL    Result = FALSE;

    if (Assigned(FConnectionPoint))
    {
        FConnectionPoint->Release();
        FConnectionPoint = nullptr;
    }

    if (Assigned(FConnectionPointContainer))
    {
        FConnectionPointContainer->Release();
        FConnectionPointContainer = nullptr;
    }

    return Result;
};

CAttachableObject::CAttachableObject(
    __in_opt    LPVOID  Owner) :
    CBaseComObject(Owner)
{
    FRefCnt = 1;
};

CAttachableObject::~CAttachableObject()
{

};

ULONG STDMETHODCALLTYPE CAttachableObject::Release()
{
    ULONG   Result = InterlockedDecrement(&FRefCnt);

    if ((Result == 0) && (!FDestructorInProgress))
    {
        delete this;
    }

    return Result;
};

BOOL STDMETHODCALLTYPE CAttachableObject::Attach(
    __in    IConnectionPointContainer   *ConnectionPointContainer)
{
    BOOL    Result = FALSE;

    RETURN_VALUE_IF_FALSE(
        Assigned(ConnectionPointContainer),
        FALSE);

    RETURN_VALUE_IF_FALSE(
        !Assigned(FConnectionPointContainer),
        FALSE);

    FConnectionPointContainer = ConnectionPointContainer;
    FConnectionPointContainer->AddRef();
    __try
    {
        LEAVE_IF_FALSE(InternalInitialize());
        __try
        {
            Result = SUCCEEDED(FConnectionPoint->Advise(FSelfInterface, &FConnectionCookie));
        }
        __finally
        {
            if (!Result)
            {
                InternalFinalize();
            }
        }
    }
    __finally
    {
        if ((!Result) &&
            (Assigned(FConnectionPointContainer)))
        {
            FConnectionPointContainer->Release();
            FConnectionPointContainer = nullptr;
        }
    }

    return Result;
};

BOOL STDMETHODCALLTYPE CAttachableObject::Detach()
{
    BOOL    Result = FALSE;

    RETURN_VALUE_IF_FALSE(
        FConnectionCookie != 0,
        FALSE);

    Result = SUCCEEDED(FConnectionPoint->Unadvise(FConnectionCookie));
    if (Result)
    {
        FConnectionCookie = 0;
        InternalFinalize();
    }

    return Result;
};