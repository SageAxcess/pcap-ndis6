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
#include "BaseComObject.h"

#include <OCIdl.h>

class CAttachableObject :
    virtual public CBaseComObject
{
protected:
    BOOL                        FDestructorInProgress = FALSE;
    IUnknown                    *FSelfInterface = nullptr;
    DWORD                       FConnectionCookie = 0;
    IConnectionPointContainer   *FConnectionPointContainer = nullptr;
    IConnectionPoint            *FConnectionPoint = nullptr;

    virtual REFIID InternalGetConnectionPointRIID();
    virtual BOOL InternalInitialize();
    virtual BOOL InternalFinalize();

public:
    CAttachableObject(
        __in_opt    LPVOID  Owner = nullptr);
    virtual ~CAttachableObject();

    virtual ULONG STDMETHODCALLTYPE Release();

    virtual BOOL STDMETHODCALLTYPE Attach(
        __in    IConnectionPointContainer   *ConnectionPointContainer);

    virtual BOOL STDMETHODCALLTYPE Detach();
};