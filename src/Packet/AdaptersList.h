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

#include "..\shared\CommonDefs.h"
#include "..\shared\BaseComObject.h"
#include "..\shared\ThreadObject.h"
#include "..\shared\CSObject.h"
#include "..\shared\TaskThread.h"
#include "..\shared\UmMemoryPool.h"

#include <netlistmgr.h>
#include <string>

class CAdaptersRefreshThread:
    virtual public CTaskThread
{
};

class CAdaptersList :
    virtual public CCSObject,
    virtual protected CThread
{
private:
    HANDLE  FRefreshRequestEvent = NULL;

protected:
    virtual void InternalRefresh();

    virtual void ThreadRoutine();

public:
    CAdaptersList(
        __in_opt    LPVOID  Owner = nullptr);
    virtual ~CAdaptersList();

    virtual void Refresh();

    virtual DWORD GetCount() const;
    
    CLASS_READ_ONLY_PROPERTY(DWORD, Count);
};