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

class CAdaptersListTaskThread :
    virtual public CTaskThread
{
private:
    INetworkListManager *FManager = nullptr;

protected:
    virtual void InternalProcessTask(
        __in    const   LPTASK  Task);

    virtual BOOL InternalInitialize();

    virtual void InternalFinalize();

public:
    CAdaptersListTaskThread(
        __in_opt    LPVOID  Owner = nullptr);
    virtual ~CAdaptersListTaskThread();

};

class CAdaptersList :
    virtual public CCSObject,
    virtual protected CThread
{
private:
    CAdaptersListTaskThread *FTaskThread = nullptr;

protected:
    virtual void InternalRefresh();

    virtual void ThreadRoutine();

public:
    CAdaptersList();
    virtual ~CAdaptersList();

    virtual void Refresh();

    virtual DWORD GetCount() const;