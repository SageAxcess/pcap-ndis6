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
#include <Windows.h>

#define THREAD_EXCEPTION_FAILED_TO_CREATE_STOP_EVENT    L"Thread exception: failed to create event object (stop event)"
#define THREAD_EXCEPTION_FAILED_TO_CREATE_STOPPED_EVENT L"Thread exception: failed to create event object (stopped event)"
#define THREAD_EXCEPTION_FAILED_TO_CREATE_THREAD        L"Thread exception: failed to create thread"

class CThread:
    virtual public CBaseObject
{
public:
    typedef void(__stdcall *LPTHREAD_FINISH_CALLBACK)(
        __in    const   CThread   *ThreadObject);

private:
    DWORD                       FThreadId = 0;
    DWORD                       FReturnValue = 0;
    BOOL                        FFinished = FALSE;
    BOOL                        FThreadTerminated = FALSE;
    BOOL                        FCreateSuspended = FALSE;
    BOOL                        FFreeOnTerminate = FALSE;

    HANDLE                      FThreadHandle = NULL;
    HANDLE                      FStopEvent = NULL;
    HANDLE                      FStoppedEvent = NULL;

    LPTHREAD_FINISH_CALLBACK    FOnFinish = nullptr;

private:
    void ThreadFinished();

    static DWORD __stdcall WINAPI ThreadProc(
        __in    LPVOID  Parameter);

protected:
    virtual HANDLE InternalGetStopEvent() const;

    virtual void ThreadRoutine();

public:
    explicit CThread(
        __in_opt    LPVOID  Owner = nullptr,
        __in_opt    BOOL    InitiallySuspended = FALSE);

    virtual ~CThread();

    virtual void Stop(
        __in_opt    DWORD Timeout = INFINITE);

    virtual void Suspend();

    virtual void Resume();

    virtual void Terminate();

    virtual LPTHREAD_FINISH_CALLBACK GetOnFinish() const;

    virtual void SetOnFinish(
        __in    LPTHREAD_FINISH_CALLBACK    Value);

    virtual BOOL GetFreeOnTerminate() const;

    virtual void SetFreeOnTerminate(
        __in    BOOL    Value);

    CLASS_READ_ONLY_PROPERTY(DWORD, Id);
    CLASS_PROPERTY(LPTHREAD_FINISH_CALLBACK, OnFinish);
    CLASS_PROPERTY(BOOL, FreeOnTerminate);
};