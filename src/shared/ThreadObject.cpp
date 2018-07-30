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

#include "ThreadObject.h"

void CThread::ThreadFinished()
{
    BOOL    ShouldFreeObject;

    RETURN_IF_FALSE(Assigned(this));
    
    ShouldFreeObject = FFreeOnTerminate;
    
    if (FStoppedEvent != NULL)
    {
        SetEvent(FStoppedEvent);
    }

    if (ShouldFreeObject)
    {
        delete this;
    }
};

DWORD __stdcall WINAPI CThread::ThreadProc(
    __in    LPVOID  Parameter)
{
    DWORD           Result = 0;
    CThread   *ThreadObject = nullptr;

    RETURN_VALUE_IF_FALSE(
        Assigned(Parameter),
        0);

    ThreadObject = reinterpret_cast<CThread *>(Parameter);
    __try
    {
        if (!ThreadObject->FThreadTerminated)
        {
            __try
            {
                ThreadObject->FCreateSuspended = FALSE;
                ThreadObject->ThreadRoutine();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }
    }
    __finally
    {
        Result = ThreadObject->FReturnValue;
        ThreadObject->FFinished = TRUE;
        ThreadObject->ThreadFinished();
    }

    ExitThread(Result);
};

HANDLE CThread::InternalGetStopEvent() const
{
    return FStopEvent;
};

void CThread::ThreadRoutine()
{
};

CThread::CThread(
    __in_opt    LPVOID  Owner,
    __in_opt    BOOL    InitiallySuspended):
    CBaseObject(Owner)
{
    FCreateSuspended = InitiallySuspended;

    FStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    THROW_EXCEPTION_IF_FALSE(
        FStopEvent != NULL,
        THREAD_EXCEPTION_FAILED_TO_CREATE_STOP_EVENT);

    FStoppedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    THROW_EXCEPTION_IF_FALSE(
        FStoppedEvent != NULL,
        THREAD_EXCEPTION_FAILED_TO_CREATE_STOPPED_EVENT);

    FThreadHandle = CreateThread(
        nullptr,
        0,
        ThreadProc,
        reinterpret_cast<LPVOID>(this),
        InitiallySuspended ? CREATE_SUSPENDED : 0,
        &FThreadId);
    THROW_EXCEPTION_IF_FALSE(
        FThreadHandle != NULL,
        THREAD_EXCEPTION_FAILED_TO_CREATE_THREAD);
};

CThread::~CThread()
{
    if (!FFinished)
    {
        if (FCreateSuspended)
        {
            FThreadTerminated = TRUE;
            Resume();
        }
        else
        {
            Terminate();
        }
    };
    if (FThreadHandle != NULL)
    {
        CloseHandle(FThreadHandle);
        FThreadHandle = NULL;
    }
    if (FStopEvent != NULL)
    {
        CloseHandle(FStopEvent);
        FStopEvent = NULL;
    }
    if (FStoppedEvent != NULL)
    {
        CloseHandle(FStoppedEvent);
        FStoppedEvent = NULL;
    }
};

void CThread::Stop(
    __in_opt    DWORD Timeout)
{
    if ((FStopEvent != NULL) &&
        (FStoppedEvent != NULL))
    {
        SetEvent(FStopEvent);
        WaitForSingleObject(FStoppedEvent, Timeout);
    }
};

void CThread::Suspend()
{
    if (FThreadHandle != NULL)
    {
        SuspendThread(FThreadHandle);
    }
};

void CThread::Resume()
{
    if (FThreadHandle != NULL)
    {
        ResumeThread(FThreadHandle);
    }
};

void CThread::Terminate()
{
    if ((FThreadHandle != NULL) &&
        (!FFinished))
    {
        TerminateThread(FThreadHandle, FReturnValue);
    }
};

CThread::LPTHREAD_FINISH_CALLBACK CThread::GetOnFinish() const
{
    return FOnFinish;
};

void CThread::SetOnFinish(
    __in    CThread::LPTHREAD_FINISH_CALLBACK Value)
{
    FOnFinish = Value;
};

BOOL CThread::GetFreeOnTerminate() const
{
    return FFreeOnTerminate;
};

void CThread::SetFreeOnTerminate(
    __in    BOOL    Value)
{
    FFreeOnTerminate = Value;
};