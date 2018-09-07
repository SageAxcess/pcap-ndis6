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
#include "CSObject.h"
#include "ThreadObject.h"
#include <queue>

#define TASK_THREAD_EXCEPTION_FAILED_TO_CREATE_NEW_TASK_EVENT   L"Task thread exception: failed to create event object (new task event)"

#define TASK_THREAD_ROUTINE_FLAG_NONE       0x0
#define TASK_THREAD_ROUTINE_FLAG_CANCELLED  0x1

class CTaskThread;

typedef void(__stdcall _TASK_THREAD_ROUTINE)(
    __in    const   CTaskThread &Thread,
    __in    const   LPVOID      Params,
    __in    const   DWORD       Flags);
typedef _TASK_THREAD_ROUTINE    *PTASK_THREAD_ROUTINE, *LPTASK_THREAD_ROUTINE;

class CTaskThread :
    virtual public CThread,
    virtual public CCSObject
{
protected:
    typedef struct _TASK
    {
        LPTASK_THREAD_ROUTINE   TaskRoutine;
        LPVOID                  Params;
        HANDLE                  CompletionEventHandle;
    } TASK, *PTASK, *LPTASK;

private:
    std::queue<TASK>    FTasks;
    HANDLE              FNewTaskEvent = NULL;

protected:
    virtual BOOL InternalGetTask(
        __out   LPTASK  Task);

    virtual BOOL InternalProcessTask(
        __in    const   LPTASK  Task,
        __in    const   BOOL    CancellTask = FALSE);

    virtual BOOL InternalSubmitTask(
        __in        LPTASK_THREAD_ROUTINE   TaskRoutine,
        __in_opt    LPVOID                  Params = nullptr,
        __in_opt    HANDLE                  CompletionEvent = NULL);

    virtual void ThreadRoutine();

    virtual BOOL InternalInitialize();

    virtual void InternalFinalize();

public:
    CTaskThread(
        __in_opt    LPVOID  Owner = nullptr);
    virtual ~CTaskThread();

    virtual BOOL SubmitTask(
        __in        LPTASK_THREAD_ROUTINE   TaskRoutine,
        __in_opt    LPVOID                  Params = nullptr,
        __in_opt    HANDLE                  CompletionEvent = NULL);
};