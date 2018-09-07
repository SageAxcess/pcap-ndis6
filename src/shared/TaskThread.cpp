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

#include "TaskThread.h"

BOOL CTaskThread::InternalGetTask(
    __out   LPTASK  Task)
{
    BOOL    Result = FALSE;

    RETURN_VALUE_IF_FALSE(
        Assigned(Task),
        FALSE);

    Enter();
    __try
    {
        if (!FTasks.empty())
        {
            *Task = FTasks.front();
            FTasks.pop();
            Result = TRUE;
        }
    }
    __finally
    {
        Leave();
    }

    return Result;
};

BOOL CTaskThread::InternalProcessTask(
    __in    const   LPTASK  Task,
    __in    const   BOOL    CancellTask)
{
    BOOL    Result = FALSE;

    RETURN_VALUE_IF_FALSE(
        Assigned(Task),
        FALSE);

    __try
    {
        Task->TaskRoutine(
            *this,
            Task->Params,
            CancellTask ? TASK_THREAD_ROUTINE_FLAG_CANCELLED : TASK_THREAD_ROUTINE_FLAG_NONE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    if (Task->CompletionEventHandle != NULL)
    {
        SetEvent(Task->CompletionEventHandle);
    }

    return Result;
};

BOOL CTaskThread::InternalSubmitTask(
    __in        LPTASK_THREAD_ROUTINE   TaskRoutine,
    __in_opt    LPVOID                  Params,
    __in_opt    HANDLE                  CompletionEvent)
{
    TASK    NewTask = { TaskRoutine, Params, CompletionEvent };

    FTasks.push(NewTask);

    if (FNewTaskEvent != NULL)
    {
        SetEvent(FNewTaskEvent);
    }

    return TRUE;
};

void CTaskThread::ThreadRoutine()
{
    DWORD   WaitResult;
    BOOL    StopThread = FALSE;
    TASK    Task;
    HANDLE  WaitArray[] = 
    {
        InternalGetStopEvent(),
        FNewTaskEvent
    };

    RETURN_IF_FALSE(InternalInitialize());

    while (!StopThread)
    {
        WaitResult = WaitForMultipleObjects(2, WaitArray, FALSE, INFINITE);

        switch (WaitResult)
        {
        case WAIT_OBJECT_0:
            {
                StopThread = TRUE;
            }break;

        case WAIT_OBJECT_0 + 1:
            {
                if (InternalGetTask(&Task))
                {
                    InternalProcessTask(&Task);
                }
            }break;
        };
    };

    while (InternalGetTask(&Task))
    {
        InternalProcessTask(&Task, TRUE);
    }

    InternalFinalize();
};

BOOL CTaskThread::InternalInitialize()
{
    return TRUE;
};

void CTaskThread::InternalFinalize()
{
};

CTaskThread::CTaskThread(
    __in_opt    LPVOID  Owner):
    CCSObject(Owner),
    CThread(Owner, TRUE)
{
    FNewTaskEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    THROW_EXCEPTION_IF_FALSE(
        FNewTaskEvent != NULL,
        TASK_THREAD_EXCEPTION_FAILED_TO_CREATE_NEW_TASK_EVENT);
};

CTaskThread::~CTaskThread()
{
    Enter();
    Leave();
    Stop();
    if (FNewTaskEvent != NULL)
    {
        CloseHandle(FNewTaskEvent);
    }
};

BOOL CTaskThread::SubmitTask(
    __in        LPTASK_THREAD_ROUTINE   TaskRoutine,
    __in_opt    LPVOID                  Params,
    __in_opt    HANDLE                  CompletionEvent)
{
    BOOL    Result = FALSE;

    Enter();
    __try
    {
        Result = InternalSubmitTask(
            TaskRoutine,
            Params,
            CompletionEvent);
    }
    __finally
    {
        Leave();
    }

    return Result;
};
