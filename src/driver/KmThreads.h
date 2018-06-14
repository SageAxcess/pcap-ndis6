//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2017 ChangeDynamix, LLC
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef KM_THREADS_H
#define KM_THREADS_H

#include "KmMemoryManager.h"

#pragma pack(push, 1)

typedef struct _KM_THREAD
{
    PKM_MEMORY_MANAGER  MemoryManager;
    PETHREAD            ThreadObject;
    KEVENT              StopEvent;
    PVOID               Context;
} KM_THREAD, *PKM_THREAD;

typedef void __stdcall _KM_THREAD_FUNCTION(
    __in    PKM_THREAD  Thread);
typedef _KM_THREAD_FUNCTION KM_THREAD_FUNCTION, *PKM_THREAD_FUNCTION;

/*
    KmThreads_CreateThread routine.

    Purpose:
        Creates a system thread.

    Parameters:
        MemoryManager   - Memory manager
        Thread          - Pointer to the variable to receive the new thread object.
        ThreadFunction  - Pointer to KM_THREAD_FUNCTION callback.
        Context         - Client-specific context value.
*/
NTSTATUS __stdcall KmThreads_CreateThread(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out	PKM_THREAD          *Thread,
    __in    PKM_THREAD_FUNCTION ThreadFunction,
    __in	PVOID			    Context);

/*
    KmThreads_DestroyThread routine.

    Purpose:
        Destroys the thread object.

    Parameters:
        Thread - Pointer to KM_THREAD structure.

    Return values:
        Returns STATUS_SUCCESS upon success or
        other NTSTATUS values upon failure.
*/
NTSTATUS __stdcall KmThreads_DestroyThread(
    __in    PKM_THREAD  Thread);

/*
    KmThreads_StopThread routine.

    Purpose:
        Initiates kernel thread stop and waits
        for it to stop a specified time amount.

    Params:
        Thread      - pointer to KM_THREAD structure.
        WaitTimeout - amount of time to wait for the thread stop in miliseconds.

    Return values:
        STATUS_WAIT_TIMEOUT        - wait timed-out.
        STATUS_WAIT_0              - wait succeeded.
        Other status codes         - An error occured.
*/
NTSTATUS __stdcall KmThreads_StopThread(
    __in    PKM_THREAD  Thread,
    __in    ULONG       WaitTimeout);

#define KmThreads_WaitForThread(Thread) \
    KeWaitForSingleObject((Thread)->ThreadObject, Executive, KernelMode, FALSE, NULL)

NTSTATUS __stdcall KmThreads_RunThreaded(
    __in        PKM_MEMORY_MANAGER  MemoryManager,
    __in        PKM_THREAD_FUNCTION ThreadRoutine,
    __in        PKM_THREAD_FUNCTION ThreadCompletionRoutine,
    __in_opt    PVOID               Context);

#pragma pack(pop)

#endif