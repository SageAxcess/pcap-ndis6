//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#pragma once

#include "KmMemoryManager.h"
#include "KmThreads.h"

typedef struct _KM_TIMER_THREAD KM_TIMER_THREAD, *PKM_TIMER_THREAD;

typedef void(__stdcall _KM_TIMER_THREAD_ROUTINE)(
    __in    PKM_TIMER_THREAD    Thread,
    __in    PVOID               Context);
typedef _KM_TIMER_THREAD_ROUTINE    *PKM_TIMER_THREAD_ROUTINE;

NTSTATUS __stdcall KmTimerThread_Allocate(
    __in        PKM_MEMORY_MANAGER          MemoryManager,
    __in        PKM_TIMER_THREAD_ROUTINE    ThreadRoutine,
    __in_opt    PVOID                       ThreadContext,
    __out       PKM_TIMER_THREAD            *Thread);

NTSTATUS __stdcall KmTimerThread_SetInterval(
    __in    PKM_TIMER_THREAD    Thread,
    __in    ULONG               Interval);

NTSTATUS __stdcall KmTimerThread_Stop(
    __in        PKM_TIMER_THREAD    Thread,
    __in_opt    ULONG               Timeout);

NTSTATUS __stdcall KmTimerThread_Destroy(
    __in    PKM_TIMER_THREAD    Thread);