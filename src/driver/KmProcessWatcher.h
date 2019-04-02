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

#include <ntddk.h>
#include "KmMemoryManager.h"

/*
    Process creation/deletion callback

    Parameters:
        ParentProcessId - ID of the parent process.
                          This parameter is only valid if the
                          NewProcess parameter is TRUE.
        ProcessId       - ID of the new process being created.
        NewProcess      - Boolean value representing whether
                          the process is being created or terminated.

    Return value:
        none.
*/
typedef void(__stdcall _KM_PROCESS_WATCHER_CALLBACK)(
    __in_opt    HANDLE  ParentProcessId,
    __in        HANDLE  ProcessId,
    __in        BOOLEAN NewProcess,
    __in        PVOID   Context);
typedef _KM_PROCESS_WATCHER_CALLBACK    KM_PROCESS_WATCHER_CALLBACK, *PKM_PROCESS_WATCHER_CALLBACK;

NTSTATUS __stdcall Km_ProcessWatcher_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager);

NTSTATUS __stdcall Km_ProcessWatcher_Finalize();

NTSTATUS __stdcall Km_ProcessWatcher_RegisterCallback(
    __in    PKM_PROCESS_WATCHER_CALLBACK    Callback,
    __in    PVOID                           Context,
    __out   PHANDLE                         CallbackHandle);

NTSTATUS __stdcall Km_ProcessWatcher_UnregisterCallback(
    __in    HANDLE  CallbackHandle);