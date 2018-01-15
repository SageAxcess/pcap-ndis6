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

#ifndef BFE_STATE_WATCHER_H
#define BFE_STATE_WATCHER_H

#include "KmMemoryManager.h"

#include <fwpmk.h>


NTSTATUS __stdcall BfeStateWatcher_Initialize(
    __in    PDRIVER_OBJECT                      DriverObject,
    __in    PKM_MEMORY_MANAGER                  MemoryManager,
    __in    FWPM_SERVICE_STATE_CHANGE_CALLBACK  Callback,
    __in    PVOID                               Context,
    __out   PHANDLE                             Instance);

NTSTATUS __stdcall BfeStateWatcher_Finalize(
    __in    HANDLE  Instance);

#endif