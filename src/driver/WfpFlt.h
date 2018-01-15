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

#pragma once

#include <fwpsk.h>
#include <fwpmk.h>

#include "KmTypes.h"

#include "KmMemoryManager.h"

typedef void(__stdcall _WFP_NETWORK_EVENT_CALLBACK)(
    __in    PNETWORK_EVENT_INFO Info);
typedef _WFP_NETWORK_EVENT_CALLBACK WFP_NETWORK_EVENT_CALLBACK, *PWFP_NETWORK_EVENT_CALLBACK;

NTSTATUS __stdcall Wfp_Initialize(
    __in    PDRIVER_OBJECT              DriverObject,
    __in    PKM_MEMORY_MANAGER          MemoryManager,
    __in    PWFP_NETWORK_EVENT_CALLBACK EventCallback,
    __out   PHANDLE                     Instance);

NTSTATUS __stdcall Wfp_Finalize(
    __in    HANDLE  Instance);