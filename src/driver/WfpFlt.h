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

#include <ntddk.h>

#include "KmTypes.h"

#include "KmMemoryManager.h"

typedef enum _WFP_NETWORK_EVENT_TYPE
{
    wnetNewFlow,
    wnetFlowRemove
} WFP_NETWORK_EVENT_TYPE;

typedef void(__stdcall _WFP_NETWORK_EVENT_CALLBACK)(
    __in    WFP_NETWORK_EVENT_TYPE  EventType,
    __in    PNET_EVENT_INFO         Info,
    __in    PVOID                   Context);
typedef _WFP_NETWORK_EVENT_CALLBACK WFP_NETWORK_EVENT_CALLBACK, *PWFP_NETWORK_EVENT_CALLBACK;

NTSTATUS __stdcall Wfp_Initialize(
    __in    PDRIVER_OBJECT              DriverObject,
    __in    PKM_MEMORY_MANAGER          MemoryManager,
    __in    PWFP_NETWORK_EVENT_CALLBACK EventCallback,
    __in    PVOID                       EventCallbackContext,
    __out   PHANDLE                     Instance);

NTSTATUS __stdcall Wfp_Finalize(
    __in    HANDLE  Instance);