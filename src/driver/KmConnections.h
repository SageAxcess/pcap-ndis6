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
#ifndef KM_CONNECTIONS_H
#define KM_CONNECTIONS_H

#include "KmList.h"
#include "KmMemoryManager.h"
#include "KmTypes.h"

#define KM_CONNECTIONS_INITIAL_POOL_SIZE    0x200

NTSTATUS __stdcall Km_Connections_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PHANDLE             Instance);

NTSTATUS __stdcall Km_Connections_Finalize(
    __in    HANDLE  Instance);

NTSTATUS __stdcall Km_Connections_Add(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info);

NTSTATUS __stdcall Km_Connections_Remove(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info);

NTSTATUS __stdcall Km_Connections_GetPIDForPacket(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info,
    __out   PULONGLONG      ProcessId);

#endif