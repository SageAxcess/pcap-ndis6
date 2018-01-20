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
#ifndef KM_FLOWS_LIST_H
#define KM_FLOWS_LIST_H

#include "KmList.h"
#include "KmMemoryManager.h"
#include "KmTypes.h"

NTSTATUS __stdcall Km_Connections_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PHANDLE             Instance);

NTSTATUS __stdcall Km_Connections_Finalize(
    __in    HANDLE  Instance);

NTSTATUS __stdcall Km_Connections_Add(
    __in    HANDLE              Instance,
    __in    PNETWORK_EVENT_INFO Info);

NTSTATUS __stdcall Km_Connections_Remove(
    __in    HANDLE              Instance,
    __in    PNETWORK_EVENT_INFO Info);

NTSTATUS __stdcall Km_Connections_GetPIDForPacket(
    __in    HANDLE              Instance,
    __in    PNETWORK_EVENT_INFO Info,
    __out   PHANDLE             ProcessId);

#endif
