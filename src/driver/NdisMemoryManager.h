//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2017 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef NDIS_MEMORY_MANAGER_H
#define NDIS_MEMORY_MANAGER_H

#include <ndis.h>
#include "KmMemoryManager.h"

NTSTATUS __stdcall Ndis_MM_Initialize(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    NDIS_HANDLE         NdisHandle,
    __in    EX_POOL_PRIORITY    PoolPriority,
    __in    ULONG               MemoryTag);

NTSTATUS __stdcall Ndis_MM_Cleanup(
    __in    PKM_MEMORY_MANAGER  Manager);

PVOID __stdcall Ndis_MM_AllocMem(
    __in        PKM_MEMORY_MANAGER  Manager,
    __in        SIZE_T              Size,
    __in_opt    ULONG               Tag);

NTSTATUS __stdcall Ndis_MM_FreeMem(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               Ptr);

NTSTATUS __stdcall Ndis_MM_QueryStats(
    __in    PKM_MEMORY_MANAGER  Manager,
    __out   PKM_MM_STATS        Stats);

#endif