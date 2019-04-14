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

#ifndef WFP_MEMORY_MANAGER_H
#define WFP_MEMORY_MANAGER_H

#include <ntddk.h>
#include "..\shared\CommonDefs.h"
#include "KmMemoryManager.h"

NTSTATUS __stdcall Wfp_MM_Initialize(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    EX_POOL_PRIORITY    PoolPriority,
    __in    POOL_TYPE           PoolType,
    __in    ULONG               MemoryTag);

NTSTATUS __stdcall Wfp_MM_Cleanup(
    __in    PKM_MEMORY_MANAGER  Manager);

#ifdef KM_MEMORY_MANAGER_EXTENDED_DEBUG_INFO
PVOID __stdcall Wfp_MM_AllocMem(
    __in        PKM_MEMORY_MANAGER  Manager,
    __in        SIZE_T              Size,
    __in_opt    ULONG               Tag,
    __in_opt    char                *FileName,
    __in_opt    SIZE_T              FileNameLength,
    __in_opt    int                 LineNumber,
    __in_opt    char                *FunctionName,
    __in_opt    SIZE_T              FunctionNameLength);
#else
PVOID __stdcall Wfp_MM_AllocMem(
    __in        PKM_MEMORY_MANAGER  Manager,
    __in        SIZE_T              Size,
    __in_opt    ULONG               Tag);
#endif

NTSTATUS __stdcall Wfp_MM_FreeMem(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               Ptr);

NTSTATUS __stdcall Wfp_MM_QueryStats(
    __in    PKM_MEMORY_MANAGER  Manager,
    __out   PKM_MM_STATS        Stats);

#endif
