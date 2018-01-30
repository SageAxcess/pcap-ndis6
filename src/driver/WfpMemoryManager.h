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

PVOID __stdcall Wfp_MM_AllocMem(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    SIZE_T              Size);

NTSTATUS __stdcall Wfp_MM_FreeMem(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PVOID               Ptr);

#endif
