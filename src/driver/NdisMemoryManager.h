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

#ifndef NDIS_MEMORY_MANAGER_H
#define NDIS_MEMORY_MANAGER_H

#include <ndis.h>
#include "KmLock.h"

typedef struct _NDIS_MM
{
    //  A handle received from one of the following NDIS routines:
    //      * NdisMRegisterMiniportDriver
    //      * MiniportInitializeEx
    //      * NdisRegisterProtocolDriver
    //      * NdisOpenAdapterEx,
    //      * NdisFRegisterFilterDriver
    //      * FilterAttach
    NDIS_HANDLE         NdisObjectHandle;

    //  Lock object
    KM_LOCK             Lock;

    //  List containing allocated memory blocks
    LIST_ENTRY          AllocatedBlocks;

    //  Priority for allocations
    EX_POOL_PRIORITY    PoolPriority;

    //  Pool tag for allocations
    ULONG               Tag;
} NDIS_MM, *PNDIS_MM;

NTSTATUS __stdcall Ndis_MM_Initialize(
    __in    PNDIS_MM            MemoryManager,
    __in    NDIS_HANDLE         NdisHandle,
    __in    EX_POOL_PRIORITY    PoolPriority,
    __in    ULONG               Tag);

NTSTATUS __stdcall Ndis_MM_Finalize(
    __in    PNDIS_MM    MemoryManager);

PVOID __stdcall Ndis_MM_AllocMem(
    __in    PNDIS_MM    MemoryManager,
    __in    UINT        Size);

NTSTATUS __stdcall Ndis_MM_FreeMem(
    __in    PVOID   MemoryBlock);

PVOID __stdcall Ndis_MM_ReAllocMem(
    __in    PVOID   MemoryBlock,
    __in    SIZE_T  NewSize);

#endif