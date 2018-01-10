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

#define NdisMM_AllocMem(Manager, Size)                      Ndis_MM_AllocMem((Manager), (Size))
#define NdisMM_AllocMemTypedWithSize(Manager, Type, Size)   (Type *)NdisMM_AllocMem((Manager), (Size))
#define NdisMM_AllocMemTyped(Manager, Type)                 NdisMM_AllocMemTypedWithSize((Manager), Type, sizeof(Type))
#define NdisMM_FreeMem(Ptr)                                 Ndis_MM_FreeMem(Ptr)

#endif