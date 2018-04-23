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

#include "..\shared\CommonDefs.h"

typedef struct _KM_MEMORY_MANAGER KM_MEMORY_MANAGER;
typedef KM_MEMORY_MANAGER *PKM_MEMORY_MANAGER;

typedef PVOID(__stdcall _KM_MM_ALLOC_MEM_ROUTINE)(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    SIZE_T              Size);
typedef _KM_MM_ALLOC_MEM_ROUTINE KM_MM_ALLOC_MEM_ROUTINE, *PKM_MM_ALLOC_MEM_ROUTINE;

typedef NTSTATUS(__stdcall _KM_MM_FREE_MEM_ROUTINE)(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               Ptr);
typedef _KM_MM_FREE_MEM_ROUTINE KM_MM_FREE_MEM_ROUTINE, *PKM_MM_FREE_MEM_ROUTINE;

typedef NTSTATUS(__stdcall _KM_MM_INIT_ROUTINE)(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               InitParams);
typedef _KM_MM_INIT_ROUTINE KM_MM_INIT_ROUTINE, *PKM_MM_INIT_ROUTINE;

typedef NTSTATUS(__stdcall _KM_MM_CLEANUP_ROUTINE)(
    __in    PKM_MEMORY_MANAGER  Manager);
typedef _KM_MM_CLEANUP_ROUTINE  KM_MM_CLEANUP_ROUTINE, *PKM_MM_CLEANUP_ROUTINE;

typedef struct _KM_MEMORY_MANAGER
{
    ULONG                       MemoryTag;

    PKM_MM_ALLOC_MEM_ROUTINE    AllocMemRoutine;

    PKM_MM_FREE_MEM_ROUTINE     FreeMemRoutine;

    PKM_MM_CLEANUP_ROUTINE      CleanupRoutine;

    PVOID                       Context;

} KM_MEMORY_MANAGER;

typedef KM_MEMORY_MANAGER *PKM_MEMORY_MANAGER;

NTSTATUS __stdcall Km_MM_Initialize(
    __in    PKM_MEMORY_MANAGER          Manager,
    __in    PKM_MM_ALLOC_MEM_ROUTINE    AllocMemRoutine,
    __in    PKM_MM_FREE_MEM_ROUTINE     FreeMemRoutine,
    __in    PKM_MM_INIT_ROUTINE         InitRoutine,
    __in    PKM_MM_CLEANUP_ROUTINE      CleanupRoutine,
    __in    ULONG                       MemoryTag,
    __in    PVOID                       InitParams,
    __in    PVOID                       Context);

NTSTATUS __stdcall Km_MM_Finalize(
    __in    PKM_MEMORY_MANAGER  Manager);

#define Km_MM_AllocMem(Manager, Size)                       (Assigned((Manager)->AllocMemRoutine) ? (Manager)->AllocMemRoutine((Manager), (Size)) : NULL)
#define Km_MM_AllocMemTypedWithSize(Manager, Type, Size)    (Type *)Km_MM_AllocMem((Manager), (Size))
#define Km_MM_AllocMemTyped(Manager, Type)                  Km_MM_AllocMemTypedWithSize((Manager), Type, sizeof(Type))
#define Km_MM_AllocArray(Manager, ItemType, ItemCount)      Km_MM_AllocMemTypedWithSize((Manager), ItemType, sizeof(ItemType) * (ItemCount))

#define Km_MM_FreeMem(Manager, Ptr)                         (Assigned((Manager)->FreeMemRoutine) ? (Manager)->FreeMemRoutine((Manager), (Ptr)) : STATUS_UNSUCCESSFUL)