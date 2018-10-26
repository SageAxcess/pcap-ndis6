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

typedef struct _KM_MM_ALLOCATION_STATS
{
    unsigned long long  UserBytesAllocated;

    unsigned long long  TotalBytesAllocated;

    unsigned long long  NumberOfAllocations;

} KM_MM_ALLOCATION_STATS, *PKM_MM_ALLOCATION_STATS;

#define KM_MM_STATS_FLAG_NONE                               0x0
#define KM_MM_STATS_FLAG_CURRENT_ALLOCATION_STATS_PRESENT   0x1

typedef struct _KM_MM_STATS
{
    unsigned long   Flags;

    KM_MM_ALLOCATION_STATS  CurrentAllocations;

} KM_MM_STATS, *PKM_MM_STATS;

typedef struct _KM_MEMORY_MANAGER KM_MEMORY_MANAGER;
typedef KM_MEMORY_MANAGER *PKM_MEMORY_MANAGER;

typedef PVOID(__stdcall _KM_MM_ALLOC_MEM_ROUTINE)(
    __in        PKM_MEMORY_MANAGER  Manager,
    __in        SIZE_T              Size,
    __in_opt    ULONG               Tag);
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

typedef NTSTATUS(__stdcall _KM_MM_QUERY_STATS_ROUTINE)(
    __in    PKM_MEMORY_MANAGER  Manager,
    __out   PKM_MM_STATS        Stats);
typedef _KM_MM_QUERY_STATS_ROUTINE  *PKM_MM_QUERY_STATS_ROUTINE;

typedef struct _KM_MEMORY_MANAGER
{
    ULONG                       MemoryTag;

    PKM_MM_ALLOC_MEM_ROUTINE    AllocMemRoutine;

    PKM_MM_FREE_MEM_ROUTINE     FreeMemRoutine;

    PKM_MM_CLEANUP_ROUTINE      CleanupRoutine;

    PKM_MM_QUERY_STATS_ROUTINE  QueryStatsRoutine;

    PVOID                       Context;

} KM_MEMORY_MANAGER;

typedef KM_MEMORY_MANAGER *PKM_MEMORY_MANAGER;

NTSTATUS __stdcall Km_MM_Initialize(
    __in    PKM_MEMORY_MANAGER          Manager,
    __in    PKM_MM_ALLOC_MEM_ROUTINE    AllocMemRoutine,
    __in    PKM_MM_FREE_MEM_ROUTINE     FreeMemRoutine,
    __in    PKM_MM_INIT_ROUTINE         InitRoutine,
    __in    PKM_MM_CLEANUP_ROUTINE      CleanupRoutine,
    __in    PKM_MM_QUERY_STATS_ROUTINE  QueryStatsRoutine,
    __in    ULONG                       MemoryTag,
    __in    PVOID                       InitParams,
    __in    PVOID                       Context);

NTSTATUS __stdcall Km_MM_Finalize(
    __in    PKM_MEMORY_MANAGER  Manager);

#define Km_MM_AllocMemWithTag(Manager, Size, Tag)                   (Assigned((Manager)->AllocMemRoutine) ? (Manager)->AllocMemRoutine((Manager), (Size), (Tag)) : NULL)
#define Km_MM_AllocMem(Manager, Size)                               Km_MM_AllocMemWithTag((Manager), (Size), 0)
#define Km_MM_AllocMemTypedWithSizeAndTag(Manager, Type, Size, Tag) (Type *)Km_MM_AllocMemWithTag((Manager), (Size), (Tag))
#define Km_MM_AllocMemTypedWithSize(Manager, Type, Size)            Km_MM_AllocMemTypedWithSizeAndTag((Manager), Type, (Size), 0)
#define Km_MM_AllocMemTypedWithTag(Manager, Type, Tag)              Km_MM_AllocMemTypedWithSizeAndTag((Manager), Type, sizeof(Type), (Tag))
#define Km_MM_AllocMemTyped(Manager, Type)                          Km_MM_AllocMemTypedWithSize((Manager), Type, sizeof(Type))
#define Km_MM_AllocArrayWithTag(Manager, ItemType, ItemCount, Tag)  Km_MM_AllocMemTypedWithSizeAndTag((Manager), ItemType, sizeof(ItemType) * (ItemCount), (Tag))
#define Km_MM_AllocArray(Manager, ItemType, ItemCount)              Km_MM_AllocArrayWithTag((Manager), ItemType, ItemCount, 0)


#define Km_MM_FreeMem(Manager, Ptr)                                 (Assigned((Manager)->FreeMemRoutine) ? (Manager)->FreeMemRoutine((Manager), (Ptr)) : STATUS_UNSUCCESSFUL)

#define Km_MM_QueryStats(Manager, Stats)                            (Assigned((Manager)->QueryStatsRoutine) ? (Manager)->QueryStatsRoutine((Manager), (Stats)) : STATUS_NOT_IMPLEMENTED)