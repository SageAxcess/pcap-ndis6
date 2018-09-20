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

#include "WfpMemoryManager.h"
#include "KmLock.h"

typedef struct _WFP_MM
{
    //  Lock object
    KM_LOCK             Lock;

    struct
    {
        KM_MM_ALLOCATION_STATS  Stats;

        //  List containing allocated memory blocks
        LIST_ENTRY  AllocatedBlocks;

    } Allocations;

    //  Priority for allocations
    EX_POOL_PRIORITY    PoolPriority;

    //  Pool type
    POOL_TYPE           PoolType;

} WFP_MM, *PWFP_MM;

typedef struct _WFP_MM_MEM_BLOCK_HEADER
{
    LIST_ENTRY          Link;

    PKM_MEMORY_MANAGER  MemoryManager;

    SIZE_T              Size;

    SIZE_T              MaxSize;

    ULONG               Tag;

} WFP_MM_MEM_BLOCK_HEADER, *PWFP_MM_MEM_BLOCK_HEADER;


NTSTATUS Wfp_MM_Init(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               InitParams)
{
    UNREFERENCED_PARAMETER(Manager);
    UNREFERENCED_PARAMETER(InitParams);

    return STATUS_SUCCESS;
};

NTSTATUS __stdcall Wfp_MM_Initialize(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    EX_POOL_PRIORITY    PoolPriority,
    __in    POOL_TYPE           PoolType,
    __in    ULONG               MemoryTag)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PWFP_MM     WfpMM = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER_1);

    WfpMM = ExAllocatePoolWithTagPriority(
        PoolType,
        sizeof(WFP_MM),
        MemoryTag,
        PoolPriority);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(WfpMM),
        STATUS_INSUFFICIENT_RESOURCES);

    Status = Km_Lock_Initialize(&WfpMM->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    InitializeListHead(&WfpMM->Allocations.AllocatedBlocks);

    WfpMM->PoolPriority = PoolPriority;
    WfpMM->PoolType = PoolType;

    Status = Km_MM_Initialize(
        Manager,
        Wfp_MM_AllocMem,
        Wfp_MM_FreeMem,
        Wfp_MM_Init,
        Wfp_MM_Cleanup,
        Wfp_MM_QueryStats,
        MemoryTag,
        NULL,
        (PVOID)WfpMM);

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(WfpMM))
        {
            ExFreePoolWithTag(
                WfpMM,
                MemoryTag);
        }
    }

    return Status;
};

NTSTATUS __stdcall Wfp_MM_Cleanup(
    __in    PKM_MEMORY_MANAGER  Manager)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PWFP_MM     WfpMM = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager->Context),
        STATUS_INVALID_PARAMETER_1);

    WfpMM = (PWFP_MM)Manager->Context;

    Status = Km_Lock_Acquire(&WfpMM->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        if (!IsListEmpty(&WfpMM->Allocations.AllocatedBlocks))
        {
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    __finally
    {
        Km_Lock_Release(&WfpMM->Lock);
    }

    if (NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(
            WfpMM,
            Manager->MemoryTag);
    }

cleanup:
    return Status;
};

PVOID __stdcall Wfp_MM_AllocMem(
    __in        PKM_MEMORY_MANAGER  Manager,
    __in        SIZE_T              Size,
    __in_opt    ULONG               Tag)
{
    PVOID       Result = NULL;
    PWFP_MM     WfpMM = NULL;
    SIZE_T      SizeRequired = 0;
    ULONG       MemTag;

    RETURN_VALUE_IF_FALSE(
        (Assigned(Manager)) &&
        (Size > 0),
        NULL);
    RETURN_VALUE_IF_FALSE(
        Assigned(Manager->Context),
        NULL);

    WfpMM = (PWFP_MM)Manager->Context;

    SizeRequired = sizeof(WFP_MM_MEM_BLOCK_HEADER) + Size;

    RETURN_VALUE_IF_FALSE(
        NT_SUCCESS(Km_Lock_Acquire(&WfpMM->Lock)),
        NULL);
    __try
    {
        PVOID   NewBlock;
        
        MemTag = Tag == 0 ? Manager->MemoryTag : Tag;

        NewBlock = ExAllocatePoolWithTagPriority(
            WfpMM->PoolType,
            SizeRequired,
            MemTag,
            WfpMM->PoolPriority);

        if (Assigned(NewBlock))
        {
            PWFP_MM_MEM_BLOCK_HEADER Header = (PWFP_MM_MEM_BLOCK_HEADER)NewBlock;

            Header->Size = Header->MaxSize = Size;
            Header->MemoryManager = Manager;
            Header->Tag = MemTag;

            InsertHeadList(
                &WfpMM->Allocations.AllocatedBlocks,
                &Header->Link);

            WfpMM->Allocations.Stats.NumberOfAllocations++;
            WfpMM->Allocations.Stats.TotalBytesAllocated += SizeRequired;
            WfpMM->Allocations.Stats.UserBytesAllocated += Size;

            Result = (PVOID)((PUCHAR)NewBlock + sizeof(WFP_MM_MEM_BLOCK_HEADER));
        }
    }
    __finally
    {
        Km_Lock_Release(&WfpMM->Lock);
    }

    return Result;
};

NTSTATUS __stdcall Wfp_MM_FreeMem(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               Ptr)
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    PWFP_MM_MEM_BLOCK_HEADER    Header;
    PWFP_MM                     WfpMM;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Ptr),
        STATUS_INVALID_PARAMETER_2);

    Header = (PWFP_MM_MEM_BLOCK_HEADER)((PUCHAR)Ptr - sizeof(WFP_MM_MEM_BLOCK_HEADER));
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Header->MemoryManager),
        STATUS_INVALID_PARAMETER);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Header->MemoryManager == Manager,
        STATUS_UNSUCCESSFUL);

    WfpMM = (PWFP_MM)Header->MemoryManager->Context;

    Status = Km_Lock_Acquire(&WfpMM->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        RemoveEntryList(&Header->Link);

        ExFreePoolWithTag(
            Header,
            Header->Tag);
    }
    __finally
    {
        Km_Lock_Release(&WfpMM->Lock);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Wfp_MM_QueryStats(
    __in    PKM_MEMORY_MANAGER  Manager,
    __out   PKM_MM_STATS        Stats)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PWFP_MM     WfpMM = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager->Context),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Stats),
        STATUS_INVALID_PARAMETER_2);

    WfpMM = (PWFP_MM)Manager->Context;

    Status = Km_Lock_Acquire(&WfpMM->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        RtlCopyMemory(
            &Stats->CurrentAllocations,
            &WfpMM->Allocations.Stats,
            sizeof(KM_MM_ALLOCATION_STATS));
    }
    __finally
    {
        Km_Lock_Release(&WfpMM->Lock);
    }

    Stats->Flags = KM_MM_STATS_FLAG_CURRENT_ALLOCATION_STATS_PRESENT;

cleanup:
    return Status;
};