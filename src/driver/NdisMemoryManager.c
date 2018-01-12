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

#include "..\shared\CommonDefs.h"
#include "NdisMemoryManager.h"
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

} NDIS_MM, *PNDIS_MM;

typedef struct _NDIS_MM_MEM_BLOCK_HEADER
{
    LIST_ENTRY  Link;

    PNDIS_MM    MemoryManager;

    SIZE_T      Size;

    SIZE_T      MaxSize;

} NDIS_MM_MEM_BLOCK_HEADER, *PNDIS_MM_MEM_BLOCK_HEADER;

NTSTATUS __stdcall Ndis_MM_Init(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               InitParams)
{
    UNREFERENCED_PARAMETER(Manager);
    UNREFERENCED_PARAMETER(InitParams);

    return STATUS_SUCCESS;
};

NTSTATUS __stdcall Ndis_MM_Initialize(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    NDIS_HANDLE         NdisHandle,
    __in    EX_POOL_PRIORITY    PoolPriority,
    __in    ULONG               MemoryTag)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PNDIS_MM    NdisMM = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NdisHandle != NULL,
        STATUS_INVALID_PARAMETER_2);

    NdisMM = (PNDIS_MM)NdisAllocateMemoryWithTagPriority(
        NdisHandle,
        (UINT)sizeof(NDIS_MM),
        MemoryTag,
        PoolPriority);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NdisMM),
        STATUS_INSUFFICIENT_RESOURCES);

    Status = Km_Lock_Initialize(&NdisMM->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    InitializeListHead(&NdisMM->AllocatedBlocks);

    NdisMM->NdisObjectHandle = NdisHandle;
    NdisMM->PoolPriority = PoolPriority;

    Status = Km_MM_Initialize(
        Manager,
        Ndis_MM_AllocMem,
        Ndis_MM_FreeMem,
        Ndis_MM_Init,
        Ndis_MM_Cleanup,
        MemoryTag,
        NULL,
        (PVOID)NdisMM);

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NdisMM))
        {
            NdisFreeMemoryWithTagPriority(
                NdisHandle,
                NdisMM,
                MemoryTag);
        }
    }

    return Status;
};

NTSTATUS __stdcall Ndis_MM_Cleanup(
    __in    PKM_MEMORY_MANAGER  Manager)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PNDIS_MM    NdisMM = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager->Context),
        STATUS_INVALID_PARAMETER_1);

    NdisMM = (PNDIS_MM)Manager->Context;

    Status = Km_Lock_Acquire(&NdisMM->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        if (!IsListEmpty(&NdisMM->AllocatedBlocks))
        {
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    __finally
    {
        Km_Lock_Release(&NdisMM->Lock);
    }

    if (NT_SUCCESS(Status))
    {
        NdisFreeMemoryWithTagPriority(
            NdisMM->NdisObjectHandle,
            NdisMM,
            Manager->MemoryTag);
    }

cleanup:
    return Status;
};

PVOID __stdcall Ndis_MM_AllocMem(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    SIZE_T              Size)
{
    PVOID       Result = NULL;
    PNDIS_MM    NdisMM = NULL;
    UINT        SizeRequired;

    RETURN_VALUE_IF_FALSE(
        (Assigned(Manager)) &&
        (Size > 0),
        NULL);
    RETURN_VALUE_IF_FALSE(
        Assigned(Manager->Context),
        NULL);

    NdisMM = (PNDIS_MM)Manager->Context;

    SizeRequired = (UINT)(sizeof(NDIS_MM_MEM_BLOCK_HEADER) + Size);

    RETURN_VALUE_IF_FALSE(
        NT_SUCCESS(Km_Lock_Acquire(&NdisMM->Lock)),
        NULL);
    __try
    {
        PVOID   NewBlock = NdisAllocateMemoryWithTagPriority(
            NdisMM->NdisObjectHandle,
            SizeRequired,
            Manager->MemoryTag,
            NdisMM->PoolPriority);

        if (Assigned(NewBlock))
        {
            PNDIS_MM_MEM_BLOCK_HEADER Header = (PNDIS_MM_MEM_BLOCK_HEADER)NewBlock;

            Header->Size = Header->MaxSize = Size;
            Header->MemoryManager = NdisMM;

            InsertHeadList(
                &NdisMM->AllocatedBlocks,
                &Header->Link);

            Result = (PVOID)((PUCHAR)NewBlock + sizeof(NDIS_MM_MEM_BLOCK_HEADER));
        }
    }
    __finally
    {
        Km_Lock_Release(&NdisMM->Lock);
    }

    return Result;
};

NTSTATUS __stdcall Ndis_MM_FreeMem(
    __in    PKM_MEMORY_MANAGER  Manager,
    __in    PVOID               Ptr)
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    PNDIS_MM_MEM_BLOCK_HEADER   Header;
    PNDIS_MM                    NdisMM;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Ptr),
        STATUS_INVALID_PARAMETER_2);

    Header = (PNDIS_MM_MEM_BLOCK_HEADER)((PUCHAR)Ptr - sizeof(NDIS_MM_MEM_BLOCK_HEADER));
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Header->MemoryManager),
        STATUS_INVALID_PARAMETER);

    NdisMM = Header->MemoryManager;

    Status = Km_Lock_Acquire(&NdisMM->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        RemoveEntryList(&Header->Link);
        NdisFreeMemoryWithTagPriority(
            NdisMM->NdisObjectHandle,
            Header,
            Manager->MemoryTag);
    }
    __finally
    {
        Km_Lock_Release(&NdisMM->Lock);
    }

cleanup:
    return Status;
};