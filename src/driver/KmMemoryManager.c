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

#include "KmMemoryManagery.h"

NTSTATUS __stdcall Km_MM_Initialize(
    __in    PKM_MEMORY_MANAGER          Manager,
    __in    PKM_MM_ALLOC_MEM_ROUTINE    AllocMemRoutine,
    __in    PKM_MM_FREE_MEM_ROUTINE     FreeMemRoutine,
    __in    PKM_MM_INIT_ROUTINE         InitRoutine,
    __in    PKM_MM_CLEANUP_ROUTINE      CleanupRoutine,
    __in    ULONG                       MemoryTag,
    __in    PVOID                       InitParams,
    __in    PVOID                       Context)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(AllocMemRoutine),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(FreeMemRoutine),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InitRoutine),
        STATUS_INVALID_PARAMETER_4);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CleanupRoutine),
        STATUS_INVALID_PARAMETER_5);

    Status = InitRoutine(Manager, InitParams);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Manager->AllocMemRoutine = AllocMemRoutine;
    Manager->FreeMemRoutine = FreeMemRoutine;
    Manager->CleanupRoutine = CleanupRoutine;
    Manager->Context = Context;
    Manager->MemoryTag = MemoryTag;

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MM_Finalize(
    __in    PKM_MEMORY_MANAGER  Manager)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Manager->CleanupRoutine),
        STATUS_INVALID_PARAMETER_1);

    Status = Manager->CleanupRoutine(Manager);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    RtlZeroMemory(
        Manager,
        sizeof(KM_MEMORY_MANAGER));

cleanup:
    return Status;
};