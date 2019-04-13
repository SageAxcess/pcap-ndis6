//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include "KmTimer.h"
#include "..\shared\CommonDefs.h"

NTSTATUS __stdcall KmTimer_Allocate(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PKM_TIMER           *Timer)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PKM_TIMER   NewTimer = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Timer),
        STATUS_INVALID_PARAMETER_2);

    NewTimer = Km_MM_AllocMemTypedWithTag(
        MemoryManager,
        KM_TIMER,
        KM_TIMER_OBJECT_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewTimer),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        RtlZeroMemory(NewTimer, sizeof(KM_TIMER));

        NewTimer->MemoryManager = MemoryManager;

        KeInitializeTimer(&NewTimer->Timer);
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            Km_MM_FreeMem(MemoryManager, NewTimer);
        }
    }

    *Timer = NewTimer;

cleanup:
    return  Status;
};

NTSTATUS __stdcall KmTimer_Destroy(
    __in    PKM_TIMER   Timer)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_MEMORY_MANAGER  MemoryManager = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Timer),
        STATUS_INVALID_PARAMETER_1);
    MemoryManager =
        (PKM_MEMORY_MANAGER)InterlockedExchangePointer(
            (PVOID *)&Timer->MemoryManager,
            NULL);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);

    Status = KmTimer_Cancel(Timer);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Km_MM_FreeMem(MemoryManager, Timer);

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTimer_Cancel(
    __in    PKM_TIMER   Timer)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Timer),
        STATUS_INVALID_PARAMETER_1);

    KeCancelTimer(&Timer->Timer);

cleanup:
    return Status;
};


NTSTATUS __stdcall KmTimer_SetExpiration(
    __in    PKM_TIMER   Timer,
    __in    ULONG       Value,
    __in    BOOLEAN     Recurring)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    LARGE_INTEGER   DueTime = { 0 };

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Timer),
        STATUS_INVALID_PARAMETER_1);

    DueTime.QuadPart -= MilisecondsTo100Nanoseconds(Value);

    KeSetTimerEx(
        &Timer->Timer,
        DueTime,
        Recurring ? (LONG)Value : 0,
        NULL);

cleanup:
    return Status;
};