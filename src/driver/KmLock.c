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

#include "KmLock.h"

NTSTATUS __stdcall Km_Lock_Initialize(
    __in    PKM_LOCK    Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER);

    RtlZeroMemory(Lock, sizeof(KM_LOCK));

    KeInitializeSpinLock(&Lock->SpinLock);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Lock_Acquire(
    __in    PKM_LOCK    Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER);

    KeAcquireSpinLock(
        &Lock->SpinLock,
        &Lock->Irql);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Lock_Release(
    __in    PKM_LOCK    Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER);

    KeReleaseSpinLock(&Lock->SpinLock, Lock->Irql);

cleanup:
    return Status;
};
