//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2019 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include "KmMREWLock.h"
#include "..\shared\CommonDefs.h"

typedef struct _KM_MREW_LOCK
{
    //  Spin lock
    EX_SPIN_LOCK    SpinLock;

    //  Interrupt request level.
    //  This field is used to store the original IRQL the 
    //  SpinLock was acquired at.
    KIRQL           Irql;

    //  Boolean flag that indicates whether the spinlock
    //  was acquired at IRQL >= DISPATCH_LEVEL
    BOOLEAN         AcquiredAtDispatchOrHigher;

    //  Multi-read/exclusive-write lock object
    //  Used for synchronizing shared and exclusive access
    //  to other objects/resources.
} KM_MREW_LOCK, *PKM_MREW_LOCK;

NTSTATUS __stdcall Km_MREW_Lock_Initialize(
    __inout PKM_MREW_LOCK   Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER_1);

    RtlZeroMemory(Lock, sizeof(KM_MREW_LOCK));

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MREW_Lock_AcquireRead(
    __inout PKM_MREW_LOCK   Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    KIRQL       Irql;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER_1);

    Irql = KeGetCurrentIrql();

    if (Irql >= DISPATCH_LEVEL)
    {
        ExAcquireSpinLockSharedAtDpcLevel(&Lock->SpinLock);

        Lock->AcquiredAtDispatchOrHigher = TRUE;
    }
    else
    {
        Lock->Irql = ExAcquireSpinLockShared(&Lock->SpinLock);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MREW_Lock_AcquireWrite(
    __inout PKM_MREW_LOCK   Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    KIRQL       Irql;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER_1);

    Irql = KeGetCurrentIrql();

    if (Irql >= DISPATCH_LEVEL)
    {
        ExAcquireSpinLockExclusiveAtDpcLevel(&Lock->SpinLock);

        Lock->AcquiredAtDispatchOrHigher = TRUE;
    }
    else
    {
        Lock->Irql = ExAcquireSpinLockExclusive(&Lock->SpinLock);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MREW_Lock_ReleaseRead(
    __inout PKM_MREW_LOCK   Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER_1);

    if (Lock->AcquiredAtDispatchOrHigher)
    {
        Lock->AcquiredAtDispatchOrHigher = FALSE;

        ExReleaseSpinLockSharedFromDpcLevel(&Lock->SpinLock);
    }
    else
    {
        ExReleaseSpinLockShared(&Lock->SpinLock, Lock->Irql);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_MREW_Lock_ReleaseWrite(
    __inout PKM_MREW_LOCK   Lock)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Lock),
        STATUS_INVALID_PARAMETER_1);

    if (Lock->AcquiredAtDispatchOrHigher)
    {
        Lock->AcquiredAtDispatchOrHigher = FALSE;

        ExReleaseSpinLockExclusiveFromDpcLevel(&Lock->SpinLock);
    }
    else
    {
        ExReleaseSpinLockExclusive(&Lock->SpinLock, Lock->Irql);
    }

cleanup:
    return Status;
};