//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2017 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef KM_LOCK_H
#define KM_LOCK_H

#include <ntddk.h>

typedef struct _KM_LOCK
{
    //  Spin lock
    KSPIN_LOCK  SpinLock;

    //  Interrupt request level.
    //  This field is used to store the original IRQL the 
    //  SpinLock was acquired at.
    KIRQL       Irql;

} KM_LOCK, *PKM_LOCK;

/*
    Km_Lock_Initialize routine.

    Purpose:
        Initializes KM_LOCK object.

    Parameters:
        Lock    - Pointer to KM_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER    - The Lock parameter is NULL.

    Remarks:
        The storage for the KM_LOCK object should be resident.
*/
NTSTATUS __stdcall Km_Lock_Initialize(
    __in    PKM_LOCK    Lock);

/*
    Km_Lock_Acquire routine.

    Purpose:
        Acquires (locks) the KM_LOCK object.

    Parameters:
        Lock    - Pointer to KM_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER    - The Lock parameter is NULL.

    Remarks:
        The caller should be running at IRQL <= DISPATCH_LEVEL.
        An attempt to acquire the KM_LOCK object recursively causes a deadlock.
        The IRQL is being raised to DISPATCH_LEVEL after acquiring the KM_LOCK
        and is being reset to the previous value after a call to Km_Lock_Release.
*/
NTSTATUS __stdcall Km_Lock_Acquire(
    __in    PKM_LOCK    Lock);

/*
    Km_Lock_Release routine.

    Purpose:
        Releases (unlocks) the KM_LOCK object.

    Parameters:
        Lock    - Pointer to KM_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER    - The Lock parameter is NULL.

    Remarks:
        The caller should be running at IRQL = DISPATCH_LEVEL.
        The routine restores the IRQL to the level that was stored
        during Km_Lock_Acquire call.
*/
NTSTATUS __stdcall Km_Lock_Release(
    __in    PKM_LOCK    Lock);

#endif