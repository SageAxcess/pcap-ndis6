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


#pragma once

#include <ntddk.h>

//  Multi-read/exclusive-write lock object
typedef struct _KM_MREW_LOCK    KM_MREW_LOCK, *PKM_MREW_LOCK;

/*
    Km_MREW_Lock_Initialize routine.

    Purpose:
        Initializes KM_MREW_LOCK object.

    Parameters:
        Lock    - Pointer to KM_MREW_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER_1  - The Lock parameter is NULL.

    Remarks:
        The storage for the KM_MREW_LOCK object should be allocated
        from a non-paged pool.
*/
NTSTATUS __stdcall Km_MREW_Lock_Initialize(
    __inout PKM_MREW_LOCK   Lock);

/*
    Km_MREW_Lock_AcquireRead routine.

    Purpose:
        Acquires read (shared) access to the lock object.

    Parameters:
        Lock    - Pointer to KM_MREW_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER_1  - The Lock parameter is NULL.

    Remarks:
        Acquiring a KM_MREW_LOCK object recursively leads to
        a guaranteed dead lock.
*/
NTSTATUS __stdcall Km_MREW_Lock_AcquireRead(
    __inout PKM_MREW_LOCK   Lock);

/*
    Km_MREW_Lock_AcquireWrite routine.

    Purpose:
        Acquires write (exclusive) access to the lock object.

    Parameters:
        Lock    - Pointer to KM_MREW_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER_1  - The Lock parameter is NULL.

    Remarks:
        Acquiring a KM_MREW_LOCK object recursively leads to
        a guaranteed dead lock.
*/
NTSTATUS __stdcall Km_MREW_Lock_AcquireWrite(
    __inout PKM_MREW_LOCK   Lock);

/*
    Km_MREW_Lock_ReleaseRead routine.

    Purpose:
        Releases a previously acquired read (shared) access 
        to the lock object.

    Parameters:
        Lock    - Pointer to KM_MREW_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER_1  - The Lock parameter is NULL.
*/
NTSTATUS __stdcall Km_MREW_Lock_ReleaseRead(
    __inout PKM_MREW_LOCK   Lock);

/*
    Km_MREW_Lock_ReleaseWrite routine.

    Purpose:
        Releases a previously acquired write (exclusive) access
        to the lock object.

    Parameters:
        Lock    - Pointer to KM_MREW_LOCK structure representing the lock.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER_1  - The Lock parameter is NULL.
*/
NTSTATUS __stdcall Km_MREW_Lock_ReleaseWrite(
    __inout PKM_MREW_LOCK   Lock);