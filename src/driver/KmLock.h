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

#ifndef KM_LOCK_H
#define KM_LOCK_H

#include <ntddk.h>

typedef struct _KM_LOCK
{
    KSPIN_LOCK  SpinLock;
    KIRQL       Irql;
} KM_LOCK, *PKM_LOCK;

NTSTATUS __stdcall Km_Lock_Initialize(
    __in    PKM_LOCK    Lock);

NTSTATUS __stdcall Km_Lock_Acquire(
    __in    PKM_LOCK    Lock);

NTSTATUS __stdcall Km_Lock_Release(
    __in    PKM_LOCK    Lock);

#endif