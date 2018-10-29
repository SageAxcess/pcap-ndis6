//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 ChangeDynamix, LLC
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef KM_TIMER_H
#define KM_TIMER_H

#include "KmMemoryManager.h"

#define KM_TIMER_MEMORY_TAG 'TMTK'

typedef struct _KM_TIMER
{
    PKM_MEMORY_MANAGER  MemoryManager;

    KTIMER              Timer;

} KM_TIMER, *PKM_TIMER;

NTSTATUS __stdcall KmTimer_Allocate(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PKM_TIMER           *Timer);

NTSTATUS __stdcall KmTimer_Destroy(
    __in    PKM_TIMER   Timer);

NTSTATUS __stdcall KmTimer_Cancel(
    __in    PKM_TIMER   Timer);

NTSTATUS __stdcall KmTimer_SetExpiration(
    __in    PKM_TIMER   Timer,
    __in    ULONG       Value,
    __in    BOOLEAN     Reccurring);

#endif