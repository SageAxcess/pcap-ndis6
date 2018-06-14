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

#ifndef KM_EVENT_H
#define KM_EVENT_H

#include "KmMemoryManager.h"

typedef struct _KM_EVENT
{
    PVOID   EventObject;
} KM_EVENT, *PKM_EVENT;

typedef void(__stdcall _KM_EVENT_WAIT_COMPLETION_ROUTINE)(
    __in    PKM_EVENT   Event,
    __in    PVOID       Context);

typedef _KM_EVENT_WAIT_COMPLETION_ROUTINE KM_EVENT_WAIT_COMPLETION_ROUTINE, *PKM_EVENT_WAIT_COMPLETION_ROUTINE;

NTSTATUS __stdcall KmEvent_Create(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    EVENT_TYPE          EventType,
    __in    BOOLEAN             InitialState,
    __out   PKM_EVENT           *Event);

NTSTATUS __stdcall KmEvent_Destroy(
    __in    PKM_EVENT   Event);

NTSTATUS __stdcall KmEvent_WaitFor(
    __in    PKM_EVENT       Event,
    __in    BOOLEAN         Alertable,
    __in    PLARGE_INTEGER  Timeout);

#endif