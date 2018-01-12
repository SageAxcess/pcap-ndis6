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
// Author: Mikhail Burilov
// 
// Based on original WinPcap source code - https://www.winpcap.org/
// Copyright(c) 1999 - 2005 NetGroup, Politecnico di Torino(Italy)
// Copyright(c) 2005 - 2007 CACE Technologies, Davis(California)
// Filter driver based on Microsoft examples - https://github.com/Microsoft/Windows-driver-samples
// Copyrithg(C) 2015 Microsoft
// All rights reserved.
//////////////////////////////////////////////////////////////////////

#include "precomp.h"
#include "Events.h"
#include "KernelUtil.h"
#include "..\shared\CommonDefs.h"

volatile ULONG _curEventId = 0;

NTSTATUS InitializeEvent(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __inout PEVENT              Event)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    ULONG           EventId = 0;
    LARGE_INTEGER   Timestamp = { 0, };
    char            FullEventName[256];
    PUNICODE_STRING EventNameU = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Event),
        STATUS_INVALID_PARAMETER_2);

    RtlZeroMemory(Event, sizeof(EVENT));

    EventId = InterlockedIncrement((volatile LONG *)&_curEventId);
    Timestamp = KeQueryPerformanceCounter(NULL);

    sprintf_s(Event->Name, 256, EVENT_NAME_FMT, EventId, Timestamp.QuadPart);

    RtlZeroMemory(FullEventName, sizeof(FullEventName));

    sprintf_s(FullEventName, 256, "\\BaseNamedObjects\\%s", Event->Name);

    EventNameU = CreateString(
        MemoryManager,
        FullEventName);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EventNameU),
        STATUS_INSUFFICIENT_RESOURCES);

    Event->Event = IoCreateNotificationEvent(
        EventNameU,
        &Event->EventHandle);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Event->Event),
        STATUS_INSUFFICIENT_RESOURCES);

    KeClearEvent(Event->Event);

cleanup:

    if (Assigned(EventNameU))
    {
        FreeString(
            MemoryManager,
            EventNameU);
    }

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(Event))
        {
            if (Event->EventHandle != NULL)
            {
                ZwClose(Event->EventHandle);
            }
            RtlZeroMemory(Event, sizeof(EVENT));
        }
    }

    return Status;
};

NTSTATUS FinalizeEvent(
    __in    PEVENT  Event)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Event),
        STATUS_INVALID_PARAMETER_1);

    if (Event->EventHandle != NULL)
    {
        ZwClose(Event->EventHandle);
    }

    RtlZeroMemory(Event, sizeof(EVENT));

cleanup:
    return Status;
};