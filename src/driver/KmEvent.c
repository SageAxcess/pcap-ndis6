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

#include "KmEvent.h"
#include "KmThreads.h"

typedef struct _KM_EVENT_OBJECT
{
    PKM_MEMORY_MANAGER  MemoryManager;

    KEVENT              EventObject;

    KM_EVENT            KmEvent;

} KM_EVENT_OBJECT, *PKM_EVENT_OBJECT;

#define KM_EVENT_OBJECT_WAIT_FLAG_NONE          0x0
#define KM_EVENT_OBJECT_WAIT_FLAG_INFINITE_WAIT 0x1

typedef struct _KM_EVENT_OBJECT_ASYNC_WAIT_PARAMS
{
    PKM_EVENT_OBJECT                    EventObject;

    ULONG                               Flags;

    LARGE_INTEGER                       Timeout;

    PKM_EVENT_WAIT_COMPLETION_ROUTINE   WaitCompletionRoutine;

    PVOID                               ClientContext;

} KM_EVENT_OBJECT_ASYNC_WAIT_PARAMS, *PKM_EVENT_OBJECT_ASYNC_WAIT_PARAMS;

NTSTATUS __stdcall KmEvent_Create(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    EVENT_TYPE          EventType,
    __in    BOOLEAN             InitialState,
    __out   PKM_EVENT           *Event)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_EVENT_OBJECT    NewEvent = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Event),
        STATUS_INVALID_PARAMETER_4);

    NewEvent = Km_MM_AllocMemTyped(MemoryManager, KM_EVENT_OBJECT);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewEvent),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewEvent, sizeof(KM_EVENT_OBJECT));

    NewEvent->MemoryManager = MemoryManager;
    KeInitializeEvent(&NewEvent->EventObject, EventType, InitialState);
    NewEvent->KmEvent.EventObject = (PVOID)NewEvent;

    *Event = &NewEvent->KmEvent;

cleanup:
    return Status;
};

NTSTATUS __stdcall KmEvent_Destroy(
    __in    PKM_EVENT   Event)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_EVENT_OBJECT    EventObject = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Event),
        STATUS_INVALID_PARAMETER_1);

    EventObject = CONTAINING_RECORD(Event, KM_EVENT_OBJECT, KmEvent);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        ((PVOID)EventObject != Event->EventObject) &&
        (Assigned(Event->EventObject)),
        STATUS_INVALID_PARAMETER_1);

    Km_MM_FreeMem(
        EventObject->MemoryManager,
        EventObject);

cleanup:
    return Status;
};

NTSTATUS __stdcall KmEvent_WaitFor(
    __in    PKM_EVENT       Event,
    __in    BOOLEAN         Alertable,
    __in    PLARGE_INTEGER  Timeout)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_EVENT_OBJECT    EventObject = NULL;
    KIRQL               Irql;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Event),
        STATUS_INVALID_PARAMETER_1);

    Irql = KeGetCurrentIrql();
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Irql <= DISPATCH_LEVEL,
        STATUS_UNSUCCESSFUL);

    if (Assigned(Timeout))
    {
        GOTO_CLEANUP_IF_TRUE_SET_STATUS(
            (Timeout->QuadPart != 0) &&
            (Irql > APC_LEVEL),
            STATUS_UNSUCCESSFUL);
    }
    else
    {
        GOTO_CLEANUP_IF_TRUE_SET_STATUS(
            Irql > APC_LEVEL,
            STATUS_UNSUCCESSFUL);
    }

    Status = KeWaitForSingleObject(
        &EventObject->EventObject,
        Executive,
        KernelMode,
        Alertable,
        Timeout);

cleanup:
    return Status;
};