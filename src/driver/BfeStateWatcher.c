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
#include "BfeStateWatcher.h"
#include "..\shared\CommonDefs.h"

#define BFE_STATE_WATCHER_DEVICE_NAME_W L"\\Device\\BFE_STATE_WATCHER_DEVICE"

typedef struct _BFE_STATE_WATCHER
{
    ULONG                               Active;

    HANDLE                              ChangeHandle;

    PKM_MEMORY_MANAGER                  MemoryManager;

    PVOID                               ClientContext;

    FWPM_SERVICE_STATE_CHANGE_CALLBACK  ClientCallback;

    PDEVICE_OBJECT                      DeviceObject;

} BFE_STATE_WATCHER, *PBFE_STATE_WATCHER;

void __stdcall BfeStateWatcher_OnStateChangeCallback(
    __inout PVOID               Context,
    __in    FWPM_SERVICE_STATE  NewState)
{
    PBFE_STATE_WATCHER  Watcher;

    RETURN_IF_FALSE(Assigned(Context));

    Watcher = (PBFE_STATE_WATCHER)Context;

    RETURN_IF_FALSE(Assigned(Watcher->ClientCallback));

    RETURN_IF_FALSE(Watcher->Active);

    Watcher->ClientCallback(
        Watcher->ClientContext,
        NewState);
};

NTSTATUS __stdcall BfeStateWatcher_Initialize(
    __in    PDRIVER_OBJECT                      DriverObject,
    __in    PKM_MEMORY_MANAGER                  MemoryManager,
    __in    FWPM_SERVICE_STATE_CHANGE_CALLBACK  Callback,
    __in    PVOID                               Context,
    __out   PHANDLE                             Instance)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PBFE_STATE_WATCHER  NewWatcher = NULL;
    UNICODE_STRING      DeviceName = RTL_CONSTANT_STRING(BFE_STATE_WATCHER_DEVICE_NAME_W);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DriverObject),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Callback),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Instance),
        STATUS_INVALID_PARAMETER_5);

    NewWatcher = Km_MM_AllocMemTyped(
        MemoryManager,
        BFE_STATE_WATCHER);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewWatcher),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewWatcher, 
        sizeof(BFE_STATE_WATCHER));

    NewWatcher->ClientCallback = Callback;
    NewWatcher->ClientContext = Context;
    NewWatcher->MemoryManager = MemoryManager;

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &NewWatcher->DeviceObject);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewWatcher->Active = TRUE;

    Status = FwpmBfeStateSubscribeChanges(
        NewWatcher->DeviceObject,
        BfeStateWatcher_OnStateChangeCallback,
        NewWatcher,
        &NewWatcher->ChangeHandle);

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewWatcher))
        {
            if (Assigned(NewWatcher->DeviceObject))
            {
                IoDeleteDevice(NewWatcher->DeviceObject);
            }

            Km_MM_FreeMem(
                MemoryManager,
                NewWatcher);
        }
    }
    else
    {
        *Instance = (HANDLE)NewWatcher;
    }

    return Status;
};

NTSTATUS __stdcall BfeStateWatcher_Finalize(
    __in    HANDLE  Instance)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PBFE_STATE_WATCHER  Watcher = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);

    Watcher = (PBFE_STATE_WATCHER)Instance;

    InterlockedExchange((volatile LONG *)&Watcher->Active, FALSE);

    if (Watcher->ChangeHandle != NULL)
    {
        FwpmBfeStateUnsubscribeChanges(Watcher->ChangeHandle);
    }

    if (Assigned(Watcher->DeviceObject))
    {
        IoDeleteDevice(Watcher->DeviceObject);
    }

    Km_MM_FreeMem(
        Watcher->MemoryManager,
        Watcher);

cleanup:
    return Status;
};