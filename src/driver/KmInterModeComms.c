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

#include "KmInterModeComms.h"
#include "KernelUtil.h"

#define DEVICE_NAME_PREFIX_W            L"\\Device\\"
#define DEVICE_SYM_LINK_NAME_PREFIX_W   L"\\DosDevices\\Global\\"

NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
Km_IMC_IoControlHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    IRP             *Irp);


typedef struct _KM_IMC_DATA
{
    //  Memory manager
    PKM_MEMORY_MANAGER      MemoryManager;

    //  Callback received during initialization
    PKM_IMC_IOCTL_CALLBACK  IOCTLCallback;

    //  Client-specific context value
    PVOID                   Context;

    //  IMC Device object
    PDEVICE_OBJECT          DeviceObject;

    //  Symbolic link name
    PUNICODE_STRING         SymLinkName;

} KM_IMC_DATA, *PKM_IMC_DATA;

typedef struct _KM_IMC_DEVICE_EXTENSION
{
    PKM_IMC_DATA    Data;
} KM_IMC_DEVICE_EXTENSION, *PKM_IMC_DEVICE_EXTENSION;

NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
Km_IMC_IoControlHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    IRP             *Irp)
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    PKM_IMC_DEVICE_EXTENSION    Extension = NULL;
    PKM_IMC_IOCTL_CALLBACK      Callback = NULL;
    PVOID                       CallbackContext = NULL;
    PIO_STACK_LOCATION          IoStackLocation = NULL;
    ULONG_PTR                   ReturnSize = 0;
    PVOID                       InBuffer = NULL;
    PVOID                       OutBuffer = NULL;
    ULONG                       InBufferSize = 0;
    ULONG                       OutBufferSize = 0;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (Assigned(DeviceObject)) &&
        (Assigned(Irp)),
        STATUS_UNSUCCESSFUL);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceObject->DeviceExtension),
        STATUS_UNSUCCESSFUL);

    Extension = (PKM_IMC_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Extension->Data),
        STATUS_UNSUCCESSFUL);

    CallbackContext = Extension->Data->Context;
    Callback = Extension->Data->IOCTLCallback;

    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

    Status = IOUtils_ValidateAndGetIOBuffers(
        Irp,
        &InBuffer,
        &InBufferSize,
        &OutBuffer,
        &OutBufferSize);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    if (Assigned(Callback))
    {
        Status = Callback(
            CallbackContext,
            IoStackLocation->Parameters.DeviceIoControl.IoControlCode,
            InBuffer,
            InBufferSize,
            OutBuffer,
            OutBufferSize,
            &ReturnSize);
    }

cleanup:

    if (Assigned(Irp))
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = ReturnSize;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
};

NTSTATUS __stdcall Km_IMC_Initialize(
    __in        PKM_MEMORY_MANAGER      MemoryManager,
    __in        PDRIVER_OBJECT          DriverObject,
    __in        PKM_IMC_IOCTL_CALLBACK  IOCTLCallback,
    __in        PUNICODE_STRING         DeviceName,
    __in        ULONG                   DeviceType,
    __out       PHANDLE                 InstanceHandle,
    __in_opt    PVOID                   Context)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PUNICODE_STRING SymLinkName = NULL;
    PUNICODE_STRING DevName = NULL;
    USHORT          SymLinkNameLength = 0;
    USHORT          DevNameLength = 0;
    PKM_IMC_DATA    NewData = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DriverObject),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(IOCTLCallback),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceName),
        STATUS_INVALID_PARAMETER_4);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        DeviceName->Length >= sizeof(wchar_t),
        STATUS_INVALID_PARAMETER_4);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InstanceHandle),
        STATUS_INVALID_PARAMETER_6);

    NewData = Km_MM_AllocMemTyped(
        MemoryManager,
        KM_IMC_DATA);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewData),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewData, sizeof(KM_IMC_DATA));

    NewData->MemoryManager = MemoryManager;
    NewData->IOCTLCallback = IOCTLCallback;
    NewData->Context = Context;

    DevNameLength =
        DeviceName->Length +
        (USHORT)sizeof(DEVICE_NAME_PREFIX_W);

    DevName = AllocateString(
        MemoryManager,
        DevNameLength);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DevName),
        STATUS_INSUFFICIENT_RESOURCES);

    Status = RtlAppendUnicodeToString(
        DevName,
        DEVICE_NAME_PREFIX_W);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = RtlAppendUnicodeStringToString(
        DevName,
        DeviceName);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    SymLinkNameLength =
        DeviceName->Length +
        (USHORT)sizeof(DEVICE_SYM_LINK_NAME_PREFIX_W);

    SymLinkName = AllocateString(
        MemoryManager,
        SymLinkNameLength);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(SymLinkName),
        STATUS_INSUFFICIENT_RESOURCES);

    Status = RtlAppendUnicodeToString(
        SymLinkName,
        DEVICE_SYM_LINK_NAME_PREFIX_W);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = RtlAppendUnicodeStringToString(
        SymLinkName,
        DeviceName);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = IoCreateDevice(
        DriverObject,
        (ULONG)sizeof(KM_IMC_DEVICE_EXTENSION),
        DevName,
        DeviceType,
        0,
        FALSE,
        &NewData->DeviceObject);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    ((PKM_IMC_DEVICE_EXTENSION)NewData->DeviceObject->DeviceExtension)->Data = NewData;

    Status = IoCreateSymbolicLink(SymLinkName, DeviceName);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewData->SymLinkName = SymLinkName;
    SymLinkName = NULL;

    *InstanceHandle = (HANDLE)NewData;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Km_IMC_IoControlHandler;

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewData))
        {
            if (Assigned(NewData->DeviceObject))
            {
                IoDeleteDevice(NewData->DeviceObject);
            }

            Km_MM_FreeMem(
                MemoryManager,
                NewData);
        }
    }

    if (Assigned(DevName))
    {
        FreeString(
            MemoryManager,
            DevName);
    }

    if (Assigned(SymLinkName))
    {
        FreeString(
            MemoryManager,
            SymLinkName);
    }

    return Status;
};

NTSTATUS __stdcall Km_IMC_Finalize(
    __in    HANDLE  Instance)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PKM_IMC_DATA    Data = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);

    Data = (PKM_IMC_DATA)Instance;

    InterlockedExchangePointer(
        (PVOID *)&Data->IOCTLCallback,
        NULL);

    if (Assigned(Data->SymLinkName))
    {
        IoDeleteSymbolicLink(Data->SymLinkName);
        FreeString(
            Data->MemoryManager,
            Data->SymLinkName);
    }

    if (Assigned(Data->DeviceObject))
    {
        IoDeleteDevice(Data->DeviceObject);
    }

    Km_MM_FreeMem(
        Data->MemoryManager,
        Data);

cleanup:
    return Status;
};