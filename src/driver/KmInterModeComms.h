//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#pragma once

#include <ntddk.h>
#include "KmTypes.h"

typedef NTSTATUS(__stdcall _KM_IMC_IOCTL_CALLBACK)(
    __in    PVOID       Context,
    __in    ULONG       ControlCode,
    __in    PVOID       InBuffer,
    __in    ULONG       InBufferSize,
    __out   PVOID       OutBuffer,
    __in    ULONG       OutBufferSize,
    __out   PULONG_PTR  BytesReturned);

typedef _KM_IMC_IOCTL_CALLBACK  KM_IMC_IOCTL_CALLBACK, *PKM_IMC_IOCTL_CALLBACK;

NTSTATUS __stdcall Km_IMC_Initialize(
    __in        PKM_MEMORY_MANAGER      MemoryManager,
    __in        PDRIVER_OBJECT          DriverObject,
    __in        PKM_IMC_IOCTL_CALLBACK  IOCTLCallback,
    __in        PUNICODE_STRING         DeviceName,
    __in        ULONG                   DeviceType,
    __out       PHANDLE                 InstanceHandle,
    __in_opt    PVOID                   Context);

NTSTATUS __stdcall Km_IMC_Finalize(
    __in    HANDLE  Instance);