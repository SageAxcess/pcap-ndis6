#pragma once

#include <ndis.h>

typedef NTSTATUS(__stdcall _IMR_IOCTL_HANDLER)(
    __in    HANDLE  ImrInstance,
    __in    PVOID   AssociatedContext,
    __in    PIRP    Irp);
typedef _IMR_IOCTL_HANDLER   IMR_IOCTL_HANDLER, *PIMR_IOCTL_HANDLER;

NTSTATUS __stdcall IMR_Initialize(
    __in        PIMR_IOCTL_HANDLER  CallbackRoutine,
    __in_opt    PVOID               AssociatedContext,
    __out       PHANDLE             InstanceHandle);

NTSTATUS __stdcall IMR_Finalize(
    __in    PHANDLE InstanceHandle);

NTSTATUS __stdcall 