#include "..\shared\CommonDefs.h"

#include <ntddk.h>

#include "KmThreads.h"

typedef struct _KM_THREAD_ROUTINE_PARAMS
{
    PKM_THREAD          Thread;
    PKM_THREAD_FUNCTION ThreadFunction;
} KM_THREAD_ROUTINE_PARAMS, *PKM_THREAD_ROUTINE_PARAMS;

void KmThreads_ThreadRoutine(
    __in    PVOID   ThreadContext)
{
    if (Assigned(ThreadContext))
    {
        PKM_THREAD_ROUTINE_PARAMS   Params = (PKM_THREAD_ROUTINE_PARAMS)ThreadContext;
        __try
        {
            Params->ThreadFunction(Params->Thread);
        }
        __finally
        {
            Km_MM_FreeMem(
                Params->Thread->MemoryManager,
                Params);
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
};

NTSTATUS __stdcall KmThreads_CreateThread(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out	PKM_THREAD          *Thread,
    __in    PKM_THREAD_FUNCTION ThreadFunction,
    __in	PVOID			    Context)
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    HANDLE                      ThreadHandle = NULL;
    PKM_THREAD_ROUTINE_PARAMS   Params = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ThreadFunction),
        STATUS_INVALID_PARAMETER_3);

    Params = Km_MM_AllocMemTyped(
        MemoryManager,
        KM_THREAD_ROUTINE_PARAMS);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Params),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        Params->Thread = Km_MM_AllocMemTyped(
            MemoryManager,
            KM_THREAD);
        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(Params->Thread),
            STATUS_INSUFFICIENT_RESOURCES);
        __try
        {
            Params->ThreadFunction = ThreadFunction;
            Params->Thread->Context = Context;
            Params->Thread->MemoryManager = MemoryManager;
            KeInitializeEvent(
                &Params->Thread->StopEvent,
                NotificationEvent,
                FALSE);
            Status = PsCreateSystemThread(
                &ThreadHandle,
                THREAD_ALL_ACCESS,
                NULL,
                NULL,
                NULL,
                KmThreads_ThreadRoutine,
                Params);
            if (NT_SUCCESS(Status))
            {
                ObReferenceObjectByHandle(
                    ThreadHandle,
                    0,
                    NULL,
                    KernelMode,
                    (PVOID *)&Params->Thread->ThreadObject,
                    NULL);
                ZwClose(ThreadHandle);
                *Thread = Params->Thread;
                Params = NULL;
            }
        }
        __finally
        {
            if (Assigned(Params))
            {
                if (Assigned(Params->Thread))
                {
                    Km_MM_FreeMem(
                        MemoryManager,
                        Params->Thread);
                }
            }
        }
    }
    __finally
    {
        if (Assigned(Params))
        {
            Km_MM_FreeMem(
                MemoryManager,
                Params);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmThreads_DestroyThread(
    __in    PKM_THREAD  Thread)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_1);

    if (Assigned(Thread->ThreadObject))
    {
        ObDereferenceObject(Thread->ThreadObject);
    }

    Km_MM_FreeMem(
        Thread->MemoryManager,
        Thread);

cleanup:
    return Status;
};

NTSTATUS __stdcall KmThreads_StopThread(
    __in    PKM_THREAD  Thread,
    __in    ULONG       WaitTimeout)

{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread->ThreadObject),
        STATUS_INVALID_PARAMETER_1);

    KeSetEvent(
        &Thread->StopEvent,
        0,
        FALSE);

    if (WaitTimeout != MAXULONG)
    {
        LARGE_INTEGER   Timeout;
        KIRQL           Irql = KeGetCurrentIrql();
        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Irql <= APC_LEVEL,
            STATUS_UNSUCCESSFUL);

        Timeout.QuadPart = (-1) * WaitTimeout;
        Status = KeWaitForSingleObject(
            Thread->ThreadObject,
            Executive,
            KernelMode,
            FALSE,
            &Timeout);
    }
    else
    {
        Status = KeWaitForSingleObject(
            Thread->ThreadObject,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }

cleanup:
    return Status;
};