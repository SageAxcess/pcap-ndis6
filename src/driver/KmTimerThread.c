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

#include "KmTimerThread.h"
#include "..\shared\CommonDefs.h"
#include "KmList.h"
#include "KmMemoryPool.h"

#define KM_TIMER_THREAD_WAIT_OBJECTS_COUNT  0x2

typedef enum _KM_TIMER_THREAD_PARAMS_UPDATE_TYPE
{
    UpdateType_Timeout = 0,

    UpdateType_Callback = 1,

} KM_TIMER_THREAD_PARAMS_UPDATE_TYPE, *PKM_TIMER_THREAD_PARAMS_UPDATE_TYPE;

typedef struct _KM_TIMER_THREAD_PARAMS_UPDATE_DATA
{
    LIST_ENTRY                          Link;

    KM_TIMER_THREAD_PARAMS_UPDATE_TYPE  Type;

    union _DATA
    {
        ULONG                       Timeout;

        PKM_TIMER_THREAD_ROUTINE    Callback;

    } Data;

} KM_TIMER_THREAD_PARAMS_UPDATE_DATA, *PKM_TIMER_THREAD_PARAMS_UPDATE_DATA;

typedef struct _KM_TIMER_THREAD
{
    PKM_MEMORY_MANAGER          MemoryManager;

    PKM_THREAD                  Thread;

    PKM_TIMER_THREAD_ROUTINE    Callback;

    PVOID                       CallbackContext;

    ULONG                       Timeout;

    PKWAIT_BLOCK                WaitBlocks;

    struct _PARAMS_UPDATE
    {
        KEVENT  Event;

        KM_LIST AllocatedItems;

        HANDLE  AvailableItems;

    } ParamsUpdate;

} KM_TIMER_THREAD, *PKM_TIMER_THREAD;

NTSTATUS __stdcall KmTimerThread_AllocateUpdateData(
    __in    PKM_TIMER_THREAD                    Thread,
    __out   PKM_TIMER_THREAD_PARAMS_UPDATE_DATA *Data)
{
    NTSTATUS                            Status = STATUS_SUCCESS;
    PKM_TIMER_THREAD_PARAMS_UPDATE_DATA NewData = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_2);

    Status = Km_List_Lock(&Thread->ParamsUpdate.AllocatedItems);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_MP_AllocateCheckSize(
            Thread->ParamsUpdate.AvailableItems,
            sizeof(KM_TIMER_THREAD_PARAMS_UPDATE_DATA),
            (PVOID *)&NewData);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        RtlZeroMemory(
            NewData,
            sizeof(KM_TIMER_THREAD_PARAMS_UPDATE_DATA));

        *Data = NewData;
    }
    __finally
    {
        Km_List_Unlock(&Thread->ParamsUpdate.AllocatedItems);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTimerThread_SubmitParamsUpdate(
    __in    PKM_TIMER_THREAD                    Thread,
    __in    PKM_TIMER_THREAD_PARAMS_UPDATE_DATA Data)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_2);

    Status = Km_List_Lock(&Thread->ParamsUpdate.AllocatedItems);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_AddItemEx(
            &Thread->ParamsUpdate.AllocatedItems,
            &Data->Link,
            FALSE,
            FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        KeSetEvent(&Thread->ParamsUpdate.Event, 0, FALSE);
    }
    __finally
    {
        Km_List_Unlock(&Thread->ParamsUpdate.AllocatedItems);
    }
cleanup:
    return Status;
};

void __stdcall KmTimerThread_ThreadRoutine(
    __in    PKM_THREAD  Thread)
{
    PKM_TIMER_THREAD    TimerThread = NULL;
    PVOID               WaitArray[KM_TIMER_THREAD_WAIT_OBJECTS_COUNT];
    BOOLEAN             StopThread = FALSE;
    NTSTATUS            Status = STATUS_SUCCESS;
    LARGE_INTEGER       WaitTimeout = { 0 };

    RETURN_IF_FALSE(Assigned(Thread));
    RETURN_IF_FALSE(Assigned(Thread->Context));

    TimerThread = (PKM_TIMER_THREAD)Thread->Context;

    RtlZeroMemory(
        WaitArray, 
        sizeof(PVOID) * KM_TIMER_THREAD_WAIT_OBJECTS_COUNT);

    WaitArray[0] = (PVOID)&Thread->StopEvent;
    WaitArray[1] = (PVOID)&TimerThread->ParamsUpdate.Event;

    while (!StopThread)
    {
        if (TimerThread->Timeout > 0)
        {
            WaitTimeout.QuadPart = (-1) * (MilisecondsTo100Nanoseconds(TimerThread->Timeout));
        }

        Status = KeWaitForMultipleObjects(
            KM_TIMER_THREAD_WAIT_OBJECTS_COUNT,
            WaitArray,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            TimerThread->Timeout == 0 ? NULL : &WaitTimeout,
            TimerThread->WaitBlocks);

        switch (Status)
        {
        case STATUS_WAIT_0:
            {
                StopThread = TRUE;
            }break;

        case STATUS_WAIT_1:
            {
                LIST_ENTRY  TmpList;
                ULARGE_INTEGER  Count = { MAXULONGLONG };

                InitializeListHead(&TmpList);

                Km_List_Lock(&TimerThread->ParamsUpdate.AllocatedItems);
                __try
                {
                    Km_List_ExtractEntriesEx(
                        &TimerThread->ParamsUpdate.AllocatedItems,
                        &TmpList,
                        &Count,
                        FALSE,
                        FALSE);

                    KeClearEvent(&TimerThread->ParamsUpdate.Event);

                    while (!IsListEmpty(&TmpList))
                    {
                        PKM_TIMER_THREAD_PARAMS_UPDATE_DATA Data =
                            CONTAINING_RECORD(RemoveHeadList(&TmpList), KM_TIMER_THREAD_PARAMS_UPDATE_DATA, Link);
                        __try
                        {
                            switch (Data->Type)
                            {
                            case UpdateType_Callback:
                                {
                                    TimerThread->Callback = Data->Data.Callback;
                                }break;

                            case UpdateType_Timeout:
                                {
                                    TimerThread->Timeout = Data->Data.Timeout;
                                }break;
                            };
                        }
                        __finally
                        {
                            Km_MP_Release((PVOID)Data);
                        }
                    }
                }
                __finally
                {
                    Km_List_Unlock(&TimerThread->ParamsUpdate.AllocatedItems);
                }
            }break;

        case STATUS_TIMEOUT:
            {
                if (Assigned(TimerThread->Callback))
                {
                    __try
                    {
                        TimerThread->Callback(
                            TimerThread,
                            TimerThread->CallbackContext);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                    }
                }
            }break;
        };

        if (!StopThread)
        {
            WaitTimeout.QuadPart = 0;
            StopThread =
                KeWaitForSingleObject(
                    WaitArray[0],
                    Executive,
                    KernelMode,
                    FALSE,
                    &WaitTimeout) == STATUS_WAIT_0;
        }
    }
};

NTSTATUS __stdcall KmTimerThread_Allocate(
    __in        PKM_MEMORY_MANAGER          MemoryManager,
    __in        PKM_TIMER_THREAD_ROUTINE    ThreadRoutine,
    __in_opt    PVOID                       ThreadContext,
    __out       PKM_TIMER_THREAD            *Thread)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_TIMER_THREAD    NewThread = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ThreadRoutine),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_4);

    NewThread = Km_MM_AllocMemTypedWithTag(
        MemoryManager,
        KM_TIMER_THREAD,
        KM_TIMER_THREAD_MEMORY_TAG);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewThread),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        RtlZeroMemory(
            NewThread,
            sizeof(KM_TIMER_THREAD));

        NewThread->WaitBlocks = Km_MM_AllocArrayWithTag(
            MemoryManager,
            KWAIT_BLOCK,
            KM_TIMER_THREAD_WAIT_OBJECTS_COUNT,
            KM_TIMER_THREAD_MEMORY_TAG);
        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(NewThread->WaitBlocks),
            STATUS_INSUFFICIENT_RESOURCES);
        __try
        {
            NewThread->Callback = ThreadRoutine;
            NewThread->MemoryManager = MemoryManager;
            NewThread->CallbackContext = ThreadContext;

            KeInitializeEvent(
                &NewThread->ParamsUpdate.Event,
                NotificationEvent,
                FALSE);

            Status = Km_List_Initialize(&NewThread->ParamsUpdate.AllocatedItems);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            Status = Km_MP_Initialize(
                MemoryManager,
                (ULONG)sizeof(KM_TIMER_THREAD_PARAMS_UPDATE_DATA),
                0,
                FALSE,
                KM_TIMER_THREAD_MEMORY_TAG,
                &NewThread->ParamsUpdate.AvailableItems);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            __try
            {
                Status = KmThreads_CreateThread(
                    MemoryManager,
                    &NewThread->Thread,
                    KmTimerThread_ThreadRoutine,
                    NewThread);
            }
            __finally
            {
                if (!NT_SUCCESS(Status))
                {
                    Km_MP_Finalize(&NewThread->ParamsUpdate.AvailableItems);
                }
            }
        }
        __finally
        {
            if (!NT_SUCCESS(Status))
            {
                Km_MM_FreeMem(
                    MemoryManager,
                    NewThread->WaitBlocks);
            }
        }
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            Km_MM_FreeMem(
                MemoryManager,
                NewThread);
        }
    }

    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    *Thread = NewThread;
    
cleanup:
    return Status;
};

NTSTATUS __stdcall KmTimerThread_SetInterval(
    __in    PKM_TIMER_THREAD    Thread,
    __in    ULONG               Interval)
{
    NTSTATUS                            Status = STATUS_SUCCESS;
    PKM_TIMER_THREAD_PARAMS_UPDATE_DATA UpdateData = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_1);

    Status = KmTimerThread_AllocateUpdateData(
        Thread,
        &UpdateData);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        UpdateData->Type = UpdateType_Timeout;
        UpdateData->Data.Timeout = Interval;

        Status = KmTimerThread_SubmitParamsUpdate(Thread, UpdateData);
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            Km_MP_Release(UpdateData);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTimerThread_Stop(
    __in    PKM_TIMER_THREAD    Thread,
    __in    ULONG               Timeout)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_1);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread->Thread),
        STATUS_UNSUCCESSFUL);

    Status = KmThreads_StopThread(Thread->Thread, Timeout);

cleanup:
    return Status;
};

NTSTATUS __stdcall KmTimerThread_Destroy(
    __in    PKM_TIMER_THREAD    Thread)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Thread),
        STATUS_INVALID_PARAMETER_1);

    if (Assigned(Thread->Thread))
    {
        KmThreads_DestroyThread(Thread->Thread);
    }

    if (Assigned(Thread->WaitBlocks))
    {
        Km_MM_FreeMem(
            Thread->MemoryManager,
            Thread->WaitBlocks);
    }

    if (Thread->ParamsUpdate.AvailableItems != NULL)
    {
        LIST_ENTRY      TmpList;
        ULARGE_INTEGER  Count = { MAXULONGLONG };

        InitializeListHead(&TmpList);

        Km_List_Lock(&Thread->ParamsUpdate.AllocatedItems);
        __try
        {
            Km_List_ExtractEntriesEx(
                &Thread->ParamsUpdate.AllocatedItems,
                &TmpList,
                &Count,
                FALSE,
                FALSE);

            while (!IsListEmpty(&TmpList))
            {
                Km_MP_Release(
                    CONTAINING_RECORD(
                        RemoveHeadList(&TmpList),
                        KM_TIMER_THREAD_PARAMS_UPDATE_DATA,
                        Link));
            }
        }
        __finally
        {
            Km_List_Unlock(&Thread->ParamsUpdate.AllocatedItems);
        }

        Km_MP_Finalize(&Thread->ParamsUpdate.AvailableItems);
    }

    Km_MM_FreeMem(
        Thread->MemoryManager,
        Thread);

cleanup:
    return Status;
};