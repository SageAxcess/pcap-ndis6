#include "KmProcessWatcher.h"
#include "KmLock.h"
#include "KmList.h"

typedef struct _KM_PROCESS_WATCHER_CALLBACK_ITEM
{
    LIST_ENTRY                      Link;
    PKM_PROCESS_WATCHER_CALLBACK    Callback;
    PVOID                           Context;
} KM_PROCESS_WATCHER_CALLBACK_ITEM, *PKM_PROCESS_WATCHER_CALLBACK_ITEM;

typedef struct _KM_PROCESS_WATCHER_DATA
{
    //  Memory manager

    PKM_MEMORY_MANAGER  MemoryManager;

    //  Callbacks list
    KM_LIST             CallbacksList;

} KM_PROCESS_WATCHER_DATA, *PKM_PROCESS_WATCHER_DATA;

PKM_PROCESS_WATCHER_DATA    ProcessWatcherData = NULL;

void Km_ProcessWatcher_NotifyRoutine(
    __in    HANDLE  ParentId,
    __in    HANDLE  ProcessId,
    __in    BOOLEAN Create)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    RETURN_IF_FALSE(
        Assigned(ProcessWatcherData));

    Status = Km_List_Lock(&ProcessWatcherData->CallbacksList);
    RETURN_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PLIST_ENTRY Entry;

        for (Entry = ProcessWatcherData->CallbacksList.Head.Flink;
            Entry != &ProcessWatcherData->CallbacksList.Head;
            Entry = Entry->Flink)
        {
            PKM_PROCESS_WATCHER_CALLBACK_ITEM   Item =
                CONTAINING_RECORD(Entry, KM_PROCESS_WATCHER_CALLBACK_ITEM, Link);

            if (Assigned(Item->Callback))
            {
                Item->Callback(
                    ParentId,
                    ProcessId,
                    Create,
                    Item->Context);
            }
        };
    }
    __finally
    {
        Km_List_Unlock(&ProcessWatcherData->CallbacksList);
    }
};

NTSTATUS __stdcall Km_ProcessWatcher_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager)
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    PKM_PROCESS_WATCHER_DATA    NewData = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);

    Status = PsSetCreateProcessNotifyRoutine(
        Km_ProcessWatcher_NotifyRoutine,
        FALSE);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewData = Km_MM_AllocMemTyped(
        MemoryManager,
        KM_PROCESS_WATCHER_DATA);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewData),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewData,
        sizeof(KM_PROCESS_WATCHER_DATA));

    Status = Km_List_Initialize(&NewData->CallbacksList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    
    NewData->MemoryManager = MemoryManager;

    InterlockedExchangePointer(
        (PVOID *)&ProcessWatcherData,
        (PVOID)NewData);

cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewData))
        {
            Km_MM_FreeMem(
                MemoryManager,
                NewData);
        }
    }

    return Status;
};

NTSTATUS __stdcall Km_ProcessWatcher_Finalize()
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    PKM_PROCESS_WATCHER_DATA    Data = NULL;
    LIST_ENTRY                  TmpList;
    ULARGE_INTEGER              Count;

    Data = (PKM_PROCESS_WATCHER_DATA)InterlockedExchangePointer(
        (PVOID *)&ProcessWatcherData,
        NULL);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_UNSUCCESSFUL);

    InitializeListHead(&TmpList);

    Count.QuadPart = MAXULONGLONG;

    Km_List_Lock(&Data->CallbacksList);
    __try
    {
        Status = Km_List_ExtractEntriesEx(
            &Data->CallbacksList,
            &TmpList,
            &Count,
            FALSE,
            FALSE);
    }
    __finally
    {
        Km_List_Unlock(&Data->CallbacksList);
    }

    while (!IsListEmpty(&TmpList))
    {
        PLIST_ENTRY                         Entry = RemoveHeadList(&TmpList);
        PKM_PROCESS_WATCHER_CALLBACK_ITEM   Item = 
            CONTAINING_RECORD(Entry, KM_PROCESS_WATCHER_CALLBACK_ITEM, Link);

        Km_MM_FreeMem(
            Data->MemoryManager,
            Item);
    }

    Km_MM_FreeMem(
        Data->MemoryManager,
        Data);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_ProcessWatcher_RegisterCallback(
    __in    PKM_PROCESS_WATCHER_CALLBACK    Callback,
    __in    PVOID                           Context,
    __out   PHANDLE                         CallbackHandle)
{
    NTSTATUS                            Status = STATUS_SUCCESS;
    PKM_PROCESS_WATCHER_CALLBACK_ITEM   NewItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Callback),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(CallbackHandle),
        STATUS_INVALID_PARAMETER_3);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ProcessWatcherData),
        STATUS_UNSUCCESSFUL);

    Status = Km_List_Lock(&ProcessWatcherData->CallbacksList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        NewItem = Km_MM_AllocMemTyped(
            ProcessWatcherData->MemoryManager,
            KM_PROCESS_WATCHER_CALLBACK_ITEM);
        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(NewItem),
            STATUS_INSUFFICIENT_RESOURCES);

        RtlZeroMemory(
            NewItem,
            sizeof(KM_PROCESS_WATCHER_CALLBACK_ITEM));

        NewItem->Callback = Callback;
        NewItem->Context = Context;

        Status = Km_List_AddItemEx(
            &ProcessWatcherData->CallbacksList,
            &NewItem->Link,
            FALSE,
            FALSE);
        if (!NT_SUCCESS(Status))
        {
            Km_MM_FreeMem(
                ProcessWatcherData->MemoryManager,
                NewItem);
            __leave;
        }

        *CallbackHandle = (HANDLE)NewItem;
    }
    __finally
    {
        Km_List_Unlock(&ProcessWatcherData->CallbacksList);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_ProcessWatcher_UnregisterCallback(
    __in    HANDLE  CallbackHandle)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        CallbackHandle != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ProcessWatcherData),
        STATUS_UNSUCCESSFUL);

    Status = Km_List_Lock(&ProcessWatcherData->CallbacksList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PLIST_ENTRY Entry;

        for (Entry = ProcessWatcherData->CallbacksList.Head.Flink;
            Entry != &ProcessWatcherData->CallbacksList.Head;
            Entry = Entry->Flink)
        {
            PKM_PROCESS_WATCHER_CALLBACK_ITEM   Item =
                CONTAINING_RECORD(Entry, KM_PROCESS_WATCHER_CALLBACK_ITEM, Link);

            if ((HANDLE)Item == CallbackHandle)
            {
                Status = Km_List_RemoveItemEx(
                    &ProcessWatcherData->CallbacksList,
                    &Item->Link,
                    FALSE,
                    FALSE);
                LEAVE_IF_FALSE(NT_SUCCESS(Status));

                Km_MM_FreeMem(
                    ProcessWatcherData->MemoryManager,
                    Item);
            };

        };
    }
    __finally
    {
        Km_List_Unlock(&ProcessWatcherData->CallbacksList);
    }

cleanup:
    return Status;
};