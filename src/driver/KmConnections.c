#include "KmConnections.h"
#include "KmTypes.h"

typedef struct _KM_CONNECTIONS_ITEM
{
    LIST_ENTRY          Link;

    NETWORK_EVENT_INFO  Info;

} KM_CONNECTIONS_ITEM, *PKM_CONNECTIONS_ITEM;

typedef struct _KM_CONNECTIONS_DATA
{
    KM_LIST             List;

    PKM_MEMORY_MANAGER  MemoryManager;

} KM_CONNECTIONS_DATA, *PKM_CONNECTIONS_DATA;

int __stdcall Km_Connections_GetPID_ItemCmpCallback(
    __in    PKM_LIST    List,
    __in    PVOID       ItemDefinition,
    __in    PLIST_ENTRY Item)
{
    PKM_CONNECTIONS_ITEM    ConnItem = CONTAINING_RECORD(Item, KM_CONNECTIONS_ITEM, Link);
    PNETWORK_EVENT_INFO     EventInfo = (PNETWORK_EVENT_INFO)ItemDefinition;

    UNREFERENCED_PARAMETER(List);

    if ((Assigned(ConnItem)) &&
        (Assigned(EventInfo)))
    {
        int CmpRes = COMPARE_VALUES(EventInfo->AddressFamily, ConnItem->Info.AddressFamily);
        if (CmpRes == 0)
        {
            CmpRes = COMPARE_VALUES(EventInfo->IpProtocol, ConnItem->Info.IpProtocol);
            if (CmpRes == 0)
            {
                //  1st pass

                #pragma region STD_COMPARE
                CmpRes = COMPARE_VALUES(EventInfo->Local.Port, ConnItem->Info.Local.Port);
                if (CmpRes == 0)
                {
                    CmpRes = COMPARE_VALUES(EventInfo->Remote.Port, ConnItem->Info.Remote.Port);
                    if (CmpRes == 0)
                    {
                        size_t  CmpSize =
                            EventInfo->AddressFamily == 2 ?
                            sizeof(IP_ADDRESS_V4) :
                            sizeof(IP_ADDRESS_V6);

                        CmpRes = memcmp(
                            &EventInfo->Local.Address,
                            &ConnItem->Info.Local.Address,
                            CmpSize);

                        if (CmpRes == 0)
                        {
                            CmpRes = memcmp(
                                &EventInfo->Remote.Address,
                                &ConnItem->Info.Remote.Address,
                                CmpSize);
                        }
                    }
                }
                #pragma endregion

                #pragma region REVERESE_COMPARE
                if (CmpRes != 0)
                {
                    CmpRes = COMPARE_VALUES(EventInfo->Remote.Port, ConnItem->Info.Local.Port);
                    if (CmpRes == 0)
                    {
                        CmpRes = COMPARE_VALUES(EventInfo->Local.Port, ConnItem->Info.Remote.Port);
                        if (CmpRes == 0)
                        {
                            size_t  CmpSize =
                                EventInfo->AddressFamily == 2 ?
                                sizeof(IP_ADDRESS_V4) :
                                sizeof(IP_ADDRESS_V6);

                            CmpRes = memcmp(
                                &EventInfo->Remote.Address,
                                &ConnItem->Info.Local.Address,
                                CmpSize);

                            if (CmpRes == 0)
                            {
                                CmpRes = memcmp(
                                    &EventInfo->Local.Address,
                                    &ConnItem->Info.Remote.Address,
                                    CmpSize);
                            }
                        }
                    }
                }
                #pragma endregion
            }
        }

        return CmpRes;
    }

    return COMPARE_VALUES(ItemDefinition, (PVOID)Item);
};

int __stdcall Km_Connections_ItemCmpCallback(
    __in    PKM_LIST    List,
    __in    PVOID       ItemDefinition,
    __in    PLIST_ENTRY Item)
{
    PKM_CONNECTIONS_ITEM    ConnItem = CONTAINING_RECORD(Item, KM_CONNECTIONS_ITEM, Link);
    PNETWORK_EVENT_INFO     EventInfo = (PNETWORK_EVENT_INFO)ItemDefinition;

    UNREFERENCED_PARAMETER(List);

    if ((Assigned(ConnItem)) &&
        (Assigned(EventInfo)))
    {
        int CmpRes = COMPARE_VALUES(EventInfo->AddressFamily, ConnItem->Info.AddressFamily);
        if (CmpRes == 0)
        {
            CmpRes = COMPARE_VALUES(EventInfo->IpProtocol, ConnItem->Info.IpProtocol);
            if (CmpRes == 0)
            {
                CmpRes = COMPARE_VALUES(EventInfo->Local.Port, ConnItem->Info.Local.Port);
                if (CmpRes == 0)
                {
                    CmpRes = COMPARE_VALUES(EventInfo->Remote.Port, ConnItem->Info.Remote.Port);
                    if (CmpRes == 0)
                    {
                        size_t  CmpSize =
                            EventInfo->AddressFamily == 2 ?
                            sizeof(IP_ADDRESS_V4) :
                            sizeof(IP_ADDRESS_V6);

                        CmpRes = memcmp(
                            &EventInfo->Local.Address,
                            &ConnItem->Info.Local.Address,
                            CmpSize);
                        if (CmpRes == 0)
                        {
                            return memcmp(
                                &EventInfo->Remote.Address,
                                &ConnItem->Info.Remote.Address,
                                CmpSize);
                        }
                    }
                }
            }
        }

        return CmpRes;
    }

    return COMPARE_VALUES(ItemDefinition, (PVOID)Item);
};

NTSTATUS __stdcall Km_Connections_AllocateItem(
    __in    PKM_MEMORY_MANAGER      MemoryManager,
    __in    PNETWORK_EVENT_INFO     Info,
    __out   PKM_CONNECTIONS_ITEM    *Item)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_ITEM    NewItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Item),
        STATUS_INVALID_PARAMETER_3);

    NewItem = Km_MM_AllocMemTyped(
        MemoryManager,
        KM_CONNECTIONS_ITEM);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewItem),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewItem,
        sizeof(KM_CONNECTIONS_ITEM));

    RtlCopyMemory(
        &NewItem->Info,
        Info,
        sizeof(NETWORK_EVENT_INFO));

    *Item = NewItem;

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PHANDLE             Instance)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA    NewData = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Instance),
        STATUS_INVALID_PARAMETER_2);

    NewData = Km_MM_AllocMemTyped(
        MemoryManager,
        KM_CONNECTIONS_DATA);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewData),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewData,
        sizeof(KM_CONNECTIONS_DATA));

    Status = Km_List_Initialize(&NewData->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    NewData->MemoryManager = MemoryManager;

    *Instance = (HANDLE)NewData;

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

NTSTATUS __stdcall Km_Connections_Finalize(
    __in    HANDLE  Instance)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    ULARGE_INTEGER          Count;
    PKM_CONNECTIONS_DATA    Data = NULL;
    LIST_ENTRY              TmpList;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    InitializeListHead(&TmpList);

    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Count.QuadPart = MAXULONGLONG;
        Km_List_ExtractEntriesEx(
            &Data->List,
            &TmpList,
            &Count,
            FALSE,
            FALSE);
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

    while (!IsListEmpty(&TmpList))
    {
        PKM_CONNECTIONS_ITEM Item = CONTAINING_RECORD(
            RemoveHeadList(&TmpList),
            KM_CONNECTIONS_ITEM,
            Link);

        Km_MM_FreeMem(Data->MemoryManager, Item);
    }

    Km_MM_FreeMem(Data->MemoryManager, Data);

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_Add(
    __in    HANDLE              Instance,
    __in    PNETWORK_EVENT_INFO Info)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA    Data = NULL;
    PKM_CONNECTIONS_ITEM    NewItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_FindItemEx(
            &Data->List,
            (PVOID)Info,
            Km_Connections_ItemCmpCallback,
            NULL,
            FALSE,
            FALSE);
        if (Status == STATUS_NOT_FOUND)
        {
            Status = Km_Connections_AllocateItem(
                Data->MemoryManager,
                Info,
                &NewItem);
            LEAVE_IF_FALSE(NT_SUCCESS(Status));

            Status = Km_List_AddItemEx(
                &Data->List,
                &NewItem->Link,
                FALSE,
                FALSE);
            if (!NT_SUCCESS(Status))
            {
                Km_MM_FreeMem(
                    Data->MemoryManager,
                    NewItem);
            }
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_Remove(
    __in    HANDLE              Instance,
    __in    PNETWORK_EVENT_INFO Info)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA    Data = NULL;
    PLIST_ENTRY             FoundItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);

    Data = (PKM_CONNECTIONS_DATA)Instance;
    
    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_FindItemEx(
            &Data->List,
            (PVOID)Info,
            Km_Connections_ItemCmpCallback,
            &FoundItem,
            FALSE,
            FALSE);

        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Status = Km_List_RemoveItemEx(
            &Data->List,
            FoundItem,
            FALSE,
            FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        Km_MM_FreeMem(
            Data->MemoryManager,
            CONTAINING_RECORD(FoundItem, KM_CONNECTIONS_ITEM, Link));
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Km_Connections_GetPIDForPacket(
    __in    HANDLE              Instance,
    __in    PNETWORK_EVENT_INFO Info,
    __out   PULONGLONG          ProcessId)
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PKM_CONNECTIONS_DATA    Data = NULL;
    PLIST_ENTRY             FoundItem = NULL;
    PKM_CONNECTIONS_ITEM    ConnItem = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Instance != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(ProcessId),
        STATUS_INVALID_PARAMETER_3);

    Data = (PKM_CONNECTIONS_DATA)Instance;

    Status = Km_List_Lock(&Data->List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_List_FindItemEx(
            &Data->List,
            Info,
            Km_Connections_GetPID_ItemCmpCallback,
            &FoundItem,
            FALSE,
            FALSE);
        if (NT_SUCCESS(Status))
        {
            ConnItem = CONTAINING_RECORD(FoundItem, KM_CONNECTIONS_ITEM, Link);
            *ProcessId = ConnItem->Info.Process.Id;
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->List);
    }

cleanup:
    return Status;
};