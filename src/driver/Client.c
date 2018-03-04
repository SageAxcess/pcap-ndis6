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

#include "Client.h"
#include "Device.h"
#include "Events.h"
#include "Packet.h"
#include "KernelUtil.h"
#include <flt_dbg.h>

#include "..\shared\CommonDefs.h"

//////////////////////////////////////////////////////////////////////
// Client methods
//////////////////////////////////////////////////////////////////////

NTSTATUS CreateClient(
    __in    PDEVICE         Device,
    __in    PFILE_OBJECT    FileObject,
    __out   PCLIENT         *Client)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PCLIENT     NewClient = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Device),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Device->DriverData),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(FileObject),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Client),
        STATUS_INVALID_PARAMETER_3);

    NewClient = Km_MM_AllocMemTyped(
        &Device->DriverData->Ndis.MemoryManager,
        CLIENT);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewClient),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(NewClient, sizeof(CLIENT));

    NewClient->Device = Device;
    NewClient->FileObject = FileObject;
    NewClient->MemoryManager = &Device->DriverData->Ndis.MemoryManager;

    Status = InitializeEvent(
        &Device->DriverData->Ndis.MemoryManager,
        &NewClient->Event);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_List_Initialize(&NewClient->PacketList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_Lock_Initialize(&NewClient->ReadLock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = Km_List_AddItem(
        &Device->ClientList,
        &NewClient->Link);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    
cleanup:

    if (!NT_SUCCESS(Status))
    {
        if (Assigned(NewClient))
        {
            FinalizeEvent(&NewClient->Event);

            Km_MM_FreeMem(
                &Device->DriverData->Ndis.MemoryManager,
                NewClient);
        }
    }
    else
    {
        *Client = NewClient;
    }

    return Status;
};

NTSTATUS FreeClient(
    __in    PCLIENT Client)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Client),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Client->MemoryManager),
        STATUS_INVALID_PARAMETER_1);

    Km_Lock_Acquire(&Client->ReadLock);
    __try
    {
        ClearPacketList(&Client->PacketList);
    }
    __finally
    {
        Km_Lock_Release(&Client->ReadLock);
    }

    FinalizeEvent(&Client->Event);

    Km_MM_FreeMem(
        Client->MemoryManager,
        Client);

cleanup:
    return Status;
};
int __stdcall Client_FindClientCallback(
    __in    PKM_LIST    List,
    __in    PVOID       ItemDefinition,
    __in    PLIST_ENTRY Item)
{
    PCLIENT Client1 = (PCLIENT)ItemDefinition;
    PCLIENT Client2 = CONTAINING_RECORD(Item, CLIENT, Link);

    UNREFERENCED_PARAMETER(List);

    return
        Client1 == Client2 ? 0 :
        Client1 > Client2 ? 1 :
        -1;
};

NTSTATUS RemoveClientFromList(
    __in    PKM_LIST    List,
    __in    PCLIENT     Client)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(List),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Client),
        STATUS_INVALID_PARAMETER_2);

    Status = Km_List_Lock(List);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PLIST_ENTRY FoundItem = NULL;

        Status = Km_List_FindItemEx(
            List,
            (PVOID)Client,
            Client_FindClientCallback,
            &FoundItem,
            FALSE,
            FALSE);
        if (NT_SUCCESS(Status))
        {
            Status = Km_List_RemoveItemEx(
                List,
                FoundItem,
                FALSE,
                FALSE);
        }
    }
    __finally
    {
        Km_List_Unlock(List);
    }

cleanup:
    return Status;
};

void __stdcall ClearClientsList_ItemCallback(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item)
{
    UNREFERENCED_PARAMETER(List);

    RETURN_IF_FALSE(Assigned(Item));

    FreeClient(CONTAINING_RECORD(Item, CLIENT, Link));
};

NTSTATUS ClearClientList(
    __in    PKM_LIST    List)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(List),
        STATUS_INVALID_PARAMETER_1);

    Km_List_Clear(
        List,
        ClearClientsList_ItemCallback);

cleanup:
    return Status;
};