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

#include "Packet.h"

#define PACKET_ALLOCATOR_TYPE_MEMORY_POOL       0x0
#define PACKET_ALLOCATOR_TYPE_MEMORY_MANAGER    0x1

#pragma warning(push)
#pragma warning(disable: 4201)

typedef struct _PACKET_CONTAINER
{
    struct Allocator
    {
        ULONG   Type;
        union
        {
            HANDLE              MemoryPool;
            PKM_MEMORY_MANAGER  MemoryManager;
        };
    } Allocator;

    LONG    ReferenceCount;

    PACKET  Packet;

} PACKET_CONTAINER, *PPACKET_CONTAINER;

#pragma warning(pop)

NTSTATUS __stdcall Packet_Reference(
    __in    PPACKET Packet)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PPACKET_CONTAINER   Container = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Packet),
        STATUS_INVALID_PARAMETER_1);

    Container = CONTAINING_RECORD(Packet, PACKET_CONTAINER, Packet);

    InterlockedIncrement(&Container->ReferenceCount);

cleanup:
    return Status;
};

NTSTATUS __stdcall Packet_Dereference(
    __in    PPACKET Packet)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PPACKET_CONTAINER   Container = NULL;
    LONG                RefCnt = 0;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Packet),
        STATUS_INVALID_PARAMETER_1);

    Container = CONTAINING_RECORD(Packet, PACKET_CONTAINER, Packet);

    RefCnt = InterlockedDecrement(&Container->ReferenceCount);
    if (RefCnt == 0)
    {
        Status = Packet_Release(Packet);
        if (!NT_SUCCESS(Status))
        {
            InterlockedIncrement(&Container->ReferenceCount);
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall Packet_Allocate(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    SIZE_T              PacketDataSize,
    __out   PPACKET             *Packet)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PPACKET_CONTAINER   NewContainer = NULL;
    SIZE_T              SizeRequired = sizeof(PACKET_CONTAINER) + PacketDataSize - 1;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Packet),
        STATUS_INVALID_PARAMETER_3);

    NewContainer = Km_MM_AllocMemTypedWithSize(
        MemoryManager,
        PACKET_CONTAINER,
        SizeRequired);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewContainer),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewContainer,
        SizeRequired);

    NewContainer->Allocator.MemoryManager = MemoryManager;
    NewContainer->Allocator.Type = PACKET_ALLOCATOR_TYPE_MEMORY_MANAGER;
    NewContainer->ReferenceCount = 1;
    
    *Packet = &NewContainer->Packet;

cleanup:
    return Status;
};

NTSTATUS __stdcall Packet_AllocateFromPool(
    __in    HANDLE  MemoryPool,
    __in    SIZE_T  PacketDataSize,
    __out   PPACKET *Packet)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PPACKET_CONTAINER   NewContainer = NULL;
    SIZE_T              SizeRequired = sizeof(PACKET_CONTAINER) + PacketDataSize - 1;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        MemoryPool != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Packet),
        STATUS_INVALID_PARAMETER_3);

    Status = Km_MP_AllocateCheckSize(
        MemoryPool,
        SizeRequired,
        (PVOID *)&NewContainer);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewContainer),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewContainer,
        SizeRequired);

    NewContainer->Allocator.MemoryPool = MemoryPool;
    NewContainer->Allocator.Type = PACKET_ALLOCATOR_TYPE_MEMORY_POOL;
    NewContainer->ReferenceCount = 1;

    *Packet = &NewContainer->Packet;

cleanup:
    return Status;
};

NTSTATUS __stdcall Packet_ReleaseEx(
    __in        PPACKET Packet,
    __in_opt    BOOLEAN Force)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PPACKET_CONTAINER   Container = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Packet),
        STATUS_INVALID_PARAMETER_1);

    Container = CONTAINING_RECORD(Packet, PACKET_CONTAINER, Packet);
    
    GOTO_CLEANUP_IF_TRUE_SET_STATUS(
        (Container->ReferenceCount > 0) &&
        (!Force),
        STATUS_UNSUCCESSFUL);

    switch (Container->Allocator.Type)
    {
    case PACKET_ALLOCATOR_TYPE_MEMORY_POOL:
        {
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                Container->Allocator.MemoryPool != NULL,
                STATUS_UNSUCCESSFUL);

            Status = Km_MP_Release(Container);
        }break;

    case PACKET_ALLOCATOR_TYPE_MEMORY_MANAGER:
        {
            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                Assigned(Container->Allocator.MemoryManager),
                STATUS_UNSUCCESSFUL);

            Status = Km_MM_FreeMem(
                Container->Allocator.MemoryManager,
                Container);
        }break;

        
    default:
        {
            Status = STATUS_UNSUCCESSFUL;
        }break;
    };

cleanup:
    return Status;
};

SIZE_T __stdcall Packet_CalcRequiredMemorySize(
    __in    SIZE_T  PacketDataSize)
{
    return sizeof(PACKET_CONTAINER) + PacketDataSize - 1;
};