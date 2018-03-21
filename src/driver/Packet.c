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

#include "filter.h"
#include "Packet.h"
#include "KmMemoryPool.h"
#include "..\shared\CommonDefs.h"

//////////////////////////////////////////////////////////////////////
// Packet methods
//////////////////////////////////////////////////////////////////////

PPACKET CreatePacket(
    __in    HANDLE      MemoryPool,
    __in    PVOID       Data,
    __in    ULONG       DataSize,
    __in    ULONGLONG   ProcessId,
    __in    PKM_TIME    Timestamp)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PPACKET     NewPacket = NULL;
    ULONG       SizeRequired = (ULONG)sizeof(PACKET) + DataSize - 1;

    RETURN_VALUE_IF_FALSE(
        (Assigned(MemoryPool)) &&
        (Assigned(Data)) &&
        (DataSize > 0) &&
        (Assigned(Timestamp)),
        NULL);

    Status = Km_MP_AllocateCheckSize(
        MemoryPool,
        SizeRequired,
        (PVOID *)&NewPacket);
    RETURN_VALUE_IF_FALSE(
        NT_SUCCESS(Status),
        NULL);

    RtlZeroMemory(NewPacket, SizeRequired);

    NewPacket->DataSize = DataSize;
    RtlCopyMemory(
        &NewPacket->Timestamp,
        Timestamp,
        sizeof(KM_TIME));
    RtlCopyMemory(
        &NewPacket->Data,
        Data,
        DataSize);

    NewPacket->ProcessId = ProcessId;

    return NewPacket;
};