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
#include "..\shared\CommonDefs.h"

//////////////////////////////////////////////////////////////////////
// Packet methods
//////////////////////////////////////////////////////////////////////

PACKET* CreatePacket(
    __in    PVOID           Data,
    __in    ULONG           DataSize,
    __in    PLARGE_INTEGER  Timestamp)
{
    PPACKET NewPacket = NULL;
    ULONG   SizeRequired = (ULONG)sizeof(PACKET) + DataSize - 1;

    RETURN_VALUE_IF_FALSE(
        (Assigned(Data)) &&
        (DataSize > 0) &&
        (Assigned(Timestamp)),
        NULL);

    NewPacket = FILTER_ALLOC_MEM_TYPED_WITH_SIZE(PACKET, FilterDriverHandle, SizeRequired);
    RETURN_VALUE_IF_FALSE(
        Assigned(NewPacket),
        NULL);

    RtlZeroMemory(NewPacket, SizeRequired);

    NewPacket->DataSize = DataSize;
    RtlCopyMemory(
        &NewPacket->Timestamp, 
        Timestamp, 
        sizeof(LARGE_INTEGER));
    RtlCopyMemory(
        &NewPacket->Data,
        Data,
        DataSize);

    return NewPacket;
};

void FreePacket(
    __in    PPACKET Packet)
{
    RETURN_IF_FALSE(Assigned(Packet));

    FILTER_FREE_MEM(Packet);
}

void FreePacketList(PLIST list)
{
	if(!list)
	{
		return;
	}

	NdisAcquireSpinLock(list->Lock);
	list->Releasing = TRUE;

	PLIST_ITEM item = list->First;
	while (item)
	{
		PPACKET packet = (PPACKET)item->Data;
		if (packet)
		{
			FreePacket(packet);
		}
		item->Data = NULL;

		item = item->Next;
	}

	NdisReleaseSpinLock(list->Lock);

	FreeList(list);
}