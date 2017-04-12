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

//////////////////////////////////////////////////////////////////////
// Packet methods
//////////////////////////////////////////////////////////////////////

PACKET* CreatePacket(UCHAR* Data, UINT Size, LARGE_INTEGER Timestamp)
{
	PACKET* packet = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(PACKET));
	if(!packet)
	{
		return NULL;
	}

	packet->Data = FILTER_ALLOC_MEM(FilterDriverObject, Size);
	RtlCopyBytes(packet->Data, Data, Size); 	//TODO: support for IEEE802.1Q?
	packet->Size = Size;
	packet->Timestamp = Timestamp;

	return packet;
}

void FreePacket(PACKET* packet)
{
	if(!packet)
	{
		return;
	}
	if (packet->Data) {
		FILTER_FREE_MEM(packet->Data);
	}
	FILTER_FREE_MEM(packet);
}

void FreePacketList(PLIST list)
{
	if(!list)
	{
		return;
	}

	NdisAcquireSpinLock(list->Lock);
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

	//TODO: possible memory leak if something is added to the list before it's released
	FreeList(list);
}