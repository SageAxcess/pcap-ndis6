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
#include "Adapter.h"
#include "Client.h"
#include "Device.h"
#include "Events.h"
#include "Packet.h"
#include "KernelUtil.h"

//////////////////////////////////////////////////////////////////////
// Client methods
//////////////////////////////////////////////////////////////////////

PCLIENT CreateClient(PDEVICE device, PFILE_OBJECT fileObject)
{
	CLIENT* client = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(CLIENT));
	NdisZeroMemory(client, sizeof(CLIENT));

	client->Device = device;
	client->FileObject = fileObject;
	client->Event = CreateEvent();
	client->ReadLock = CreateSpinLock();

	NET_BUFFER_LIST_POOL_PARAMETERS parameters;
	memset(&parameters, 0, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));

	parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	parameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	parameters.fAllocateNetBuffer = TRUE;
	parameters.ContextSize = 32 + sizeof(UINT32) * 12;
	parameters.DataSize = MAX_PACKET_SIZE;
	parameters.PoolTag = FILTER_TAG;

	client->NetBufferListPool = NdisAllocateNetBufferListPool(NULL, &parameters);

	AddToList(device->ClientList, client);

	return client;
}

BOOL FreeClient(PCLIENT client)
{
	if(!client)
	{
		return FALSE;
	}

	FreePacketList(client->PacketList);
	RemoveFromListByData(client->Device->ClientList, client);

	FreeEvent(client->Event);
	FreeSpinLock(client->ReadLock);
	NdisFreeNetBufferListPool(client->NetBufferListPool);

	FILTER_FREE_MEM(client);

	return TRUE;
}

void FreeClientList(PLIST list)
{
	NdisAcquireSpinLock(list->Lock);
	PLIST_ITEM item = list->First;
	while(item)
	{
		PCLIENT client = (PCLIENT)item->Data;
		if(client)
		{
			FreeClient(client);
		}
		item->Data = NULL;

		item = item->Next;
	}

	NdisReleaseSpinLock(list->Lock);

	//TODO: possible memory leak if something is added to the list before it's released
	FreeList(list);
}
