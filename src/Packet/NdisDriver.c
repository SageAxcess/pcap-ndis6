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
// All rights reserved.
//////////////////////////////////////////////////////////////////////

#include <winsock2.h>
#include <windows.h>

#include "NdisDriver.h"
#include <stdio.h>

PCAP_NDIS* NdisDriverOpen()
{
	HANDLE hFile = CreateFileA(NTDEVICE_FILE_STRING, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE)
	{
		return NULL; //TODO: install?
	}

	PCAP_NDIS* ndis = (PCAP_NDIS*)malloc(sizeof(PCAP_NDIS));
	ndis->handle = hFile;
	return ndis;
}

void NdisDriverClose(PCAP_NDIS* ndis)
{
	if(!ndis)
	{
		return;
	}
	if(ndis->handle)
	{
		CloseHandle(ndis->handle);
	}
	free(ndis);
}

PCAP_NDIS_ADAPTER* NdisDriverOpenAdapter(PCAP_NDIS* ndis, const char* szAdapterId)
{
	if(!ndis)
	{
		return NULL;
	}

	char szFileName[1024];
	sprintf_s(szFileName, 1024, "\\\\.\\" ADAPTER_ID_PREFIX "%s", szAdapterId);

	HANDLE hFile = CreateFileA(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL; //TODO: install?
	}

	PCAP_NDIS_ADAPTER* adapter = (PCAP_NDIS_ADAPTER*)malloc(sizeof(struct PCAP_NDIS_ADAPTER));
	adapter->handle = hFile;	

	return adapter;
}

void NdisDriverCloseAdapter(PCAP_NDIS_ADAPTER* adapter)
{
	if(!adapter)
	{
		return;
	}
	if(adapter->handle)
	{
		CloseHandle(adapter->handle);
	}
	free(adapter);
}

BOOL NdisDriverNextPacket(PCAP_NDIS_ADAPTER* adapter, void** buf, size_t size, ULONGLONG* time)
{
	
	return FALSE;
}

// Get adapter list
PCAP_NDIS_ADAPTER_LIST* NdisDriverGetAdapterList(PCAP_NDIS* ndis)
{
	if (!ndis) {
		return NULL;
	}

	PCAP_NDIS_ADAPTER_LIST* list = (PCAP_NDIS_ADAPTER_LIST*)malloc(sizeof(PCAP_NDIS_ADAPTER_LIST));
	list->count = 0;
	list->adapters = NULL;

	DWORD dwBytesRead = 0;
	PCAP_NDIS_ADAPTER_LIST_HDR hdr;

	if(ReadFile(ndis->handle, &hdr, sizeof(PCAP_NDIS_ADAPTER_LIST_HDR), &dwBytesRead, NULL))
	{
		if(!memcmp(hdr.signature, SIGNATURE, 8))
		{
			NdisDriverFreeAdapterList(list);
			return NULL;
		}

		list->count = hdr.count > MAX_ADAPTERS ? MAX_ADAPTERS : hdr.count;
		
		list->adapters = (PCAP_NDIS_ADAPTER_INFO*)malloc(sizeof(PCAP_NDIS_ADAPTER_INFO) * list->count);

		for (int i = 0; i < list->count && i < MAX_ADAPTERS;i++)
		{
			if (!ReadFile(ndis->handle, &list->adapters[i], sizeof(PCAP_NDIS_ADAPTER_INFO), &dwBytesRead, NULL))
			{
				memset(list->adapters[i].AdapterId, 0, sizeof(list->adapters[i].AdapterId));
				memset(list->adapters[i].FriendlyName, 0, sizeof(list->adapters[i].FriendlyName));
				memset(list->adapters[i].MacAddress, 0, sizeof(list->adapters[i].MacAddress));
				list->adapters[i].MtuSize = 0;

				//TODO: this is a bug
			}
		}
	} else
	{
		NdisDriverFreeAdapterList(list);
		return NULL;
	}

	return list;
}

void NdisDriverFreeAdapterList(PCAP_NDIS_ADAPTER_LIST* list)
{
	if(!list)
	{
		return;
	}
	if(list->adapters)
	{
		free(list->adapters);
	}
	free(list);
}