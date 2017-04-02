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

#pragma once

#include "winpcap_ndis.h"

typedef struct PCAP_NDIS
{
	void* handle;
} PCAP_NDIS;

typedef struct PCAP_NDIS_ADAPTER_STAT {
	UINT Received;
	UINT Dropped;
	UINT Captured;
} PCAP_NDIS_ADAPTER_STAT;

typedef struct PCAP_NDIS_ADAPTER
{
	void* handle;
	UINT ReadTimeout;
	PCAP_NDIS_ADAPTER_STAT Stat;
} PCAP_NDIS_ADAPTER;

typedef struct PCAP_NDIS_ADAPTER_LIST
{
	int count;
	PCAP_NDIS_ADAPTER_INFO* adapters;
} PCAP_NDIS_ADAPTER_LIST;

// Open channel to ndis driver
PCAP_NDIS* NdisDriverOpen();
// Close channel to ndis driver
void NdisDriverClose(PCAP_NDIS* ndis);
// Open adapter for capture
PCAP_NDIS_ADAPTER* NdisDriverOpenAdapter(PCAP_NDIS* ndis, const char* szAdapterId);
// Close adapter
void NdisDriverCloseAdapter(PCAP_NDIS_ADAPTER* adapter);
// Extract packet from previously opened adapter
BOOL NdisDriverNextPacket(PCAP_NDIS_ADAPTER* adapter, void** buf, size_t size, DWORD* dwBytesReceived);
// Get adapter list
PCAP_NDIS_ADAPTER_LIST* NdisDriverGetAdapterList(PCAP_NDIS* ndis);
// Free adapter list
void NdisDriverFreeAdapterList(PCAP_NDIS_ADAPTER_LIST* list);