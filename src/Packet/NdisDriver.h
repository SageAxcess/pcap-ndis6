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
#include <string>

#define READ_BUFFER_SIZE 32000

typedef struct PCAP_NDIS
{
    void* handle;
} PCAP_NDIS;

typedef struct PCAP_NDIS_ADAPTER_STAT
{
    UINT Received;
    UINT Dropped;
    UINT Captured;
} PCAP_NDIS_ADAPTER_STAT;

typedef struct PCAP_NDIS_ADAPTER
{
    void                    *Handle;
    UINT                    ReadTimeout;
    PCAP_NDIS_ADAPTER_STAT  Stat;

    UINT                    BufferOffset;
    UINT                    BufferedPackets;
    UCHAR                   ReadBuffer[READ_BUFFER_SIZE];
} PCAP_NDIS_ADAPTER, *PPCAP_NDIS_ADAPTER;

typedef struct PCAP_NDIS_ADAPTER_LIST
{
    int                     count;
    PCAP_NDIS_ADAPTER_INFO  *adapters;
} PCAP_NDIS_ADAPTER_LIST, *PPCAP_NDIS_ADAPTER_LIST, *LPPCAP_NDIS_ADAPTER_LIST;

// Open channel to ndis driver
PCAP_NDIS* NdisDriverOpen();

// Close channel to ndis driver
void NdisDriverClose(PCAP_NDIS* ndis);

// Open adapter for capture
PPCAP_NDIS_ADAPTER NdisDriverOpenAdapter(
    __in            PCAP_NDIS   *ndis,
    __in    const   char        *szAdapterId);

std::wstring NdisDriverGetAdapterEventName(
    __in            PCAP_NDIS           *Ndis,
    __in            PCAP_NDIS_ADAPTER   *Adapter);

// Close adapter
void NdisDriverCloseAdapter(PCAP_NDIS_ADAPTER* adapter);

// Extract packet from previously opened adapter
BOOL NdisDriverNextPacket(
    __in    PCAP_NDIS_ADAPTER   *adapter,
    __out   void                **buf,
    __in    size_t              size,
    __out   DWORD*              dwBytesReceived);

// Get adapter list
PCAP_NDIS_ADAPTER_LIST* NdisDriverGetAdapterList(PCAP_NDIS* ndis);

// Free adapter list
void NdisDriverFreeAdapterList(PCAP_NDIS_ADAPTER_LIST* list);