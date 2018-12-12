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

#include "..\shared\SharedTypes.h"
#include <string>

#define PCAP_NDIS_ADAPTER_READ_TIMEOUT_MIN  5000

typedef struct _PCAP_NDIS
{
    HANDLE  Handle;
} PCAP_NDIS, *PPCAP_NDIS, *LPPCAP_NDIS;

typedef struct PCAP_NDIS_ADAPTER_STAT
{
    UINT Received;
    UINT Dropped;
    UINT Captured;
} PCAP_NDIS_ADAPTER_STAT;

typedef struct _PCAP_NDIS_ADAPTER
{
    //  Driver client id
    PCAP_NDIS_ADAPTER_ID    ClientId;

    //  Ndis object
    PPCAP_NDIS              Ndis;

    HANDLE                  NewPacketEvent;

    UINT                    ReadTimeout;

    PCAP_NDIS_ADAPTER_STAT  Stat;

    UINT                    BufferOffset;
    UINT                    BufferedPackets;
    UCHAR                   ReadBuffer[ADAPTER_READ_BUFFER_SIZE];
} PCAP_NDIS_ADAPTER, *PPCAP_NDIS_ADAPTER, *LPPCAP_NDIS_ADAPTER;

typedef struct _PCAP_NDIS_ADAPTER_LIST
{
    ULONG                   Count;
    PCAP_NDIS_ADAPTER_INFO  Items[1];
} PCAP_NDIS_ADAPTER_LIST, *PPCAP_NDIS_ADAPTER_LIST, *LPPCAP_NDIS_ADAPTER_LIST;

#define PCAP_ADAPTER_DISPLAY_NAME_LENGTH_MAX    0x200

typedef struct _PCAP_ADAPTER_INFO
{
    //  Length of the adapter display name in chars
    ULONG                   DisplayNameLength;

    //  Display name
    //  The last item in the array is reserved for termination null character.
    wchar_t                 DisplayName[PCAP_ADAPTER_DISPLAY_NAME_LENGTH_MAX + 1];

    //  Data received from kernel
    PCAP_NDIS_ADAPTER_INFO  NdisAdapterInfo;

} PCAP_ADAPTER_INFO, *PPCAP_ADAPTER_INFO, *LPPCAP_ADAPTER_INFO;

typedef struct _PCAP_ADAPTER_LIST
{
    ULONG               Count;
    PCAP_ADAPTER_INFO   Items[1];
} PCAP_ADAPTER_LIST, *PPCAP_ADAPTER_LIST, *LPPCAP_ADAPTER_LIST;

// Open channel to ndis driver
LPPCAP_NDIS NdisDriverOpen();

// Close channel to ndis driver
void NdisDriverClose(
    __in    LPPCAP_NDIS Ndis);

// Open adapter for capture
PPCAP_NDIS_ADAPTER NdisDriverOpenAdapter(
    __in    PPCAP_NDIS              Ndis,
    __in    PPCAP_NDIS_ADAPTER_ID   AdapterId);

std::wstring NdisDriverGetAdapterEventName(
    __in            PCAP_NDIS           *Ndis,
    __in            PCAP_NDIS_ADAPTER   *Adapter);

// Close adapter
void NdisDriverCloseAdapter(
    __in    LPPCAP_NDIS_ADAPTER Adapter);

// Extract packet from previously opened adapter
BOOL NdisDriverNextPacket(
    __in        LPPCAP_NDIS_ADAPTER Adapter,
    __out       LPVOID              *Buffer,
    __in        size_t              Size,
    __out       PDWORD              BytesReceived,
    __out_opt   PULONGLONG          ProcessId);

BOOL NdisDriverQueryDiagInfo(
    __in    PPCAP_NDIS  Ndis,
    __out   PULONGLONG  AllocationsCount,
    __out   PULONGLONG  AllocationSize);

// Get adapter list
LPPCAP_ADAPTER_LIST NdisDriverGetAdapterList(
    __in    PPCAP_NDIS  Ndis);

// Free adapter list
void NdisDriverFreeAdapterList(
    __in    LPPCAP_ADAPTER_LIST List);

void NdisDriverLogPacket(
    __in    LPPACKET    Packet);

void NdisDriverLogPacketEx(
    __in    LPPACKET_EX Packet);