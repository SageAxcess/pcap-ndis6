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

#pragma once

#include <minwindef.h>
#include <wchar.h>

#define SIGNATURE "PCAPNDIS"

#define FILTER_DISPLAY_NAME         L"WinPCAP NDIS 6.x Filter Driver"
#define FILTER_UNIQUE_NAME          L"{37195A99-7BC5-4C82-B00A-553C75C0AA1A}"
#define FILTER_SERVICE_NAME         L"PcapNdis6"
#define FILTER_PROTOCOL_NAME		L"PcapNdis6"

#define	ADAPTER_ID_PREFIX			"PCAPNDIS6_A_"
#define ADAPTER_NAME_FORLIST		"{00000000-0000-0000-0000-000000000000}"
#define	EVENT_NAME_FMT				"EVT_PCAP_NDIS_%u_%llu"

#define IOCTL_VENDOR_DEVICE_BASE 0x8000
#define IOCTL_VENDOR_FUNC_BASE 0x800

#define	IOCTL_GET_EVENT_NAME		CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE, METHOD_NEITHER, FILE_ANY_ACCESS)

// Adapter data

#define MAX_ADAPTERS 256
#define MAX_PACKET_SIZE 32767
#define MAX_PACKET_QUEUE_SIZE 1000

typedef struct PCAP_NDIS_ADAPTER_INFO
{
	wchar_t AdapterId[MAX_PATH];		// Adapter ID
	wchar_t DeviceName[MAX_PATH];		// device name
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding1[2];
	UINT MtuSize;						// MTU size
	char DisplayName[MAX_PATH];		// Display name
} PCAP_NDIS_ADAPTER_INFO;

typedef struct PCAP_NDIS_ADAPTER_LIST_HDR
{
	char Signature[8];
	UINT Count;
} PCAP_NDIS_ADAPTER_LIST_HDR;

typedef struct PACKET_HDR
{
	UINT Size;
	LARGE_INTEGER Timestamp;
} PACKET_HDR;
typedef struct PACKET_HDR* PPACKET_HDR;