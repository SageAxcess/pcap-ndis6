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

#define FILTER_FRIENDLY_NAME        L"WinPCAP NDIS 6.x Filter Driver"
#define FILTER_UNIQUE_NAME          L"{37195A99-7BC5-4C82-B00A-553C75C0AA1A}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"PcapNdis6"
#define FILTER_PROTOCOL_NAME		L"PcapNdis6"

//
// The filter needs to handle IOCTLs
//
#define LINKNAME_STRING             L"\\DosDevices\\PCAPNDIS6"
#define NTDEVICE_STRING             L"\\Device\\PCAPNDIS6"
#define NTDEVICE_FILE_STRING        "\\.\\PCAPNDIS6"

#define	ADAPTER_ID_PREFIX			"PCAPNDIS_A_"
#define	ADAPTER_ID_PREFIX_W			L"PCAPNDIS_A_"

// Adapter data

#define MAX_ADAPTERS 256

typedef struct PCAP_NDIS_ADAPTER_INFO
{
	wchar_t AdapterId[MAX_PATH];		// Adapter ID
	wchar_t DeviceName[MAX_PATH];		// device name
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding1[2];
	UINT MtuSize;						// MTU size
	char FriendlyName[MAX_PATH];		// Display name
} PCAP_NDIS_ADAPTER_INFO;

typedef struct PCAP_NDIS_ADAPTER_LIST_HDR
{
	char signature[8];
	UINT count;
} PCAP_NDIS_ADAPTER_LIST_HDR;

