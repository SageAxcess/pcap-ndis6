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

#define FILTER_DISPLAY_NAME                         L"WinPCAP NDIS 6.x Filter Driver"
#define FILTER_UNIQUE_NAME                          L"{37195A99-7BC5-4C82-B00A-553C75C0AA1A}"
#define FILTER_SERVICE_NAME                         L"PcapNdis6"
#define FILTER_PROTOCOL_NAME		                L"PcapNdis6"

#define ADAPTER_ID_PREFIX_W                         L"PCAPNDIS6_A_"
#define ADAPTER_ID_PREFIX_LENGTH                    ARRAYSIZE(ADAPTER_ID_PREFIX_W)

#define ADAPTER_DEVICE_NAME_PREFIX_W                L"\\Device\\"ADAPTER_ID_PREFIX_W
#define ADAPTER_DEVICE_SYM_LINK_NAME_PREFIX_W       L"\\DosDevices\\Global\\"ADAPTER_ID_PREFIX_W

#define ADAPTER_NAME_FORLIST_W                      L"{00000000-0000-0000-0000-000000000000}"
#define	EVENT_NAME_FMT				                "EVT_PCAP_NDIS_%u_%llu"
#define DEVICE_STR_W                                L"\\DEVICE\\"

#define IOCTL_VENDOR_DEVICE_BASE 0x8000
#define IOCTL_VENDOR_FUNC_BASE 0x800

#define	IOCTL_GET_EVENT_NAME		CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 0, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_READ_PACKETS          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 1, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_ADAPTERS_COUNT    CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 2, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_ADAPTERS          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 3, METHOD_NEITHER, FILE_ANY_ACCESS)


// Adapter data

#define MAX_ADAPTERS            256
#define MAX_PACKET_SIZE         32767
#define MAX_PACKET_QUEUE_SIZE   1000

#define PCAP_NDIS_ADAPTER_ID_SIZE_MAX       1024
#define PCAP_NDIS_ADAPTER_MAC_ADDRESS_SIZE  0x6

typedef __declspec(align(4)) struct _PCAP_NDIS_ADAPTER_INFO
{
    //  Adapter id length in bytes
    unsigned long   AdapterIdLength;

    //  Adapter id buffer
    wchar_t         AdapterId[PCAP_NDIS_ADAPTER_ID_SIZE_MAX];

    //  Display name
    char            DisplayName[256];

    //  Adapter physical address (mac address)
    unsigned char   MacAddress[PCAP_NDIS_ADAPTER_MAC_ADDRESS_SIZE];

    //  MTU size
    unsigned int    MtuSize;

} PCAP_NDIS_ADAPTER_INFO, *PPCAP_NDIS_ADAPTER_INFO;

typedef __declspec(align(4)) struct _PCAP_NDIS_ADAPTER_INFO_LIST
{
    //  Number of items in the list
    unsigned int            NumberOfAdapters;

    //  Array of PCAP_NDIS_ADAPTER_INFO structures.
    PCAP_NDIS_ADAPTER_INFO  Items[1];

} PCAP_NDIS_ADAPTER_INFO_LIST, *PPCAP_NDIS_ADAPTER_INFO_LIST;