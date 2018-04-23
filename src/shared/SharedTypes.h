//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 ChangeDynamix, LLC
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#pragma once

#ifndef ETH_MAXIMUM_FRAME_SIZE
#define ETH_MAXIMUM_FRAME_SIZE  1522
#endif

#ifndef ETH_ADDRESS_LENGTH
#define ETH_ADDRESS_LENGTH  0x6
#endif

typedef struct _ETH_ADDRESS
{
    unsigned char   Addr[ETH_ADDRESS_LENGTH];
} ETH_ADDRESS, *PETH_ADDRESS, *LPETH_ADDRESS;

typedef struct _ETH_HEADER
{
    ETH_ADDRESS     DstAddr;
    ETH_ADDRESS     SrcAddr;
    unsigned short  EthType;
} ETH_HEADER, *PETH_HEADER;

#define ETH_TYPE_IP             0x0800  //  IPv4
#define ETH_TYPE_REVERSE_ARP    0x8035  //  Reverse ARP
#define ETH_TYPE_ARP            0x0806  //  ARP
#define ETH_TYPE_IP6            0x86dd  //  IPv6

#define ETH_TYPE_IP_BE          0x0008  //  IPv4, big endian
#define ETH_TYPE_REVERSE_ARP_BE 0x3580  //  Reverse ARP, big endian
#define ETH_TYPE_ARP_BE         0x0608  //  ARP, big endian
#define ETH_TYPE_IP6_BE         0xdd86  //  IPv6, big endian

typedef struct _IP_ADDRESS_V4
{
    union
    {
        unsigned char   b[4];
        unsigned short  s[2];
        unsigned long   l;
    } ip;
} IP_ADDRESS_V4, *PIP_ADDRESS_V4;

typedef struct _IP_ADDRESS_V6
{
    union
    {
        unsigned char       b[16];
        unsigned short      s[8];
        unsigned long       l[4];
        unsigned long long  q[2];
    } ip;
} IP_ADDRESS_V6, *PIP_ADDRESS_V6;

typedef struct _IP_ADDRESS
{
    union
    {
        IP_ADDRESS_V4   v4;
        IP_ADDRESS_V6   v6;
    } Address;
} IP_ADDRESS, *PIP_ADDRESS;

typedef struct _IP6_HEADER
{
    unsigned long   VPF;

    //  Size of the data following the header
    unsigned short  PayloadLength;

    //  Transport protocol
    unsigned char   NextHeader;

    //  Number of hops
    unsigned char   HopLimit;

    //  Source address
    IP_ADDRESS_V6   SourceAddress;

    //  Destination address
    IP_ADDRESS_V6   DestinationAddress;

} IP6_HEADER, *PIP6_HEADER;

typedef struct _IP4_HEADER
{
    unsigned char   VerLen;

    unsigned char   Service;

    unsigned short  Length;

    unsigned short  Ident;

    unsigned short  FlagOff;

    unsigned char   TimeLive;

    unsigned char   Protocol;

    unsigned short  Checksum;

    IP_ADDRESS_V4   SourceAddress;

    IP_ADDRESS_V4   DestinationAddress;

} IP4_HEADER, *PIP4_HEADER;

typedef struct _TCP_HEADER
{
    unsigned short  SourcePort;

    unsigned short  DestinationPort;

    unsigned long   SequenceNumber;

    unsigned long   AckNumber;

    union
    {
        struct Data1
        {
            unsigned short  LenResvFlags;

            unsigned short  WindowSize;

            unsigned short  Checksum;

            unsigned short  UrgentPtr;

            unsigned char   Data[1];

        } Data1;

        struct Data2
        {
            unsigned char   LenRes;

            unsigned char   ResFlags;

        } Data2;

    } Data;

} TCP_HEADER, *PTCP_HEADER;

typedef struct _UDP_HEADER
{
    unsigned short  SourcePort;
    unsigned short  DestinationPort;
    unsigned short  Length;
    unsigned short  Checksum;
} UDP_HEADER, *PUDP_HEADER;

typedef struct _ICMP_HEADER
{
    unsigned char   IcmpType;
    unsigned char   Code;
    unsigned short  Checksum;
    unsigned short  Ident;
    unsigned short  SeqNum;
} ICMP_HEADER, *PICMP_HEADER;

typedef struct _PACKET_DESC
{
    //  Owner process ID or zero
    unsigned long   ProcessId;

    ETH_ADDRESS     SourceEthAddress;

    ETH_ADDRESS     DestinationEthAddress;

    unsigned short  EthType;

    IP_ADDRESS      SourceIPAddress;

    IP_ADDRESS      DestinationIPAddress;

    unsigned char   IPProtocol;

    union SourcePortOrIcmpType
    {
        unsigned short  SourcePort;
        unsigned short  IcmpType;
    } SourcePortOrIcmpType;

    union DestinationPortOrIcmpCode
    {
        unsigned short DestinationPort;
        unsigned short IcmpCode;
    } DestinationPortOrIcmpCode;

} PACKET_DESC, *PPACKET_DESC, *LPPACKET_DESC;

#define FILTER_DISPLAY_NAME                         L"WinPCAP NDIS 6.x Filter Driver"
#define FILTER_UNIQUE_NAME                          L"{37195A99-7BC5-4C82-B00A-553C75C0AA1A}"
#define FILTER_SERVICE_NAME                         L"PcapNdis6"
#define FILTER_PROTOCOL_NAME		                L"PcapNdis6"

#define DEVICE_STR_W                                L"\\DEVICE\\"

#define FILTER_DEVICE_NAME_W                        L"PcapNdis6"

#define IOCTL_VENDOR_DEVICE_BASE 0x8000
#define IOCTL_VENDOR_FUNC_BASE 0x800

#define	IOCTL_GET_EVENT_NAME		CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 0, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_READ_PACKETS          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 1, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_ADAPTERS_COUNT    CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 2, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_ADAPTERS          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 3, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_OPEN_ADAPTER          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 4, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CLOSE_ADAPTER         CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 5, METHOD_NEITHER, FILE_ANY_ACCESS)

// Adapter data

#define MAX_ADAPTERS                    256
#define MAX_PACKET_SIZE                 32767
#define MAX_PACKET_QUEUE_SIZE           1000

#define PCAP_NDIS_ADAPTER_ID_SIZE_MAX   1024

typedef __declspec(align(4)) struct _PCAP_NDIS_ADAPTER_ID
{
    //  Adapter id length in bytes
    unsigned long   Length;

    //  Adapter id buffer
    wchar_t         Buffer[PCAP_NDIS_ADAPTER_ID_SIZE_MAX];

} PCAP_NDIS_ADAPTER_ID, *PPCAP_NDIS_ADAPTER_ID;

typedef __declspec(align(8)) struct _PCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA
{
    unsigned long long      EventHandle;
    PCAP_NDIS_ADAPTER_ID    AdapterId;
} PCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA;

typedef PCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA *PPCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA;

#define PCAP_NDIS_ADAPTER_MAC_ADDRESS_SIZE  0x6

typedef __declspec(align(4)) struct _PCAP_NDIS_ADAPTER_INFO
{
    //  Adapter id
    PCAP_NDIS_ADAPTER_ID    AdapterId;

    //  Display name length in bytes
    unsigned long   DisplayNameLength;

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

typedef __declspec(align(8)) struct _PCAP_NDIS_CLIENT_ID
{
    unsigned long long  Index;
    unsigned long long  Handle;
} PCAP_NDIS_CLIENT_ID;

typedef PCAP_NDIS_CLIENT_ID *PPCAP_NDIS_CLIENT_ID;