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

typedef __declspec(align(2)) struct _ETH_ADDRESS
{
    unsigned char   Addr[ETH_ADDRESS_LENGTH];
} ETH_ADDRESS, *PETH_ADDRESS, *LPETH_ADDRESS;

typedef __declspec(align(2)) struct _ETH_HEADER
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

#pragma pack(push, 1)

#pragma warning (disable:4359)

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

#define NET_EVENT_INFO_PROCESS_PATH_MAX_SIZE    1024

typedef struct _NET_EVENT_INFO
{
    //  Eth type
    unsigned short  EthType;

    //  IP protocol (one of IPPROTO_XXX values)
    unsigned short  IpProtocol;

    struct NEI_IP_AND_TRANSPORT
    {
        //  Source or destination physical address
        ETH_ADDRESS     EthAddress;

        //  Source or destination ip address
        IP_ADDRESS      IpAddress;

        //  Transport-specific local/source remote/destination value.
        //  It can be a TCP/UDP port or an ICMP type/code or any other
        //  transport-specific value.
        unsigned short  TransportSpecific;

    } Remote, Local;

    struct NEI_PROCESS
    {
        //  Process id
        unsigned long long  Id;

        //  Process executable path size (in bytes)
        unsigned long       NameSize;

        //  Process executable path buffer
        wchar_t             NameBuffer[NET_EVENT_INFO_PROCESS_PATH_MAX_SIZE];

    } Process;

} NET_EVENT_INFO, *PNET_EVENT_INFO, *LPNET_EVENT_INFO;

#define EthTypeToAddressFamily(Value) \
    ((((Value) == ETH_TYPE_IP) || ((Value) == ETH_TYPE_IP_BE)) ? AF_INET : \
     (((Value) == ETH_TYPE_IP6) || ((Value) == ETH_TYPE_IP6_BE)) ? AF_INET6 : \
     AF_UNSPEC)

#pragma pack(pop)

#pragma warning(default:4359)

#define FILTER_COMPANY_PRODUCT_NAME                 L"ChangeDynamix AEGIS"
#define FILTER_COMPONENT_ID                         L"PcapNdis6"
#define FILTER_INSTALL_TIMEOUT                      60000


#define FILTER_UNIQUE_NAME                          L"{37195A99-7BC5-4C82-B00A-553C75C0AA1A}"
#define FILTER_SERVICE_NAME                         L"PcapNdis6"
#define FILTER_PROTOCOL_NAME		                L"PcapNdis6"

#define DEVICE_STR_W                                L"\\DEVICE\\"

#define FILTER_DEVICE_NAME_W                        L"PcapNdis6"

#define IOCTL_VENDOR_DEVICE_BASE 0x8000
#define IOCTL_VENDOR_FUNC_BASE 0x800

#define	IOCTL_GET_EVENT_NAME		CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 0, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_READ_PACKETS          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_ADAPTERS_COUNT    CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 2, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_ADAPTERS          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 3, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_OPEN_ADAPTER          CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 4, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CLOSE_ADAPTER         CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 5, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_DIAG_INFO         CTL_CODE(IOCTL_VENDOR_DEVICE_BASE, IOCTL_VENDOR_FUNC_BASE + 6, METHOD_NEITHER, FILE_ANY_ACCESS)

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
    //  The maximum length is PCAP_NDIS_ADAPTER_ID_SIZE_MAX
    //  One character is reserved for termination null character.
    wchar_t         Buffer[PCAP_NDIS_ADAPTER_ID_SIZE_MAX + 1];

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

typedef __declspec(align(8)) struct _MEMORY_ALLOCATION_STATS
{
    //  Number of allocations 
    unsigned long long  AllocationsCount;

    //  Number of bytes requested from a memory manager by user code
    unsigned long long  UserBytesAllocated;

    //  Total number of bytes allocated
    //  This is a sum of UserBytesAllocated and a number of bytes 
    //  allocated for servicing purposes
    unsigned long long  TotalBytesAllocated;

} MEMORY_ALLOCATION_STATS;

typedef MEMORY_ALLOCATION_STATS    *PMEMORY_ALLOCATION_STATS;

#define DRIVER_DIAG_INFORMATION_FLAG_NONE           0x0
#define DRIVER_DIAG_INFORMATION_FLAG_NDIS_MM_STATS  0x1
#define DRIVER_DIAG_INFORMATION_FLAG_WFP_MM_STATS   0x2

typedef __declspec(align(8)) struct _DRIVER_DIAG_INFORMATION
{
    unsigned long           Flags;

    MEMORY_ALLOCATION_STATS NdisMMStats;

    MEMORY_ALLOCATION_STATS WfpMMStats;

} DRIVER_DIAG_INFORMATION; //PDRIVER_DIAG_INFORMATION;

typedef DRIVER_DIAG_INFORMATION *PDRIVER_DIAG_INFORMATION;

#define ADAPTER_READ_BUFFER_SIZE    32000