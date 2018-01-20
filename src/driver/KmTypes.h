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
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef KM_TYPES_H
#define KM_TYPES_H

#include <ndis.h>
#include "KmLock.h"
#include "KmList.h"
#include "NdisMemoryManager.h"

typedef struct _ADAPTER     ADAPTER, *PADAPTER;
typedef struct _DEVICE      DEVICE, *PDEVICE;
typedef struct _DRIVER_DATA DRIVER_DATA, *PDRIVER_DATA;

typedef struct _DEVICE
{
    PDRIVER_DATA    DriverData;

    PUNICODE_STRING Name;

    PUNICODE_STRING SymlinkName;

    PDEVICE_OBJECT  Device;

    PADAPTER        Adapter;

    KM_LOCK         OpenCloseLock;

    KM_LIST         ClientList;

    ULONG           Releasing;

    ULONG           IsAdaptersList;

} DEVICE, *PDEVICE;

#define ETH_TYPE_IP             0x0800  //  IPv4
#define ETH_TYPE_REVERSE_ARP    0x8035  //  Reverse ARP
#define ETH_TYPE_ARP            0x0806  //  ARP
#define ETH_TYPE_IP6            0x86dd  //  IPv6

#define ETH_TYPE_IP_BE          0x0008  //  IPv4, big endian
#define ETH_TYPE_REVERSE_ARP_BE 0x3580  //  Reverse ARP, big endian
#define ETH_TYPE_ARP_BE         0x0608  //  ARP, big endian
#define ETH_TYPE_IP6_BE         0xdd86  //  IPv6, big endian

typedef struct _ETH_HEADER
{
    UCHAR   DstAddr[ETH_LENGTH_OF_ADDRESS];
    UCHAR   SrcAddr[ETH_LENGTH_OF_ADDRESS];
    USHORT  EthType;
} ETH_HEADER, *PETH_HEADER;

typedef struct _IP_ADDRESS_V4
{
    union
    {
        unsigned char   b[4];
        unsigned short  s[2];
        unsigned long   l;
    };
} IP_ADDRESS_V4, *PIP_ADDRESS_V4;

typedef struct _IP_ADDRESS_V6
{
    union
    {
        unsigned char       b[16];
        unsigned short      s[8];
        unsigned long       l[4];
        unsigned long long  q[2];
    };
} IP_ADDRESS_V6, *PIP_ADDRESS_V6;

typedef struct _IP_ADDRESS
{
    union
    {
        IP_ADDRESS_V4   v4;
        IP_ADDRESS_V6   v6;
    };
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

    };

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

#define NETWORK_EVENT_INFO_PROCESS_PATH_MAX_SIZE    1024

typedef struct _NETWORK_EVENT_INFO
{
    USHORT  IpProtocol;

    USHORT  AddressFamily;

    struct Local
    {
        IP_ADDRESS  Address;
        USHORT      Port;
    } Local;

    struct Remote
    {
        IP_ADDRESS  Address;
        USHORT      Port;
    } Remote;

    struct Process
    {
        unsigned long long  Id;
        unsigned long       NameSize;
        wchar_t             NameBuffer[NETWORK_EVENT_INFO_PROCESS_PATH_MAX_SIZE];
    } Process;

} NETWORK_EVENT_INFO, *PNETWORK_EVENT_INFO;

typedef struct _ADAPTER
{
    LIST_ENTRY      Link;

    //  Unicode string containing adapter id
    UNICODE_STRING  Name;

    //  Adapter display name
    char            DisplayName[1024];

    //  Size of the data stored in MacAddress field.
    ULONG           MacAddressSize;

    //  Physical adapter address
    UCHAR           MacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];

    //  MTU size
    ULONG           MtuSize;

    //  NDIS adapter handle
    NDIS_HANDLE     AdapterHandle;

    //  Adapter lock
    PNDIS_SPIN_LOCK Lock;

    //  Associated device instance
    PDEVICE         Device;

    //  Bind operation timestamp
    LARGE_INTEGER   BindTimestamp;

    // To complete Bind request if necessary
    NDIS_HANDLE     BindContext;

    // To complete Unbind request if necessary
    NDIS_HANDLE     UnbindContext;

    //  Readiness flag
    ULONG           Ready;

    //  Number of pending OID requests
    volatile ULONG  PendingOidRequests;

    //  Number of pending packet injectio requests
    volatile ULONG  PendingSendPackets;

    //  Pointer to driver data
    PDRIVER_DATA    DriverData;

} ADAPTER, *PADAPTER;


typedef struct _DRIVER_DATA
{
    LONG                DriverUnload;

    struct Ndis
    {
        KM_MEMORY_MANAGER   MemoryManager;
        NDIS_HANDLE         DriverHandle;
        NDIS_HANDLE         ProtocolHandle;
    } Ndis;

    struct Wfp
    {
        KM_MEMORY_MANAGER   MemoryManager;
        HANDLE  Instance;
    } Wfp;

    struct Other
    {
        PDRIVER_OBJECT  DriverObject;
        HANDLE          Connections;
    } Other;

    PDEVICE             ListAdaptersDevice;

    KM_LIST             AdaptersList;

} DRIVER_DATA, *PDRIVER_DATA;

#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP     17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP    2
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6  58
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6    23
#endif

#endif