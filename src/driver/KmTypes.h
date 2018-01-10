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

    BOOL            Releasing;

    BOOL            IsAdaptersList;

} DEVICE, *PDEVICE;

typedef struct _ETH_HEADER
{
    UCHAR   DstAddr[ETH_LENGTH_OF_ADDRESS];
    UCHAR   SrcAddr[ETH_LENGTH_OF_ADDRESS];
    USHORT  EthType;
} ETH_HEADER, *PETH_HEADER;

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
    BOOL            Ready;

    //  Number of pending OID requests
    volatile ULONG  PendingOidRequests;

    //  Number of pending packet injectio requests
    volatile ULONG  PendingSendPackets;

    //  Pointer to driver data
    PDRIVER_DATA    DriverData;

} ADAPTER, *PADAPTER;


typedef struct _DRIVER_DATA
{
    NDIS_MM             MemoryManager;

    LONG                DriverUnload;

    struct Ndis
    {
        NDIS_HANDLE DriverHandle;
        NDIS_HANDLE ProtocolHandle;
    } Ndis;

    struct Other
    {
        PDRIVER_OBJECT  DriverObject;
    } Other;

    PDEVICE             ListAdaptersDevice;

    KM_LIST             AdaptersList;
} DRIVER_DATA, *PDRIVER_DATA;

#endif
