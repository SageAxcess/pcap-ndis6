//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2019 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////
#ifndef KM_CONNECTIONS_H
#define KM_CONNECTIONS_H

#include "KmList.h"
#include "KmMemoryManager.h"
#include "KmTypes.h"

#define KM_CONNECTIONS_INITIAL_POOL_SIZE    0x200

#define KM_CONN_PROTO_INDEX_TCP	0x0
#define KM_CONN_PROTO_INDEX_UDP	0x1
#define KM_CONN_PROTO_COUNT		0x2
#define KM_CONN_PORTS_COUNT		0x10000

typedef struct _KM_CONNECTIONS_LIST
{
	PRTL_AVL_TABLE	ConnectionsTree;
} KM_CONNECTIONS_LIST, *PKM_CONNECTIONS_LIST;

typedef struct _KM_CONNECTIONS
{
	KM_CONNECTIONS_LIST	List[KM_CONN_PROTO_COUNT][KM_CONN_PORTS_COUNT];
} KM_CONNECTIONS, *PKM_CONNECTIONS;

NTSTATUS __stdcall Km_Connections_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PHANDLE             Instance);

NTSTATUS __stdcall Km_Connections_Finalize(
    __in    HANDLE  Instance);

NTSTATUS __stdcall Km_Connections_Add(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info);

NTSTATUS __stdcall Km_Connections_Remove(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info);

NTSTATUS __stdcall Km_Connections_GetPIDForPacket(
    __in    HANDLE          Instance,
    __in    PNET_EVENT_INFO Info,
    __out   PULONGLONG      ProcessId);

#endif