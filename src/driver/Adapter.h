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

#include <ndis.h>
#include <minwindef.h>
#include "List.h"

//////////////////////////////////////////////////////////////////////
// Adapter definitions
//////////////////////////////////////////////////////////////////////

extern PLIST AdapterList;

typedef struct _ETH_HEADER
{
    UCHAR   DstAddr[ETH_LENGTH_OF_ADDRESS];
    UCHAR   SrcAddr[ETH_LENGTH_OF_ADDRESS];
    USHORT  EthType;
} ETH_HEADER, *PETH_HEADER;

typedef struct ADAPTER {
	char AdapterId[1024];
	PNDIS_STRING Name;
	char DisplayName[1024];
	UCHAR MacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];
	ULONG MtuSize;
	NDIS_HANDLE AdapterHandle;
	PNDIS_SPIN_LOCK Lock;

	struct DEVICE* Device;

	LARGE_INTEGER BindTimestamp;

	NDIS_HANDLE BindContext;   // To complete Bind request if necessary
	NDIS_HANDLE UnbindContext; // To complete Unbind request if necessary

	BOOL Ready;

	volatile ULONG PendingOidRequests;
	volatile ULONG PendingSendPackets;

	char TmpBuf[MAX_PACKET_SIZE];
} ADAPTER;
typedef const ADAPTER *PADAPTER;

//////////////////////////////////////////////////////////////////////
// Adapter methods
//////////////////////////////////////////////////////////////////////

BOOL SendOidRequest(PADAPTER adapter, BOOL set, NDIS_OID oid, void *data, UINT size);
BOOL FreeAdapter(ADAPTER* adapter);
BOOL FreeAdapterList(PLIST list);
LARGE_INTEGER GetAdapterTime(ADAPTER* adapter); // returns time in milliseconds since adapter was bound

//////////////////////////////////////////////////////////////////////
// Adapter callbacks
//////////////////////////////////////////////////////////////////////


NDIS_STATUS _Function_class_(SET_OPTIONS) Protocol_SetOptionsHandler(NDIS_HANDLE NdisDriverHandle, NDIS_HANDLE DriverContext);
NDIS_STATUS _Function_class_(PROTOCOL_NET_PNP_EVENT) Protocol_NetPnPEventHandler(NDIS_HANDLE ProtocolBindingContext, PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification);
void _Function_class_(PROTOCOL_UNINSTALL) Protocol_UninstallHandler(VOID);
void _Function_class_(PROTOCOL_STATUS_EX) Protocol_StatusHandlerEx(NDIS_HANDLE ProtocolBindingContext, PNDIS_STATUS_INDICATION StatusIndication);
void _Function_class_(PROTOCOL_DIRECT_OID_REQUEST_COMPLETE) Protocol_DirectOidRequestCompleteHandler(NDIS_HANDLE ProtocolBindingContext, PNDIS_OID_REQUEST OidRequest, NDIS_STATUS Status);

NDIS_STATUS _Function_class_(PROTOCOL_BIND_ADAPTER_EX) Protocol_BindAdapterHandlerEx(NDIS_HANDLE ProtocolDriverContext, NDIS_HANDLE BindContext, PNDIS_BIND_PARAMETERS BindParameters);
NDIS_STATUS _Function_class_(PROTOCOL_UNBIND_ADAPTER_EX) Protocol_UnbindAdapterHandlerEx(NDIS_HANDLE UnbindContext, NDIS_HANDLE ProtocolBindingContext);
void _Function_class_(PROTOCOL_OPEN_ADAPTER_COMPLETE_EX) Protocol_OpenAdapterCompleteHandlerEx(NDIS_HANDLE ProtocolBindingContext, NDIS_STATUS Status);
void _Function_class_(PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX) Protocol_CloseAdapterCompleteHandlerEx(NDIS_HANDLE ProtocolBindingContext);
void _Function_class_(PROTOCOL_OID_REQUEST_COMPLETE) Protocol_OidRequestCompleteHandler(NDIS_HANDLE ProtocolBindingContext, NDIS_OID_REQUEST *OidRequest, NDIS_STATUS Status);
void _Function_class_(PROTOCOL_RECEIVE_NET_BUFFER_LISTS) Protocol_ReceiveNetBufferListsHandler(NDIS_HANDLE ProtocolBindingContext, PNET_BUFFER_LIST NetBufferLists, NDIS_PORT_NUMBER PortNumber, ULONG NumberOfNetBufferLists, ULONG ReceiveFlags);
void _Function_class_(PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE) Protocol_SendNetBufferListsCompleteHandler(NDIS_HANDLE ProtocolBindingContext, PNET_BUFFER_LIST NetBufferList, ULONG SendCompleteFlags);