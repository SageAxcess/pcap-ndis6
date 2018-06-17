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
#include "KmList.h"
#include "KmTypes.h"

//////////////////////////////////////////////////////////////////////
// Adapter definitions
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
// Adapter methods
//////////////////////////////////////////////////////////////////////

BOOL SendOidRequest(
    __in    PADAPTER    adapter,
    __in    BOOL        set,
    __in    NDIS_OID    oid,
    __in    void        *data,
    __in    UINT        size);

BOOL FreeAdapter(
    __in    PADAPTER    Adapter);

NTSTATUS GetAdapterTime(
    __in    PADAPTER    Adapter,
    __out   PKM_TIME    Time);

NTSTATUS FindAdapterById(
    __in        PKM_LIST                AdapterList,
    __in        PPCAP_NDIS_ADAPTER_ID   AdapterId,
    __out_opt   PADAPTER                *Adapter,
    __in        BOOLEAN                 LockList);

NTSTATUS Adapter_Reference(
    __in    PADAPTER    Adapter);

NTSTATUS Adapter_Dereference(
    __in    PADAPTER    Adapter);

NTSTATUS Adapter_AllocateAndFillPacket(
    __in    PADAPTER    Adapter,
    __in    PVOID       PacketData,
    __in    ULONG       PacketDataSize,
    __in    ULONGLONG   ProcessId,
    __in    PKM_TIME    Timestamp,
    __out   PPACKET     *Packet);

NTSTATUS Adapters_Unbind(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PKM_LIST            AdaptersList);

//////////////////////////////////////////////////////////////////////
// Adapter callbacks
//////////////////////////////////////////////////////////////////////

NDIS_STATUS
_Function_class_(SET_OPTIONS)
Protocol_SetOptionsHandler(
    __in    NDIS_HANDLE NdisDriverHandle,
    __in    NDIS_HANDLE DriverContext);

NDIS_STATUS
_Function_class_(PROTOCOL_NET_PNP_EVENT)
Protocol_NetPnPEventHandler(
    __in    NDIS_HANDLE                 ProtocolBindingContext,
    __in    PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification);

void
_Function_class_(PROTOCOL_UNINSTALL)
Protocol_UninstallHandler(void);

void
_Function_class_(PROTOCOL_STATUS_EX)
Protocol_StatusHandlerEx(
    __in    NDIS_HANDLE             ProtocolBindingContext,
    __in    PNDIS_STATUS_INDICATION StatusIndication);

void
_Function_class_(PROTOCOL_DIRECT_OID_REQUEST_COMPLETE)
Protocol_DirectOidRequestCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    PNDIS_OID_REQUEST   OidRequest,
    __in    NDIS_STATUS         Status);

NDIS_STATUS
_Function_class_(PROTOCOL_BIND_ADAPTER_EX)
Protocol_BindAdapterHandlerEx(
    __in    NDIS_HANDLE             ProtocolDriverContext,
    __in    NDIS_HANDLE             BindContext,
    __in    PNDIS_BIND_PARAMETERS   BindParameters);

NDIS_STATUS
_Function_class_(PROTOCOL_UNBIND_ADAPTER_EX)
Protocol_UnbindAdapterHandlerEx(
    __in    NDIS_HANDLE UnbindContext,
    __in    NDIS_HANDLE ProtocolBindingContext);

void
_Function_class_(PROTOCOL_OPEN_ADAPTER_COMPLETE_EX)
Protocol_OpenAdapterCompleteHandlerEx(
    __in    NDIS_HANDLE ProtocolBindingContext,
    __in    NDIS_STATUS Status);

void
_Function_class_(PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX)
Protocol_CloseAdapterCompleteHandlerEx(
    __in    NDIS_HANDLE ProtocolBindingContext);

void
_Function_class_(PROTOCOL_OID_REQUEST_COMPLETE)
Protocol_OidRequestCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    NDIS_OID_REQUEST    *OidRequest,
    __in    NDIS_STATUS         Status);

void
_Function_class_(PROTOCOL_RECEIVE_NET_BUFFER_LISTS)
Protocol_ReceiveNetBufferListsHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    PNET_BUFFER_LIST    NetBufferLists,
    __in    NDIS_PORT_NUMBER    PortNumber,
    __in    ULONG               NumberOfNetBufferLists,
    __in    ULONG               ReceiveFlags);

void
_Function_class_(PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE)
Protocol_SendNetBufferListsCompleteHandler(
    __in    NDIS_HANDLE         ProtocolBindingContext,
    __in    PNET_BUFFER_LIST    NetBufferList,
    __in    ULONG               SendCompleteFlags);