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

#ifndef WFP_UTILS_H
#define WFP_UTILS_H

#include <fwpsk.h>
#include "KmTypes.h"

typedef struct WFP_LAYER_INDEXES
{
    ULONG   LocalAddress;

    ULONG   LocalPort;

    ULONG   RemoteAddress;

    ULONG   RemotePort;

    ULONG   IpProtocol;

    ULONG   Flags;

    ULONG   Direction;

} WFP_LAYER_INDEXES, *PWFP_LAYER_INDEXES;

#define WFP_INVALID_LAYER_INDEX ((ULONG)-1)

NTSTATUS __stdcall WfpUtils_GetFlags(
    __in    const   FWPS_INCOMING_VALUES    *InFixedValues,
    __out           PULONG                  Flags);

NTSTATUS __stdcall WfpUtils_IsAleReauth(
    __in    const   FWPS_INCOMING_VALUES    *InFixedValues,
    __out           PBOOLEAN                IsReauth);

NTSTATUS __stdcall WfpUtils_GetLayerIndexes(
    __in    UINT16               LayerId,
    __out   PWFP_LAYER_INDEXES   Indexes);

NTSTATUS __stdcall WfpUtils_GetAddressFamily(
    __in    UINT16          LayerId,
    __out   ADDRESS_FAMILY  *AddressFamily);

NTSTATUS __stdcall WfpUtils_GetEthType(
    __in    UINT16  LayerId,
    __out   PUINT16 EthType);

NTSTATUS __stdcall WfpUtils_FillNetworkEventInfo(
    __in    const   FWPS_INCOMING_VALUES            *InFixedValues,
    __in    const   FWPS_INCOMING_METADATA_VALUES   *InMetaValues,
    __out           PNET_EVENT_INFO                 Info);

#endif
