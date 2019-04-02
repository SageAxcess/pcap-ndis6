//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2017 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#include "WfpUtils.h"
#include "..\shared\CommonDefs.h"

NTSTATUS __stdcall WfpUtils_GetFlags(
    __in    const   FWPS_INCOMING_VALUES    *InFixedValues,
    __out           PULONG                  Flags)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    FWP_VALUE   *FlagsValue = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InFixedValues),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Flags),
        STATUS_INVALID_PARAMETER_2);

    switch (InFixedValues->layerId)
    {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4_DISCARD:
        {
            FlagsValue = &InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS].value;
        }break;

    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6_DISCARD:
        {
            FlagsValue = &InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS].value;
        }break;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD:
        {
            FlagsValue = &InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS].value;
        }break;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD:
        {
            FlagsValue = &InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS].value;
        }break;
    };

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(FlagsValue),
        STATUS_NOT_SUPPORTED);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        FlagsValue->type == FWP_UINT32,
        STATUS_NOT_FOUND);

    *Flags = FlagsValue->uint32;

cleanup:
    return Status;
};

NTSTATUS __stdcall WfpUtils_IsAleReauth(
    __in    const   FWPS_INCOMING_VALUES    *InFixedValues,
    __out           PBOOLEAN                IsReauth)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    ULONG       Flags = 0;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InFixedValues),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(IsReauth),
        STATUS_INVALID_PARAMETER_2);

    Status = WfpUtils_GetFlags(
        InFixedValues,
        &Flags);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    *IsReauth = IsBitFlagSet(Flags, FWP_CONDITION_FLAG_IS_REAUTHORIZE);

cleanup:
    return Status;
};

NTSTATUS __stdcall WfpUtils_GetLayerIndexes(
    __in    UINT16               LayerId,
    __out   PWFP_LAYER_INDEXES   Indexes)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Indexes),
        STATUS_INVALID_PARAMETER_2);

    RtlFillMemory(
        Indexes,
        sizeof(WFP_LAYER_INDEXES),
        0xFF);

    switch (LayerId)
    {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4_DISCARD:
        {
            Indexes->Flags = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
            Indexes->IpProtocol = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
            Indexes->LocalAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
            Indexes->LocalPort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
            Indexes->RemoteAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
            Indexes->RemotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
        }break;

    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6_DISCARD:
        {
            Indexes->Flags = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
            Indexes->IpProtocol = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
            Indexes->LocalAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
            Indexes->LocalPort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
            Indexes->RemoteAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
            Indexes->RemotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
        }break;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD:
        {
            Indexes->Flags = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS;
            Indexes->IpProtocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
            Indexes->LocalAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
            Indexes->LocalPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
            Indexes->RemoteAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
            Indexes->RemotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
        }break;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD:
        {
            Indexes->Flags = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS;
            Indexes->IpProtocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
            Indexes->LocalAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
            Indexes->LocalPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
            Indexes->RemoteAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
            Indexes->RemotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
        }break;

    default:
        {
            Status = STATUS_NOT_SUPPORTED;
        }break;
    };

cleanup:
    return Status;
};

NTSTATUS __stdcall WfpUtils_GetAddressFamily(
    __in    UINT16          LayerId,
    __out   ADDRESS_FAMILY  *AddressFamily)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    UINT16      EthType = 0;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(AddressFamily),
        STATUS_INVALID_PARAMETER_2);

    Status = WfpUtils_GetEthType(LayerId, &EthType);
    GOTO_CLEANUP_IF_FALSE(
        (NT_SUCCESS(Status)) || 
        (Status == STATUS_NOT_SUPPORTED));

    *AddressFamily = EthTypeToAddressFamily(EthType);

cleanup:
    return Status;
};

NTSTATUS __stdcall WfpUtils_GetEthType(
    __in    UINT16  LayerId,
    __out   PUINT16 EthType)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EthType),
        STATUS_INVALID_PARAMETER_1);

    switch (LayerId)
    {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4_DISCARD:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD:
        {
            *EthType = ETH_TYPE_IP;
        }break;

    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6_DISCARD:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD:
        {
            *EthType = ETH_TYPE_IP6;
        }break;

    default:
        {
            *EthType = 0;
            Status = STATUS_NOT_SUPPORTED;
        }break;
    };

cleanup:
    return Status;
};

NTSTATUS __stdcall WfpUtils_FillNetworkEventInfo(
    __in    const   FWPS_INCOMING_VALUES            *InFixedValues,
    __in    const   FWPS_INCOMING_METADATA_VALUES   *InMetaValues,
    __out           PNET_EVENT_INFO                 Info)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    WFP_LAYER_INDEXES   LayerIndexes;
    ULONG               Flags;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InFixedValues),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InMetaValues),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Info),
        STATUS_INVALID_PARAMETER_3);

    Status = WfpUtils_GetFlags(
        InFixedValues,
        &Flags);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = WfpUtils_GetLayerIndexes(
        InFixedValues->layerId,
        &LayerIndexes);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = WfpUtils_GetEthType(
        InFixedValues->layerId,
        &Info->EthType);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    if (LayerIndexes.LocalPort != WFP_INVALID_LAYER_INDEX)
    {
        if (InFixedValues->incomingValue[LayerIndexes.LocalPort].value.type != FWP_EMPTY)
        {
            Info->Local.TransportSpecific = BYTES_SWAP_16(InFixedValues->incomingValue[LayerIndexes.LocalPort].value.uint16);
        }
    }

    if (LayerIndexes.RemotePort != WFP_INVALID_LAYER_INDEX)
    {
        if (InFixedValues->incomingValue[LayerIndexes.RemotePort].value.type != FWP_EMPTY)
        {
            Info->Remote.TransportSpecific = BYTES_SWAP_16(InFixedValues->incomingValue[LayerIndexes.RemotePort].value.uint16); 
        }
    }

    if (LayerIndexes.IpProtocol != WFP_INVALID_LAYER_INDEX)
    {
        if (InFixedValues->incomingValue[LayerIndexes.IpProtocol].value.type != FWP_EMPTY)
        {
            Info->IpProtocol = InFixedValues->incomingValue[LayerIndexes.IpProtocol].value.uint16;
        }
    }

    switch (Info->EthType)
    {
    case ETH_TYPE_IP:
    case ETH_TYPE_IP_BE:
        {
            if (LayerIndexes.LocalAddress != WFP_INVALID_LAYER_INDEX)
            {
                if (InFixedValues->incomingValue[LayerIndexes.LocalAddress].value.type != FWP_EMPTY)
                {
                    Info->Local.IpAddress.Address.v4.ip.l = BYTES_SWAP_32(
                        InFixedValues->incomingValue[LayerIndexes.LocalAddress].value.uint32);
                }
            }

            if (LayerIndexes.RemoteAddress != WFP_INVALID_LAYER_INDEX)
            {
                if (InFixedValues->incomingValue[LayerIndexes.RemoteAddress].value.type != FWP_EMPTY)
                {
                    Info->Remote.IpAddress.Address.v4.ip.l = BYTES_SWAP_32(
                        InFixedValues->incomingValue[LayerIndexes.RemoteAddress].value.uint32);
                }
            }

        }break;

    case ETH_TYPE_IP6:
    case ETH_TYPE_IP6_BE:
        {
            if (LayerIndexes.LocalAddress != WFP_INVALID_LAYER_INDEX)
            {
                if (InFixedValues->incomingValue[LayerIndexes.LocalAddress].value.type != FWP_EMPTY)
                {
                    RtlCopyMemory(
                        &Info->Local.IpAddress,
                        InFixedValues->incomingValue[LayerIndexes.LocalAddress].value.byteArray16,
                        sizeof(FWP_BYTE_ARRAY16));
                    IP6_SWAP_BYTE_ORDER(Info->Local.IpAddress.Address.v6.ip.s);
                }
            }

            if (LayerIndexes.RemoteAddress != WFP_INVALID_LAYER_INDEX)
            {
                if (InFixedValues->incomingValue[LayerIndexes.RemoteAddress].value.type != FWP_EMPTY)
                {
                    RtlCopyMemory(
                        &Info->Remote.IpAddress,
                        InFixedValues->incomingValue[LayerIndexes.RemoteAddress].value.byteArray16,
                        sizeof(FWP_BYTE_ARRAY16));
                    IP6_SWAP_BYTE_ORDER(Info->Remote.IpAddress.Address.v6.ip.s);
                }
            }

        }break;
    };

    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
    {
        Info->Process.Id = InMetaValues->processId;
    }
    else
    {
        Info->Process.Id = (unsigned long long)(-1);
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH))
    {
        ULONG   BytesToCopy =
            InMetaValues->processPath->size > NET_EVENT_INFO_PROCESS_PATH_MAX_SIZE ?
            NET_EVENT_INFO_PROCESS_PATH_MAX_SIZE :
            InMetaValues->processPath->size;

        if (BytesToCopy > 0)
        {
            RtlCopyMemory(
                Info->Process.NameBuffer,
                InMetaValues->processPath->data,
                BytesToCopy);
            Info->Process.NameSize = BytesToCopy;
        }
    }

cleanup:
    return Status;
};