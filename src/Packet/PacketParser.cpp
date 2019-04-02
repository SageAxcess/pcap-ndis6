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

#include "PacketParser.h"
#include "..\shared\StrUtils.h"

BOOL UTILS::PKT::Parse(
    __in    LPVOID              Buffer,
    __in    ULONG               BufferSize,
    __in    ULONG               ProcessId,
    __out   LPNET_EVENT_INFO    EventInfo)
{
    RETURN_VALUE_IF_FALSE(
        (Assigned(Buffer)) &&
        (BufferSize >= static_cast<ULONG>(sizeof(ETH_HEADER))) &&
        (Assigned(EventInfo)),
        FALSE);

    NET_EVENT_INFO  Info;
    PETH_HEADER     EthHeader = nullptr;
    DWORD           IpHeaderLength = 0;
    PUCHAR          TransportHeaderPtr = nullptr;

    RtlZeroMemory(
        &Info,
        sizeof(Info));

    Info.Process.Id = ProcessId;

    EthHeader = reinterpret_cast<PETH_HEADER>(Buffer);

    RtlCopyMemory(
        &Info.Local.EthAddress,
        &EthHeader->SrcAddr,
        sizeof(ETH_ADDRESS));

    RtlCopyMemory(
        &Info.Remote.EthAddress,
        &EthHeader->DstAddr,
        sizeof(ETH_ADDRESS));

    Info.EthType = EthHeader->EthType;

    switch (Info.EthType)
    {
    case ETH_TYPE_IP:
    case ETH_TYPE_IP_BE:
        {
            if (BufferSize <= static_cast<ULONG>(sizeof(ETH_HEADER) + sizeof(IP4_HEADER)))
            {
                PIP4_HEADER Header =
                    reinterpret_cast<PIP4_HEADER>(reinterpret_cast<PUCHAR>(EthHeader) + sizeof(ETH_HEADER));

                IpHeaderLength = (Header->VerLen & 15) * 4;

                Info.Local.IpAddress.Address.v4 = Header->SourceAddress;
                Info.Remote.IpAddress.Address.v4 = Header->DestinationAddress;
                Info.IpProtocol = Header->Protocol;
            }
        }break;

    case ETH_TYPE_IP6:
    case ETH_TYPE_IP6_BE:
        {
            if (BufferSize <= static_cast<ULONG>(sizeof(ETH_HEADER) + sizeof(IP6_HEADER)))
            {
                PIP6_HEADER Header = 
                    reinterpret_cast<PIP6_HEADER>(reinterpret_cast<PUCHAR>(Buffer) + sizeof(ETH_HEADER));

                IpHeaderLength = sizeof(IP6_HEADER);

                Info.Local.IpAddress.Address.v6 = Header->SourceAddress;
                Info.Remote.IpAddress.Address.v6 = Header->DestinationAddress;
                Info.IpProtocol = Header->NextHeader;
            }
        }break;
    };

    if (IpHeaderLength > 0)
    {
        ULONG   TransportHeaderOffset = static_cast<ULONG>(sizeof(ETH_HEADER) + IpHeaderLength);

        TransportHeaderPtr = reinterpret_cast<PUCHAR>(Buffer) + TransportHeaderOffset;

        switch (Info.IpProtocol)
        {
        case IPPROTO_TCP:
            {
                if (BufferSize <= static_cast<ULONG>(sizeof(TCP_HEADER) + TransportHeaderOffset))
                {
                    PTCP_HEADER Header = reinterpret_cast<PTCP_HEADER>(TransportHeaderPtr);

                    Info.Local.TransportSpecific = Header->SourcePort;
                    Info.Remote.TransportSpecific = Header->DestinationPort;
                }
            }break;

        case IPPROTO_UDP:
            {
                if (BufferSize <= static_cast<ULONG>(sizeof(UDP_HEADER) + TransportHeaderOffset))
                {
                    PUDP_HEADER Header = reinterpret_cast<PUDP_HEADER>(TransportHeaderPtr);

                    Info.Local.TransportSpecific = Header->SourcePort;
                    Info.Remote.TransportSpecific = Header->DestinationPort;
                }
            }break;

        case IPPROTO_ICMP:
            {
                if (BufferSize <= static_cast<ULONG>(sizeof(ICMP_HEADER) + TransportHeaderOffset))
                {
                    PICMP_HEADER Header = reinterpret_cast<PICMP_HEADER>(TransportHeaderPtr);

                    Info.Local.TransportSpecific = Header->IcmpType;
                    Info.Remote.TransportSpecific = Header->Code;
                }
            }break;
        };
    }

    RtlCopyMemory(
        EventInfo,
        &Info,
        sizeof(Info));

    return TRUE;
};

std::wstring UTILS::PKT::NetEventInfoToStringW(
    __in        LPNET_EVENT_INFO    EventInfo,
    __in_opt    BOOLEAN             IncludeEthDetails)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(EventInfo),
        L"");

    std::wstring    EthDetailsStr;
    std::wstring    SrcIPStr;
    std::wstring    DstIPStr;

    std::wstring    Result;

    if (IncludeEthDetails)
    {
        EthDetailsStr = UTILS::STR::FormatW(
            L"ETH: SRC=%s, DST=%s, TYPE=%04x ",
            EthAddressToStringW(&EventInfo->Local.EthAddress).c_str(),
            EthAddressToStringW(&EventInfo->Local.EthAddress).c_str(),
            EventInfo->EthType);
    }

    switch (EventInfo->EthType)
    {
    case ETH_TYPE_IP:
    case ETH_TYPE_IP_BE:
        {
            SrcIPStr = IP4AddressToStringW(&EventInfo->Local.IpAddress.Address.v4);
            DstIPStr = IP4AddressToStringW(&EventInfo->Remote.IpAddress.Address.v4);
        }break;

    case ETH_TYPE_IP6:
    case ETH_TYPE_IP6_BE:
        {
            SrcIPStr = IP6AddressToStringW(&EventInfo->Local.IpAddress.Address.v6);
            DstIPStr = IP6AddressToStringW(&EventInfo->Remote.IpAddress.Address.v6);
        }break;
    };

    Result =
        EthDetailsStr +
        UTILS::STR::FormatW(
            L"src=%s:%d, dst=%s:%d, ipproto = %d",
            SrcIPStr.c_str(),
            EventInfo->Local.TransportSpecific,
            DstIPStr.c_str(),
            EventInfo->Remote.TransportSpecific,
            EventInfo->IpProtocol);

    return Result;
};

std::wstring UTILS::PKT::EthAddressToStringW(
    __in    PETH_ADDRESS    Address)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(Address),
        L"");

    return UTILS::STR::FormatW(
        L"[%02x:%02x:%02x:%02x:%02x:%02x]",
        Address->Addr[0],
        Address->Addr[1],
        Address->Addr[2],
        Address->Addr[3],
        Address->Addr[4],
        Address->Addr[5]);
};

std::wstring UTILS::PKT::IP4AddressToStringW(
    __in    PIP_ADDRESS_V4  Address)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(Address),
        L"");

    return UTILS::STR::FormatW(
        L"%d.%d.%d.%d",
        Address->ip.b[0],
        Address->ip.b[1],
        Address->ip.b[2],
        Address->ip.b[3]);
};

std::wstring UTILS::PKT::IP6AddressToStringW(
    __in    PIP_ADDRESS_V6  Address)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(Address),
        L"");

    return UTILS::STR::FormatW(
        L"[%x:%x:%x:%x:%x:%x:%x:%x]",
        Address->ip.s[0],
        Address->ip.s[1],
        Address->ip.s[2],
        Address->ip.s[3],
        Address->ip.s[4],
        Address->ip.s[5],
        Address->ip.s[6],
        Address->ip.s[7]);
};