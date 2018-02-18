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

#include "PacketParser.h"
#include "..\shared\StrUtils.h"

BOOL UTILS::PKT::Parse(
    __in    LPVOID          Buffer,
    __in    ULONG           BufferSize,
    __in    ULONG           ProcessId,
    __out   LPPACKET_DESC   PacketDesc)
{
    RETURN_VALUE_IF_FALSE(
        (Assigned(Buffer)) &&
        (BufferSize >= static_cast<ULONG>(sizeof(ETH_HEADER))) &&
        (Assigned(PacketDesc)),
        FALSE);

    PACKET_DESC Desc;
    PETH_HEADER EthHeader = nullptr;
    DWORD       IpHeaderLength = 0;
    PUCHAR      TransportHeaderPtr = nullptr;

    RtlZeroMemory(
        &Desc,
        sizeof(Desc));

    Desc.ProcessId = ProcessId;

    EthHeader = reinterpret_cast<PETH_HEADER>(Buffer);

    RtlCopyMemory(
        &Desc.SourceEthAddress,
        &EthHeader->SrcAddr,
        sizeof(ETH_ADDRESS));

    RtlCopyMemory(
        &Desc.DestinationEthAddress,
        &EthHeader->DstAddr,
        sizeof(ETH_ADDRESS));

    Desc.EthType = EthHeader->EthType;

    switch (Desc.EthType)
    {
    case ETH_TYPE_IP_BE:
        {
            if (BufferSize <= static_cast<ULONG>(sizeof(ETH_HEADER) + sizeof(IP4_HEADER)))
            {
                PIP4_HEADER Header =
                    reinterpret_cast<PIP4_HEADER>(reinterpret_cast<PUCHAR>(EthHeader) + sizeof(ETH_HEADER));

                IpHeaderLength = (Header->VerLen & 15) * 4;

                Desc.SourceIPAddress.v4 = Header->SourceAddress;
                Desc.DestinationIPAddress.v4 = Header->DestinationAddress;
                Desc.IPProtocol = Header->Protocol;
            }
        }break;

    case ETH_TYPE_IP6_BE:
        {
            if (BufferSize <= static_cast<ULONG>(sizeof(ETH_HEADER) + sizeof(IP6_HEADER)))
            {
                PIP6_HEADER Header = 
                    reinterpret_cast<PIP6_HEADER>(reinterpret_cast<PUCHAR>(Buffer) + sizeof(ETH_HEADER));

                IpHeaderLength = sizeof(IP6_HEADER);

                Desc.SourceIPAddress.v6 = Header->SourceAddress;
                Desc.DestinationIPAddress.v6 = Header->DestinationAddress;
                Desc.IPProtocol = Header->NextHeader;
            }
        }break;
    };

    if (IpHeaderLength > 0)
    {
        ULONG   TransportHeaderOffset = static_cast<ULONG>(sizeof(ETH_HEADER) + IpHeaderLength);

        TransportHeaderPtr = reinterpret_cast<PUCHAR>(Buffer) + TransportHeaderOffset;

        switch (Desc.IPProtocol)
        {
        case IPPROTO_TCP:
            {
                if (BufferSize <= static_cast<ULONG>(sizeof(TCP_HEADER) + TransportHeaderOffset))
                {
                    PTCP_HEADER Header = reinterpret_cast<PTCP_HEADER>(TransportHeaderPtr);

                    Desc.SourcePortOrIcmpType.SourcePort = Header->SourcePort;
                    Desc.DestinationPortOrIcmpCode.DestinationPort = Header->DestinationPort;
                }
            }break;

        case IPPROTO_UDP:
            {
                if (BufferSize <= static_cast<ULONG>(sizeof(UDP_HEADER) + TransportHeaderOffset))
                {
                    PUDP_HEADER Header = reinterpret_cast<PUDP_HEADER>(TransportHeaderPtr);

                    Desc.SourcePortOrIcmpType.SourcePort = Header->SourcePort;
                    Desc.DestinationPortOrIcmpCode.DestinationPort = Header->DestinationPort;
                }
            }break;

        case IPPROTO_ICMP:
            {
                if (BufferSize <= static_cast<ULONG>(sizeof(ICMP_HEADER) + TransportHeaderOffset))
                {
                    PICMP_HEADER Header = reinterpret_cast<PICMP_HEADER>(TransportHeaderPtr);

                    Desc.DestinationPortOrIcmpCode.IcmpCode = Header->Code;
                    Desc.SourcePortOrIcmpType.IcmpType = Header->IcmpType;
                }
            }break;
        };
    }

    RtlCopyMemory(
        PacketDesc,
        &Desc,
        sizeof(Desc));

    return TRUE;
};

std::wstring UTILS::PKT::PacketDescToStringW(
    __in        LPPACKET_DESC   PacketDesc,
    __in_opt    BOOLEAN         IncludeEthDetails)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(PacketDesc),
        L"");

    std::wstring    EthDetailsStr;
    std::wstring    SrcIPStr;
    std::wstring    DstIPStr;

    std::wstring    Result;

    if (IncludeEthDetails)
    {
        EthDetailsStr = UTILS::STR::FormatW(
            L"ETH: SRC=%s, DST=%s, TYPE=%04x ",
            EthAddressToStringW(&PacketDesc->SourceEthAddress).c_str(),
            EthAddressToStringW(&PacketDesc->DestinationEthAddress).c_str(),
            PacketDesc->EthType);
    }

    switch (PacketDesc->EthType)
    {
    case ETH_TYPE_IP:
    case ETH_TYPE_IP_BE:
        {
            SrcIPStr = IP4AddressToStringW(&PacketDesc->SourceIPAddress.v4);
            DstIPStr = IP4AddressToStringW(&PacketDesc->DestinationIPAddress.v4);
        }break;

    case ETH_TYPE_IP6:
    case ETH_TYPE_IP6_BE:
        {
            SrcIPStr = IP6AddressToStringW(&PacketDesc->SourceIPAddress.v6);
            DstIPStr = IP6AddressToStringW(&PacketDesc->DestinationIPAddress.v6);
        }break;
    };

    Result =
        EthDetailsStr +
        UTILS::STR::FormatW(
            L"src=%s:%d, dst=%s:%d, ipproto = %d",
            SrcIPStr.c_str(),
            PacketDesc->SourcePortOrIcmpType.SourcePort,
            DstIPStr.c_str(),
            PacketDesc->DestinationPortOrIcmpCode.DestinationPort,
            PacketDesc->IPProtocol);

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
        Address->b[0],
        Address->b[1],
        Address->b[2],
        Address->b[3]);
};

std::wstring UTILS::PKT::IP6AddressToStringW(
    __in    PIP_ADDRESS_V6  Address)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(Address),
        L"");

    return UTILS::STR::FormatW(
        L"[%x:%x:%x:%x:%x:%x:%x:%x]",
        Address->s[0],
        Address->s[1],
        Address->s[2],
        Address->s[3],
        Address->s[4],
        Address->s[5],
        Address->s[6],
        Address->s[7]);
};