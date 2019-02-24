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

#include "..\shared\CommonDefs.h"
#include "..\shared\SharedTypes.h"

#include <string>

#include <Windows.h>

namespace UTILS
{
    namespace PKT
    {
        BOOL Parse(
            __in    LPVOID              Buffer,
            __in    ULONG               BufferSize,
            __in    ULONG               ProcessId,
            __out   LPNET_EVENT_INFO    EventInfo);

        std::wstring NetEventInfoToStringW(
            __in        LPNET_EVENT_INFO    EventInfo,
            __in_opt    BOOLEAN             IncludeEthDetails = FALSE);

        std::wstring EthAddressToStringW(
            __in    PETH_ADDRESS    Address);

        std::wstring IP4AddressToStringW(
            __in    PIP_ADDRESS_V4  Address);

        std::wstring IP6AddressToStringW(
            __in    PIP_ADDRESS_V6  Address);
    };
};
