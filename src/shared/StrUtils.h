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
#pragma once

#include <string>
#include <Windows.h>

namespace UTILS
{
    namespace STR
    {
        std::wstring FormatW(
            __in    LPCWSTR FormatStr,
            __in            ...);

        std::wstring GetTimeStr(
            __in_opt    BOOL    LocalOrSystem = FALSE);
    };
};
