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

#include <Windows.h>
#include <string>
#include <vector>

namespace UTILS
{
    namespace SVC
    {
        BOOL __stdcall GetServiceConfig(
            __in    const   SC_HANDLE           ServiceHandle,
            __out           std::vector<UCHAR>   &ConfigBuffer);

        std::wstring __stdcall GetServiceImagePath(
            __in    const   SC_HANDLE   ServiceHandle);

        std::wstring __stdcall GetServiceImagePath(
            __in    const   std::wstring    &ServiceName);

        BOOL __stdcall IsServiceInstalled(
            __in    const   std::wstring    &ServiceName);
    };
};

