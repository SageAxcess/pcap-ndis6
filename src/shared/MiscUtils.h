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

namespace UTILS
{
    namespace MISC
    {
        std::wstring GetModuleName(
            __in    const   HMODULE ModuleHandle);

        std::wstring GetApplicationFileName();

        std::wstring GetOsVersionStr();

        void GetOSVersionInfo(
            __out   LPOSVERSIONINFOEXW  VersionInfo);
    };
};