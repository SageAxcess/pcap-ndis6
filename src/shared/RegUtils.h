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
    namespace REG
    {
        BOOL __stdcall ReadValue(
            __in            HKEY            Key,
            __in    const   std::wstring    &ValueName,
            __out           LPVOID          Buffer,
            __out           LPDWORD         BufferSize);

        BOOL __stdcall ReadValueSize(
            __in            HKEY            Key,
            __in    const   std::wstring    &ValueName,
            __out           LPDWORD         ValueSize);

        BOOL __stdcall ReadDWORD(
            __in            HKEY            Key,
            __in    const   std::wstring    &ValueName,
            __out           LPDWORD         Value);
    };
};