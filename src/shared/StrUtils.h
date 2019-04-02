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
#pragma once

#include <string>
#include <Windows.h>

namespace UTILS
{
    namespace STR
    {
        BOOL SameTextA(
            __in    const   std::string &String1,
            __in    const   std::string &String2);

        BOOL SameTextW(
            __in    const   std::wstring    &String1,
            __in    const   std::wstring    &String2);

        std::string FormatA(
            __in    LPCSTR  FormatStr,
            __in            ...);

        std::wstring FormatW(
            __in    LPCWSTR FormatStr,
            __in            ...);

        std::wstring TimeToStringW(
            __in    const   SYSTEMTIME  &Time);

        std::wstring GetTimeStr(
            __in_opt    BOOL    LocalOrSystem = FALSE);

        BOOL EndsOnA(
            __in    const   std::string &Str,
            __in    const   std::string &SubStr);

        BOOL EndsOnW(
            __in    const   std::wstring    &Str,
            __in    const   std::wstring    &SubStr);

        std::string GuidToStringA(
            __in    const   GUID    &Guid);

        std::wstring GuidToStringW(
            __in    const   GUID    &Guid);
    };
};
