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

#include "StrUtils.h"
#include "CommonDefs.h"
#include <vector>

std::string UTILS::STR::FormatA(
    __in    LPCSTR  FormatStr,
    __in            ...)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(FormatStr),
        "");

    va_list     ArgList;
    std::string Result;

    va_start(ArgList, FormatStr);
    try
    {
        int                 NumberOfChars = _vscprintf(FormatStr, ArgList);
        std::vector<char>   Buffer;

        Buffer.resize(NumberOfChars + 3, 0);

        if (_vsnprintf_s(
            &Buffer[0],
            NumberOfChars + 2,
            NumberOfChars + 1,
            FormatStr,
            ArgList) > 0)
        {
            Result = std::string(&Buffer[0]);
        }
    }
    catch (...)
    {
    }
    va_end(ArgList);

    return Result;
};

std::wstring UTILS::STR::FormatW(
    __in    LPCWSTR FormatStr,
    __in            ...)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(FormatStr),
        L"");

    va_list         ArgList;
    std::wstring    Result;

    va_start(ArgList, FormatStr);
    try
    {
        int                     NumberOfChars = _vscwprintf(FormatStr, ArgList);
        std::vector<wchar_t>    Buffer;

        Buffer.resize(NumberOfChars + 3, 0);

        if (_vsnwprintf_s(
            &Buffer[0],
            NumberOfChars + 2,
            NumberOfChars + 1,
            FormatStr,
            ArgList) > 0)
        {
            Result = std::wstring(&Buffer[0]);
        }
    }
    catch (...)
    {
    }
    va_end(ArgList);

    return Result;
};

std::wstring UTILS::STR::GetTimeStr(
    __in_opt    BOOL    LocalOrSystem)
{
    SYSTEMTIME  Time;

    if (LocalOrSystem)
    {
        GetLocalTime(&Time);
    }
    else
    {
        GetSystemTime(&Time);
    }

    return FormatW(
        L"%02d:%02d:%02d%:%03d",
        Time.wHour,
        Time.wMinute,
        Time.wSecond,
        Time.wMilliseconds);
};