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

BOOL UTILS::STR::SameTextA(
    __in    const   std::string &String1,
    __in    const   std::string &String2)
{
    RETURN_VALUE_IF_FALSE(
        String1.length() == String2.length(),
        FALSE);
    RETURN_VALUE_IF_TRUE(
        String1.length() == 0,
        TRUE);

    return _strnicmp(
        String1.c_str(),
        String2.c_str(),
        String1.length()) == 0;
};

BOOL UTILS::STR::SameTextW(
    __in    const   std::wstring    &String1,
    __in    const   std::wstring    &String2)
{
    RETURN_VALUE_IF_FALSE(
        String1.length() == String2.length(),
        FALSE);
    RETURN_VALUE_IF_TRUE(
        String1.length() == 0,
        TRUE);

    return _wcsnicmp(
        String1.c_str(),
        String2.c_str(),
        String1.length()) == 0;
};

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
        L"%02d:%02d:%02d:%03d",
        Time.wHour,
        Time.wMinute,
        Time.wSecond,
        Time.wMilliseconds);
};

std::string UTILS::STR::GuidToStringA(
    __in    const   GUID    &Guid)
{
    return FormatA(
        "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        Guid.Data1,
        Guid.Data2,
        Guid.Data3,
        Guid.Data4[0],
        Guid.Data4[1],
        Guid.Data4[2],
        Guid.Data4[3],
        Guid.Data4[4],
        Guid.Data4[5],
        Guid.Data4[6],
        Guid.Data4[7]);
};

std::wstring UTILS::STR::GuidToStringW(
    __in    const   GUID    &Guid)
{
    return FormatW(
        L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        Guid.Data1,
        Guid.Data2,
        Guid.Data3,
        Guid.Data4[0],
        Guid.Data4[1],
        Guid.Data4[2],
        Guid.Data4[3],
        Guid.Data4[4],
        Guid.Data4[5],
        Guid.Data4[6],
        Guid.Data4[7]);
};