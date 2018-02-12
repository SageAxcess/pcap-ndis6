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

#include "..\shared\CommonDefs.h"
#include "..\shared\FileLogWriter.h"
#include "Logging.h"
#include "..\shared\RegUtils.h"
#include "..\shared\StrUtils.h"

#include <vector>

CFileLogWriter  *LogWriter = nullptr;

namespace LOG
{
    DWORD __stdcall GetLoggingLevel(
        __in    const   HKEY            RootKey,
        __in    const   std::wstring    &SubKeyName,
        __in    const   std::wstring    &ValueName);
};

DWORD __stdcall LOG::GetLoggingLevel(
    __in    const   HKEY            RootKey,
    __in    const   std::wstring    &SubKeyName,
    __in    const   std::wstring    &ValueName)
{
    RETURN_VALUE_IF_FALSE(
        (RootKey != NULL) &&
        (SubKeyName.length() > 0),
        0);

    DWORD   Result = 0;
    HKEY    Key = NULL;
    LSTATUS Status = RegOpenKeyExW(
        RootKey,
        SubKeyName.c_str(),
        0,
        KEY_READ,
        &Key);
    RETURN_VALUE_IF_FALSE(
        (Key != NULL) &&
        (Status == ERROR_SUCCESS),
        0);
    __try
    {
        if (!UTILS::REG::ReadDWORD(
            Key,
            ValueName,
            &Result))
        {
            Result = 0;
        }
    }
    __finally
    {
        RegCloseKey(Key);
    }

    return Result;
};

BOOL __stdcall LOG::Initialize(
    __in    const   std::wstring    &LogFileName,
    __in    const   HKEY            RegRootKey,
    __in    const   std::wstring    &RegSubKeyName,
    __in    const   std::wstring    &RegValueName)
{
    RETURN_VALUE_IF_FALSE(
        (LogFileName.length() > 0) &&
        (RegRootKey != NULL) &&
        (RegSubKeyName.length() > 0),
        FALSE);

    DWORD   LoggingLevel = GetLoggingLevel(
        RegRootKey,
        RegSubKeyName,
        RegValueName);

    BOOL    Result = FALSE;
    if (LoggingLevel != 0)
    {
        try
        {
            LogWriter = new CFileLogWriter(LogFileName);
            Result = TRUE;
        }
        catch (...)
        {
            Result = FALSE;
        };
    }

    return Result;
};

void __stdcall LOG::Finalize()
{
    if (Assigned(LogWriter))
    {
        delete LogWriter;
    }
};

void __stdcall LOG::LogMessage(
    __in    const   std::wstring    &Message)
{
    if (Assigned(LogWriter))
    {
        LogWriter->LogMessage(Message);
    }
};

void __stdcall LOG::LogMessageFmt(
    __in    const   std::wstring    FormatStr,
    __in                            ...)
{
    va_list ArgList;
    va_start(ArgList, FormatStr);

    RETURN_IF_FALSE(Assigned(LogWriter));

    DWORD BufferChCnt = _vscwprintf(FormatStr.c_str(), ArgList);

    if (BufferChCnt > 0)
    {
        std::vector<wchar_t>    Buffer;
        Buffer.resize(BufferChCnt + 2, 0);

        if (_vsnwprintf_s(
            &Buffer[0],
            BufferChCnt + 1,
            BufferChCnt + 1,
            FormatStr.c_str(),
            ArgList) > 0)
        {
            LogMessage(std::wstring(&Buffer[0]));
        }
    }
    va_end(ArgList);
};