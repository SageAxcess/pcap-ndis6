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

#include "LogWriter.h"
#include "CommonDefs.h"
#include "StrUtils.h"
#include "MiscUtils.h"
#include <vector>

std::wstring CLogWriter::InternalFormatMessage(
    __in    const   std::wstring    &Message)
{
    return UTILS::STR::FormatW(
        L"[%s]    %04x    %s",
        UTILS::STR::GetTimeStr().c_str(),
        GetCurrentThreadId(),
        Message.c_str());
};

void CLogWriter::InternalLogMessage(
    __in    const   std::wstring    &Message)
{
    UNREFERENCED_PARAMETER(Message);
};

void CLogWriter::InternalLogOSDetails()
{
    std::wstring Message = UTILS::STR::FormatW(
        L"%s\n",
        UTILS::MISC::GetOSVersionInfoStrFromRegistry().c_str());

    InternalLogMessage(Message);
};

CLogWriter::CLogWriter():
    CCSObject()
{
};

CLogWriter::~CLogWriter()
{
};

void CLogWriter::LogMessage(
    __in    const   std::wstring    &Message)
{
    std::wstring    FormattedMessage =
        InternalFormatMessage(Message);

    Enter();
    try
    {
        InternalLogMessage(FormattedMessage);
    }
    catch (...)
    {
    }
    Leave();
};

void CLogWriter::LogMessage(
    __in    LPCWSTR Message)
{
    Enter();
    try
    {
        InternalLogMessage(Message);
    }
    catch (...)
    {
    }
    Leave();
};

void CLogWriter::LogMessageFmt(
    __in    const   std::wstring    Format,
    __in                            ...)
{
    va_list ArgList;
    va_start(ArgList, Format);

    DWORD BufferChCnt = _vscwprintf(Format.c_str(), ArgList);

    if (BufferChCnt > 0)
    {
        std::vector<wchar_t>    Buffer;
        Buffer.resize(BufferChCnt + 2, 0);

        if (_vsnwprintf_s(
            &Buffer[0],
            BufferChCnt + 1,
            BufferChCnt + 1,
            Format.c_str(),
            ArgList) > 0)
        {
            LogMessage(&Buffer[0]);
        }
    }
    va_end(ArgList);
};

void CLogWriter::LogOSDetails()
{
    Enter();
    __try
    {
        InternalLogOSDetails();
    }
    __finally
    {
        Leave();
    }
};