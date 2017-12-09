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

#include <vector>

CFileLogWriter  *LogWriter = nullptr;

void __stdcall LOG::Initialize(
    __in    const   std::wstring    &FileName)
{
    LogWriter = new CFileLogWriter(FileName);
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
            if (Assigned(LogWriter))
            {
                LogWriter->LogMessage(&Buffer[0]);
            }
        }
    }
    va_end(ArgList);
};