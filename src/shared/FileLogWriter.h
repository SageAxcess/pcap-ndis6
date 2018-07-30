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

#include "LogWriter.h"

#define FILE_LOG_WRITER_EXCEPTION_FAILED_TO_CREATE_LOG_FILE L"File log writer exception: failed to create log file"

class CFileLogWriter :
    virtual public CLogWriter
{
private:
    HANDLE  FFileHandle = INVALID_HANDLE_VALUE;

protected:
    virtual void InternalLogMessage(
        __in    LPCWSTR Message);

    virtual BOOL InternalCreateLogFile(
        __in    const   std::wstring    &FileName);

public:
    explicit CFileLogWriter(
        __in        const   std::wstring    &FileName,
        __in_opt            LPVOID          Owner = nullptr);

    virtual ~CFileLogWriter();
};
