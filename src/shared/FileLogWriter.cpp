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

#include "CommonDefs.h"
#include "FileLogWriter.h"


void CFileLogWriter::InternalLogMessage(
    __in    LPCWSTR Message)
{
    RETURN_IF_FALSE(
        (FFileHandle != INVALID_HANDLE_VALUE) &&
        (Assigned(Message)));

    DWORD   MessageLength = static_cast<DWORD>(wcslen(Message));
    DWORD   BytesWritten;
    WriteFile(
        FFileHandle,
        reinterpret_cast<LPCVOID>(Message),
        MessageLength * sizeof(wchar_t),
        &BytesWritten,
        nullptr);
};

BOOL CFileLogWriter::InternalCreateLogFile(
    __in    const   std::wstring    &FileName)
{
    RETURN_VALUE_IF_FALSE(
        FileName.length() > 0,
        FALSE);

    FFileHandle = CreateFileW(
        FileName.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        FILE_FLAG_WRITE_THROUGH,
        NULL);

    return FFileHandle != INVALID_HANDLE_VALUE;
};

CFileLogWriter::CFileLogWriter(
    __in    const   std::wstring    &FileName):
    CLogWriter()
{
    if (!InternalCreateLogFile(FileName))
    {
        throw L"Failed to create log file";
    }
};

CFileLogWriter::~CFileLogWriter()
{
    Enter();
    try
    {
        if (FFileHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(FFileHandle);
        }
    }
    catch (...)
    {
    }
    Leave();
};


