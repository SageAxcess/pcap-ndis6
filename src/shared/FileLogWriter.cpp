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

#include "CommonDefs.h"
#include "FileLogWriter.h"
#include "StrUtils.h"

void CFileLogWriter::InternalLogMessage(
    __in    const   std::wstring    &Message)
{
    DWORD       BytesWritten = 0;
    LPCVOID     Buffer = nullptr;
    DWORD       BufferSize = 0;
    std::string MessageA;
    
    RETURN_IF_FALSE(
        (FFileHandle != INVALID_HANDLE_VALUE) &&
        (Message.length() > 0));

    if (FIsUnicode)
    {
        Buffer = reinterpret_cast<LPCVOID>(Message.data());
        BufferSize = static_cast<DWORD>(Message.length() * sizeof(wchar_t));
    }
    else
    {
        MessageA = UTILS::STR::FormatA("%S", Message.c_str());
        Buffer = reinterpret_cast<LPCVOID>(MessageA.data());
        BufferSize = static_cast<DWORD>(MessageA.length());
    }

    WriteFile(
        FFileHandle,
        Buffer,
        BufferSize,
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

BOOL CFileLogWriter::GetIsUnicode() const
{
    BOOL    Result = FALSE;

    (const_cast<CFileLogWriter *>(this))->Enter();
    __try
    {
        Result = FIsUnicode;
    }
    __finally
    {
        (const_cast<CFileLogWriter *>(this))->Leave();
    }

    return Result;
};

void CFileLogWriter::SetIsUnicode(
    __in    const   BOOL    Value)
{
    Enter();
    __try
    {
        FIsUnicode = Value;
    }
    __finally
    {
        Leave();
    }
};