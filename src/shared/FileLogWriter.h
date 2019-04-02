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

#include "LogWriter.h"
#include "CommonDefs.h"

class CFileLogWriter :
    virtual public CLogWriter
{
private:
    HANDLE  FFileHandle = INVALID_HANDLE_VALUE;
    BOOL    FIsUnicode = FALSE;

protected:
    virtual void InternalLogMessage(
        __in    const   std::wstring    &Message);

    virtual BOOL InternalCreateLogFile(
        __in    const   std::wstring    &FileName);

public:
    explicit CFileLogWriter(
        __in    const   std::wstring    &FileName);

    virtual ~CFileLogWriter();

    virtual BOOL GetIsUnicode() const;
    virtual void SetIsUnicode(
        __in    const   BOOL    Value);

    __declspec(property(get = GetIsUnicode, put = SetIsUnicode)) BOOL IsUnicode;
};
