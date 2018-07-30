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

#include "CSObject.h"

#include <Windows.h>
#include <string>

class CLogWriter:
    virtual public CCSObject
{
protected:
    virtual std::wstring InternalFormatMessage(
        __in    const   std::wstring    &Message);

    virtual void InternalLogMessage(
        __in    LPCWSTR Message);

    virtual void InternalLogOSDetails();

public:
    explicit CLogWriter(
        __in_opt    LPVOID  Owner = nullptr);
    virtual ~CLogWriter();

    virtual void LogMessage(
        __in    const   std::wstring    &Message);
    virtual void LogMessage(
        __in    LPCWSTR Message);

    virtual void LogMessageFmt(
        __in    const   std::wstring    Format,
        __in                            ...);
};
