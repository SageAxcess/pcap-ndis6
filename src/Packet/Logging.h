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

#include <string>

namespace LOG
{
    BOOL __stdcall Initialize(
        __in    const   std::wstring    &AppFileName,
        __in    const   HKEY            RegRootKey,
        __in    const   std::wstring    &RegSubKeyName,
        __in    const   std::wstring    &RegValueName);

    void __stdcall Finalize();

    void __stdcall LogMessage(
        __in    const   std::wstring    &Message);

    void __stdcall LogMessageFmt(
        __in    const   std::wstring    FormatStr,
        __in                            ...);
};