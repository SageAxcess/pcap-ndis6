//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 ChangeDynamix, LLC
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#pragma once

#include <Windows.h>
#include <string>

namespace UTILS
{
    namespace SETUP_API
    {
        BOOL InstallOEMInf(
            __in    const   std::wstring    &InfFileName);

        BOOL UninstallOEMInf(
            __in    const   std::wstring    &InfFileName);
    }
};
