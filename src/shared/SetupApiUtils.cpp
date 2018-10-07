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

#include "CommonDefs.h"
#include "SetupApiUtils.h"
#include "MiscUtils.h"

#include <SetupAPI.h>

BOOL UTILS::SETUP_API::InstallOEMInf(
    __in    const   std::wstring    &InfFileName)
{
    std::wstring    InfFilePath;

    RETURN_VALUE_IF_FALSE(
        InfFileName.c_str() > 0,
        FALSE);
    
    InfFilePath = UTILS::MISC::ExtractFilePath(InfFileName);

    return SetupCopyOEMInfW(
        InfFileName.c_str(),
        InfFilePath.c_str(),
        SPOST_PATH,
        0,
        nullptr,
        0,
        nullptr,
        nullptr);
};

BOOL UTILS::SETUP_API::UninstallOEMInf(
    __in    const   std::wstring    &InfFileName)
{
    std::wstring    Tmp;

    RETURN_VALUE_IF_FALSE(
        InfFileName.length() > 0,
        FALSE);

    Tmp = UTILS::MISC::ExtractFilePath(InfFileName);
    if (Tmp.length() > 0)
    {
        Tmp = UTILS::MISC::ExtractFileName(InfFileName);
    }
    else
    {
        Tmp = InfFileName;
    }

    return SetupUninstallOEMInfW(
        Tmp.c_str(),
        0,
        nullptr);
};
