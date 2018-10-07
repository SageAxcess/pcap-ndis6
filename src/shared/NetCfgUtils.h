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
#include <netcfgx.h>
#include <string>

namespace UTILS
{
    namespace NET_CFG
    {
        HRESULT __stdcall GetNetCfg(
            __out               INetCfg         **NetCfg,
            __out_opt           INetCfgLock     **NetCfgLock,
            __in_opt            DWORD           AcquireTimeout,
            __in_opt    const   std::wstring    &LockedByName);

        HRESULT __stdcall ReleaseNetCfg(
            __in        INetCfg     *NetCfg,
            __in_opt    INetCfgLock *NetCfgLock);

        HRESULT __stdcall InstallComponent(
            __in            INetCfg         *NetCfg,
            __in    const   std::wstring    &ComponentId,
            __in    const   GUID            &ClassGuid);

        HRESULT __stdcall UninstallComponent(
            __in            INetCfg         *NetCfg,
            __in    const   std::wstring    &ComponentId);

        HRESULT __stdcall IsComponentInstalled(
            __in            INetCfg         *NetCfg,
            __in    const   std::wstring    &ComponentId,
            __out           BOOL            *IsInstalled);
    };
};