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
#include "NetCfgUtils.h"

HRESULT __stdcall UTILS::NET_CFG::GetNetCfg(
    __out               INetCfg         **NetCfg,
    __out_opt           INetCfgLock     **NetCfgLock,
    __in_opt            DWORD           AcquireTimeout,
    __in_opt    const   std::wstring    &LockedByName)
{
    HRESULT     Result = S_OK;
    INetCfg     *Cfg = nullptr;
    INetCfgLock *CfgLock = nullptr;

    RETURN_VALUE_IF_FALSE(
        Assigned(NetCfg),
        E_INVALIDARG);
    if (Assigned(NetCfgLock))
    {
        RETURN_VALUE_IF_FALSE(
            LockedByName.length() > 0,
            E_INVALIDARG);
    }

    Result = CoCreateInstance(
        CLSID_CNetCfg,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_INetCfg,
        reinterpret_cast<void **>(&Cfg));
    RETURN_VALUE_IF_FALSE(
        SUCCEEDED(Result),
        Result);
    __try
    {
        if (Assigned(NetCfgLock))
        {
            Result = Cfg->QueryInterface(
                IID_INetCfgLock,
                reinterpret_cast<void **>(&CfgLock));
            LEAVE_IF_FALSE(SUCCEEDED(Result));
            __try
            {
                Result = CfgLock->AcquireWriteLock(
                    AcquireTimeout,
                    LockedByName.c_str(),
                    nullptr);
            }
            __finally
            {
                if (!SUCCEEDED(Result))
                {
                    CfgLock->Release();
                }
            }
        }
    }
    __finally
    {
        if (!SUCCEEDED(Result))
        {
            Cfg->Release();
        }
    }

    RETURN_VALUE_IF_FALSE(
        SUCCEEDED(Result),
        Result);

    Result = Cfg->Initialize(nullptr);
    if (!SUCCEEDED(Result))
    {
        if (Assigned(CfgLock))
        {
            CfgLock->ReleaseWriteLock();
            CfgLock->Release();
        }

        Cfg->Release();
    }
    else
    {
        if (Assigned(NetCfgLock))
        {
            *NetCfgLock = CfgLock;
        }

        *NetCfg = Cfg;
    }

    return Result;
};

HRESULT __stdcall UTILS::NET_CFG::ReleaseNetCfg(
    __in        INetCfg     *NetCfg,
    __in_opt    INetCfgLock *NetCfgLock)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(NetCfg),
        E_INVALIDARG);

    if (Assigned(NetCfgLock))
    {
        NetCfgLock->ReleaseWriteLock();
        NetCfgLock->Release();
    }

    NetCfg->Uninitialize();

    NetCfg->Release();

    return S_OK;
};

HRESULT __stdcall UTILS::NET_CFG::InstallComponent(
    __in            INetCfg         *NetCfg,
    __in    const   std::wstring    &ComponentId,
    __in    const   GUID            &ClassGuid)
{
    HRESULT             Result = S_OK;
    INetCfgClassSetup   *NetCfgClassSetup = nullptr;
    INetCfgComponent    *NetCfgComponent = nullptr;
    OBO_TOKEN           Token;

    RETURN_VALUE_IF_FALSE(
        (Assigned(NetCfg)) &&
        (ComponentId.length() > 0),
        E_INVALIDARG);

    Result = NetCfg->QueryNetCfgClass(
        &ClassGuid,
        IID_INetCfgClassSetup,
        reinterpret_cast<void **>(&NetCfgClassSetup));
    RETURN_VALUE_IF_FALSE(
        SUCCEEDED(Result),
        Result);
    __try
    {
        RtlZeroMemory(&Token, sizeof(Token));

        Token.Type = OBO_USER;

        Result = NetCfgClassSetup->Install(
            ComponentId.c_str(),
            &Token,
            0,
            0,
            nullptr,
            nullptr,
            &NetCfgComponent);
        LEAVE_IF_FALSE(SUCCEEDED(Result));
        __try
        {
            Result = NetCfg->Apply();
        }
        __finally
        {
            NetCfgComponent->Release();
        }
    }
    __finally
    {
        NetCfgClassSetup->Release();
    }

    return Result;
};

HRESULT __stdcall UTILS::NET_CFG::UninstallComponent(
    __in            INetCfg         *NetCfg,
    __in    const   std::wstring    &ComponentId)
{
    HRESULT             Result = S_OK;
    INetCfgComponent    *NetCfgComponent = nullptr;
    INetCfgClassSetup   *NetCfgClassSetup = nullptr;
    GUID                ClassGuid;
    OBO_TOKEN           Token;

    RETURN_VALUE_IF_FALSE(
        (Assigned(NetCfg)) &&
        (ComponentId.length() > 0),
        E_INVALIDARG);

    Result = NetCfg->FindComponent(
        ComponentId.c_str(),
        &NetCfgComponent);
    RETURN_VALUE_IF_FALSE(
        SUCCEEDED(Result),
        Result);
    __try
    {
        Result = NetCfgComponent->GetClassGuid(&ClassGuid);
        LEAVE_IF_FALSE(SUCCEEDED(Result));

        Result = NetCfg->QueryNetCfgClass(
            &ClassGuid,
            IID_INetCfgClassSetup,
            reinterpret_cast<void **>(&NetCfgClassSetup));
        LEAVE_IF_FALSE(SUCCEEDED(Result));
        __try
        {
            RtlZeroMemory(&Token, sizeof(Token));

            Token.Type = OBO_USER;

            Result = NetCfgClassSetup->DeInstall(NetCfgComponent, &Token, nullptr);
        }
        __finally
        {
            NetCfgClassSetup->Release();
        }
    }
    __finally
    {
        NetCfgComponent->Release();
    }

    return Result;
};

HRESULT __stdcall UTILS::NET_CFG::IsComponentInstalled(
    __in            INetCfg         *NetCfg,
    __in    const   std::wstring    &ComponentId,
    __out           BOOL            *IsInstalled)
{
    HRESULT             Result = S_OK;
    INetCfgComponent    *NetCfgComponent = nullptr;
    
    RETURN_VALUE_IF_FALSE(
        (Assigned(NetCfg)) &&
        (ComponentId.length() > 0) &&
        (Assigned(IsInstalled)),
        E_INVALIDARG);

    Result = NetCfg->FindComponent(
        ComponentId.c_str(),
        &NetCfgComponent);
    if (SUCCEEDED(Result))
    {
        *IsInstalled = TRUE;
        NetCfgComponent->Release();
    }
    else
    {
        *IsInstalled = FALSE;
    }

    return Result;
};