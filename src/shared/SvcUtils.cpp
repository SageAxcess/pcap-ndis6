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
#include "SvcUtils.h"

BOOL __stdcall UTILS::SVC::GetServiceConfig(
    __in    const   SC_HANDLE           ServiceHandle,
    __out           std::vector<UCHAR>  &ConfigBuffer)
{
    RETURN_VALUE_IF_FALSE(
        ServiceHandle != NULL,
        FALSE);

    DWORD   SizeRequired = 0;

    RETURN_VALUE_IF_FALSE(
        !QueryServiceConfigW(ServiceHandle, nullptr, 0, &SizeRequired),
        FALSE);
    RETURN_VALUE_IF_FALSE(
        GetLastError() == ERROR_INSUFFICIENT_BUFFER,
        FALSE);

    ConfigBuffer.resize(SizeRequired, 0);

    RETURN_VALUE_IF_FALSE(
        QueryServiceConfigW(
            ServiceHandle,
            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(&ConfigBuffer[0]),
            SizeRequired,
            &SizeRequired),
        FALSE);

    return TRUE;
};

std::wstring __stdcall UTILS::SVC::GetServiceImagePath(
    __in    const   SC_HANDLE   ServiceHandle)
{
    LPQUERY_SERVICE_CONFIGW ServiceConfig = nullptr;
    std::vector<UCHAR>      ConfigBuffer;

    RETURN_VALUE_IF_FALSE(
        GetServiceConfig(ServiceHandle, ConfigBuffer),
        L"");
    RETURN_VALUE_IF_FALSE(
        ConfigBuffer.size() >= sizeof(QUERY_SERVICE_CONFIGW),
        L"");

    ServiceConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(&ConfigBuffer[0]);

    return
        Assigned(ServiceConfig->lpBinaryPathName) ?
        std::wstring(ServiceConfig->lpBinaryPathName) :
        L"";
};

std::wstring __stdcall UTILS::SVC::GetServiceImagePath(
    __in    const   std::wstring    &ServiceName)
{
    RETURN_VALUE_IF_FALSE(
        ServiceName.length() > 0,
        L"");

    SC_HANDLE       SvcMgrHandle = NULL;
    SC_HANDLE       SvcHandle = NULL;
    std::wstring    Result;

    SvcMgrHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    RETURN_VALUE_IF_FALSE(
        SvcMgrHandle != NULL,
        L"");
    try
    {
        SvcHandle = OpenServiceW(
            SvcMgrHandle, 
            ServiceName.c_str(), 
            SERVICE_QUERY_CONFIG);
        if (SvcHandle != NULL)
        {
            try
            {
                Result = GetServiceImagePath(SvcHandle);
            }
            catch (...)
            {
            }
            CloseServiceHandle(SvcHandle);
        }
    }
    catch (...)
    {
    }
    CloseServiceHandle(SvcMgrHandle);

    return Result;
};

BOOL __stdcall UTILS::SVC::IsServiceInstalled(
    __in    const   std::wstring    &ServiceName)
{
    RETURN_VALUE_IF_FALSE(
        ServiceName.length() > 0,
        FALSE);

    SC_HANDLE   SvcMgrHandle = NULL;
    SC_HANDLE   SvcHandle = NULL;
    BOOL        Result = FALSE;

    SvcMgrHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    RETURN_VALUE_IF_FALSE(
        SvcMgrHandle != NULL,
        FALSE);
    __try
    {
        SvcHandle = OpenServiceW(
            SvcMgrHandle, 
            ServiceName.c_str(), 
            SERVICE_QUERY_CONFIG);
        if (SvcHandle != NULL)
        {
            Result = TRUE;
            CloseServiceHandle(SvcHandle);
        }
    }
    __finally
    {
        CloseServiceHandle(SvcMgrHandle);
    }

    return Result;
};
