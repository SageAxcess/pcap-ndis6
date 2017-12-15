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
#include "RegUtils.h"

BOOL __stdcall UTILS::REG::ReadValue(
    __in            HKEY            Key,
    __in    const   std::wstring    &ValueName,
    __out           LPVOID          Buffer,
    __out           LPDWORD         BufferSize)
{
    RETURN_VALUE_IF_FALSE(
        (Key != NULL) &&
        (Assigned(Buffer)) &&
        (Assigned(BufferSize)),
        FALSE);

    DWORD   SizeRequired = 0;

    RETURN_VALUE_IF_FALSE(
        ReadValueSize(
            Key,
            ValueName,
            &SizeRequired),
        FALSE);

    RETURN_VALUE_IF_FALSE(
        SizeRequired <= *BufferSize,
        FALSE);

    return RegQueryValueExW(
        Key,
        ValueName.length() > 0 ? ValueName.c_str() : nullptr,
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(Buffer),
        BufferSize) == ERROR_SUCCESS;
};

BOOL __stdcall UTILS::REG::ReadValueSize(
    __in            HKEY            Key,
    __in    const   std::wstring    &ValueName,
    __out           LPDWORD         ValueSize)
{
    RETURN_VALUE_IF_FALSE(
        (Key != NULL) &&
        (Assigned(ValueSize)),
        FALSE);

    DWORD   DataSize = 0;

    if (RegQueryValueExW(
        Key,
        ValueName.length() > 0 ? ValueName.c_str() : nullptr,
        nullptr,
        nullptr,
        nullptr,
        &DataSize) == ERROR_SUCCESS)
    {
        *ValueSize = DataSize;
        return TRUE;
    }
    
    return FALSE;
};

BOOL __stdcall UTILS::REG::ReadDWORD(
    __in            HKEY            Key,
    __in    const   std::wstring    &ValueName,
    __out           LPDWORD         Value)
{
    DWORD   ValueSize = static_cast<DWORD>(sizeof(DWORD));

    return ReadValue(
        Key,
        ValueName,
        reinterpret_cast<LPVOID>(Value),
        &ValueSize);
};