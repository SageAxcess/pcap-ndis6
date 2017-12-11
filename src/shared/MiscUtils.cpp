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
#include "MiscUtils.h"
#include "StrUtils.h"

std::wstring UTILS::MISC::GetModuleName(
    __in    const   HMODULE ModuleHandle)
{
    std::wstring    Result;
    wchar_t         Buffer[MAX_PATH + 2];

    RtlZeroMemory(Buffer, sizeof(Buffer));

    DWORD   Len = GetModuleFileNameW(ModuleHandle, Buffer, MAX_PATH);
    RETURN_VALUE_IF_FALSE(
        Len > 0,
        L"");

    Result.resize(Len + 1, (wchar_t)0);

    RtlCopyMemory(&Result[0], Buffer, Len * sizeof(wchar_t));

    return Result;
};

std::wstring UTILS::MISC::GetApplicationFileName()
{
    return GetModuleName(NULL);
};

std::wstring UTILS::MISC::GetOsVersionStr()
{
    OSVERSIONINFOEXW    Info;

    RtlZeroMemory(&Info, sizeof(Info));

    GetOSVersionInfo(&Info);

    return UTILS::STR::FormatW(
        L"OS: %d.%d(%s%s) Build %d",
        Info.dwMajorVersion,
        Info.dwMinorVersion,
        Info.wServicePackMajor,
        Info.wServicePackMinor,
        Info.dwBuildNumber);
};

void UTILS::MISC::GetOSVersionInfo(
    __out   LPOSVERSIONINFOEXW  VersionInfo)
{
    OSVERSIONINFOEXW    OsVersionInfo;

    RETURN_IF_FALSE(Assigned(VersionInfo));

    RtlZeroMemory(&OsVersionInfo, sizeof(OsVersionInfo));
    OsVersionInfo.dwOSVersionInfoSize = sizeof(OsVersionInfo);
    
    for (OsVersionInfo.dwMajorVersion = 0;
         OsVersionInfo.dwMajorVersion < MAXWORD;
         OsVersionInfo.dwMajorVersion++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_MAJORVERSION, VER_EQUAL));
    }

    for (OsVersionInfo.dwMinorVersion = 0;
         OsVersionInfo.dwMinorVersion < MAXWORD;
         OsVersionInfo.dwMinorVersion++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_MINORVERSION, VER_EQUAL));
    }

    for (OsVersionInfo.wServicePackMajor = 0;
         OsVersionInfo.wServicePackMajor < MAXWORD;
         OsVersionInfo.wServicePackMajor++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_SERVICEPACKMAJOR, VER_EQUAL));
    }

    for (OsVersionInfo.wServicePackMinor = 0;
         OsVersionInfo.wServicePackMinor < MAXWORD;
         OsVersionInfo.wServicePackMinor++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_SERVICEPACKMINOR, VER_EQUAL));
    }

    for (OsVersionInfo.dwBuildNumber = 0;
         OsVersionInfo.dwBuildNumber < MAXDWORD;
         OsVersionInfo.dwBuildNumber++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_BUILDNUMBER, VER_EQUAL));
    }

    for (OsVersionInfo.dwPlatformId = 0;
         OsVersionInfo.dwPlatformId < MAXDWORD;
         OsVersionInfo.dwPlatformId++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_PLATFORMID, VER_EQUAL));
    }

    for (OsVersionInfo.wSuiteMask = 0;
         OsVersionInfo.wSuiteMask < MAXWORD;
         OsVersionInfo.wSuiteMask++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_SUITENAME, VER_EQUAL));
    }

    for (OsVersionInfo.wProductType = 0;
         OsVersionInfo.wProductType < MAXWORD;
         OsVersionInfo.wProductType++)
    {
        BREAK_IF_TRUE(
            VerifyVersionInfoW(&OsVersionInfo, VER_PRODUCT_TYPE, VER_EQUAL));
    }

    RtlCopyMemory(
        VersionInfo, 
        &OsVersionInfo, 
        sizeof(OSVERSIONINFOEXW));
};