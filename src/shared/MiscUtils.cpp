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

#include <WS2tcpip.h>

#include "CommonDefs.h"
#include "StrUtils.h"
#include "MiscUtils.h"

#include <vector>

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

std::wstring UTILS::MISC::ExtractFileName(
    __in    const   std::wstring    &FullFileName)
{
    return ExtractFileNameEx(FullFileName);
};

std::wstring UTILS::MISC::ExtractFileNameEx(
    __in    const   std::wstring    &FullFileName,
    __in    const   wchar_t         Delimiter)
{
    RETURN_VALUE_IF_FALSE(
        (Delimiter == static_cast<wchar_t>(0)) ||
        (FullFileName.length() < 2),
        L"");

    for (SSIZE_T k = static_cast<SSIZE_T>(FullFileName.length()); k >= 0; k--)
    {
        if (FullFileName[k] == Delimiter)
        {
            return FullFileName.substr(static_cast<size_t>(k + 1));
        }
    }

    return FullFileName;
};

std::wstring UTILS::MISC::ExtractFilePath(
    __in    const   std::wstring    FullFileName)
{
    return ExtractFilePathEx(FullFileName);
};

std::wstring UTILS::MISC::ExtractFilePathEx(
    __in    const   std::wstring    &FullFileName,
    __in    const   wchar_t         Delimiter)
{
    RETURN_VALUE_IF_FALSE(
        (Delimiter == static_cast<wchar_t>(0)) ||
        (FullFileName.length() < 2),
        L"");

    for (SSIZE_T k = static_cast<SSIZE_T>(FullFileName.length()); k >= 0; k--)
    {
        if (FullFileName[k] == Delimiter)
        {
            return FullFileName.substr(0, static_cast<size_t>(k + 1));
        }
    }

    return FullFileName;
};

std::wstring UTILS::MISC::ExtractFileExtension(
    __in    const   std::wstring    &FileName)
{

    for (SSIZE_T k = static_cast<SSIZE_T>(FileName.length()); k >= 0; k--)
    {
        if (FileName[k] == L'.')
        {
            return FileName.substr(static_cast<size_t>(k));
        }
    };

    return L"";
};

std::wstring UTILS::MISC::ChangeFileExtension(
    __in    const   std::wstring    &FileName,
    __in    const   std::wstring    &NewExtension)
{
    RETURN_VALUE_IF_FALSE(
        FileName.length() > 0,
        NewExtension);

    std::wstring    CurrentExtension = ExtractFileExtension(FileName);
    RETURN_VALUE_IF_TRUE(
        CurrentExtension.length() == 0,
        FileName + NewExtension);

    return FileName.substr(0, FileName.length() - CurrentExtension.length()) + NewExtension;
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

std::wstring UTILS::MISC::GetFileVersion(
    __in    const   std::wstring    &FileName)
{
    UINT	dwBytes;
    PVOID	lpBuffer;

    DWORD               VersionInfoSize = 0;
    DWORD               VersionInfoHandle = 0;
    std::vector<char>   VersionInfoBuffer;
    UINT                TranslationSize = 0;
    std::wstring        SubBlockPath;

    // Structure used to store enumerated languages and code pages.
    struct LANGANDCODEPAGE
    {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    VersionInfoSize = GetFileVersionInfoSizeW(
        FileName.c_str(),
        &VersionInfoHandle);

    RETURN_VALUE_IF_FALSE(
        VersionInfoSize > 0,
        L"");

    VersionInfoBuffer.resize(VersionInfoSize, (char)0);

    RETURN_VALUE_IF_FALSE(
        GetFileVersionInfoW(
            FileName.c_str(),
            0,
            VersionInfoSize,
            reinterpret_cast<LPVOID>(&VersionInfoBuffer[0])),
        L"");

    RETURN_VALUE_IF_FALSE(
        VerQueryValueW(
            reinterpret_cast<LPVOID>(&VersionInfoBuffer[0]),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<LPVOID *>(&lpTranslate),
            &TranslationSize),
        L"");

    SubBlockPath = UTILS::STR::FormatW(
        L"\\StringFileInfo\\%04x%04x\\FileVersion",
        lpTranslate->wLanguage,
        lpTranslate->wCodePage);

    RETURN_VALUE_IF_FALSE(
        VerQueryValueW(
            reinterpret_cast<LPVOID>(&VersionInfoBuffer[0]),
            SubBlockPath.c_str(),
            &lpBuffer,
            &dwBytes),
        L"");

    return std::wstring(reinterpret_cast<PWCHAR>(lpBuffer));
};

std::wstring UTILS::MISC::ExpandEnvVarsW(
    __in    const   std::wstring    &String)
{
    DWORD                   CharsRequired = 0;
    std::vector<wchar_t>    Buffer;

    RETURN_VALUE_IF_FALSE(
        String.length() > 0,
        L"");

    CharsRequired = ExpandEnvironmentStringsW(String.c_str(), nullptr, 0);

    RETURN_VALUE_IF_FALSE(
        CharsRequired > 0,
        L"");

    Buffer.resize(CharsRequired + 1, (wchar_t)0);

    CharsRequired = ExpandEnvironmentStringsW(
        String.c_str(),
        reinterpret_cast<LPWSTR>(&Buffer[0]),
        CharsRequired + 1);

    if (CharsRequired > 0)
    {
        return std::wstring(&Buffer[0]);
    }

    return L"";
};

std::string UTILS::MISC::ExpandEnvVarsA(
    __in    const   std::string &String)
{
    DWORD               CharsRequired = 0;
    std::vector<char>   Buffer;

    RETURN_VALUE_IF_FALSE(
        String.length() > 0,
        "");

    CharsRequired = ExpandEnvironmentStringsA(String.c_str(), nullptr, 0);

    RETURN_VALUE_IF_FALSE(
        CharsRequired > 0,
        "");

    Buffer.resize(CharsRequired + 1, (char)0);

    CharsRequired = ExpandEnvironmentStringsA(
        String.c_str(),
        reinterpret_cast<LPSTR>(&Buffer[0]),
        CharsRequired + 1);

    if (CharsRequired > 0)
    {
        return std::string(&Buffer[0]);
    }

    return "";
};

std::wstring UTILS::MISC::NormalizeFileNameW(
    __in    const   std::wstring    &FileName)
{
    return FileName;
};

PIP_ADAPTER_INFO UTILS::MISC::GetAdaptersInformation()
{
    IP_ADAPTER_INFO     Tmp = { 0, };
    PIP_ADAPTER_INFO    Result = nullptr;
    ULONG               Size = 0;

    RETURN_VALUE_IF_FALSE(
        GetAdaptersInfo(&Tmp, &Size) == ERROR_BUFFER_OVERFLOW,
        nullptr);

    Result = reinterpret_cast<PIP_ADAPTER_INFO>(malloc(Size));
    RETURN_VALUE_IF_FALSE(
        Assigned(Result),
        nullptr);

    if (GetAdaptersInfo(Result, &Size) != ERROR_SUCCESS)
    {
        free(reinterpret_cast<void *>(Result));
        Result = nullptr;
    }

    return Result;
};

BOOL UTILS::MISC::StringToIpAddressV4A(
    __in    const   std::string &String,
    __out           PULONG      Address)
{
    ADDRINFOA   Hint = { 0, };
    PADDRINFOA  AddrInfo = nullptr;

    RETURN_VALUE_IF_FALSE(
        String.length() > 0,
        FALSE);

    Hint.ai_family = AF_UNSPEC;
    Hint.ai_socktype = SOCK_DGRAM;
    Hint.ai_protocol = IPPROTO_UDP;

    if (GetAddrInfoA(String.c_str(), nullptr, &Hint, &AddrInfo) == 0)
    {
        BOOL    Result = FALSE;

        __try
        {
            //if (AddrInfo->ai_addrlen == sizeof(ULONG)) // Doesn't work, ai_addrlen is always 16
            //{
                RtlCopyMemory(
                    Address,
                    AddrInfo->ai_addr->sa_data,
                    sizeof(ULONG));

				Result = *Address != 0;
            //}
        }
        __finally
        {
            FreeAddrInfoA(AddrInfo);
        }

        return Result;
    }

    return FALSE;
};