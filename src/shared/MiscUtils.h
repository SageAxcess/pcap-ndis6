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

#include <Windows.h>
#include <IPHlpApi.h>
#include <string>

namespace UTILS
{
    namespace MISC
    {
        typedef struct _OS_DETAILS
        {
            wchar_t ProductName;
        } OS_DETAILS, *POS_DETAILS, *LPOS_DETAILS;

        std::wstring GetModuleName(
            __in    const   HMODULE ModuleHandle);

        std::wstring ExtractFileName(
            __in    const   std::wstring    &FullFileName);

        std::wstring ExtractFileNameEx(
            __in    const   std::wstring    &FullFileName,
            __in    const   wchar_t         Delimiter = L'\\');

        std::wstring ExtractFilePath(
            __in    const   std::wstring    &FullFileName);

        std::wstring ExtractFilePathEx(
            __in    const   std::wstring    &FullFileName,
            __in    const   wchar_t         Delimiter = L'\\');

        std::wstring ExtractFileExtension(
            __in    const   std::wstring    &FileName);

        std::wstring ChangeFileExtension(
            __in    const   std::wstring    &FileName,
            __in    const   std::wstring    &NewExtension);

        std::wstring GetApplicationFileName();

        std::wstring GetApplicationFilePath();

        std::wstring GetOsVersionStr();

        void GetOSVersionInfo(
            __out   LPOSVERSIONINFOEXW  VersionInfo);

        std::wstring GetOSVersionInfoStrFromRegistry();

        std::wstring GetFileVersion(
            __in    const   std::wstring    &FileName);

        std::wstring ExpandEnvVarsW(
            __in    const   std::wstring    &String);

        std::string ExpandEnvVarsA(
            __in    const   std::string &String);

        std::wstring NormalizeFileNameW(
            __in    const   std::wstring    &FileName);

        PIP_ADAPTER_INFO GetAdaptersInformation();

        BOOL StringToIpAddressV4A(
            __in    const   std::string &String,
            __out           PULONG      Address);

    };
};