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

namespace UTILS
{
    namespace LISTS
    {
        #define LIST_EXCEPTION_BAD_LIST_ENTRY       L"List exception: bad list entry"
        #define LIST_EXCEPTION_INVALID_PARAMETER    L"List exception: invalid parameter(s)"

        typedef struct _ENTRY
        {
            //  Pointer to next list entry
            _ENTRY *Flink;

            //  Pointer to previous list entry
            _ENTRY *Blink;

        } ENTRY, *PENTRY, *LPENTRY;

        __forceinline void Initialize(
            __in    LPENTRY ListHead);

        __forceinline BOOL IsEmpty(
            __in    LPENTRY ListHead);

        __forceinline LPENTRY RemoveHead(
            __in    LPENTRY ListHead);

        template <typename T>
        __forceinline T * RemoveHeadAs(
            __in    LPENTRY ListHead);

        __forceinline LPENTRY RemoveTail(
            __in    LPENTRY ListHead);

        __forceinline BOOL RemoveEntry(
            __in    LPENTRY Entry);

        __forceinline BOOL InsertHead(
            __in    LPENTRY ListHead,
            __in    LPENTRY Entry);

        __forceinline BOOL InsertTail(
            __in    LPENTRY ListHead,
            __in    LPENTRY Entry);
    };
};
