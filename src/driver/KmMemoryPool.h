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

#include "KmMemoryManager.h"

NTSTATUS __stdcall Km_MP_Initialize(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    ULONG               BlockSize,
    __in    ULONG               InitialBlockCount,
    __in    BOOLEAN             FixedSize,
    __out   PHANDLE             InstanceHandle);

NTSTATUS __stdcall Km_MP_Finalize(
    __in    HANDLE  Instance);

NTSTATUS __stdcall Km_MP_Allocate(
    __in    HANDLE  Instance,
    __out   PVOID   *Block);

NTSTATUS __stdcall Km_MP_Release(
    __in    PVOID   Block);