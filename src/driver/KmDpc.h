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

#ifndef KM_DPC_H
#define KM_DPC_H

#include "KmMemoryManager.h"

NTSTATUS __stdcall Km_Dpc_Execute(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PKDPC

#endif