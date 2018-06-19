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

#ifndef PACKET_H
#define PACKET_H

#include "KmMemoryManager.h"
#include "KmMemoryPool.h"
#include "KmTypes.h"

NTSTATUS __stdcall Packet_Reference(
    __in    PPACKET Packet);

NTSTATUS __stdcall Packet_Dereference(
    __in    PPACKET Packet);

NTSTATUS __stdcall Packet_Allocate(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    SIZE_T              PacketDataSize,
    __out   PPACKET             *Packet);

NTSTATUS __stdcall Packet_AllocateFromPool(
    __in    HANDLE  MemoryPool,
    __in    SIZE_T  PacketDataSize,
    __out   PPACKET *Packet);

NTSTATUS __stdcall Packet_ReleaseEx(
    __in        PPACKET Packet,
    __in_opt    BOOLEAN Force);

SIZE_T __stdcall Packet_CalcRequiredMemorySize(
    __in    SIZE_T  PacketDataSize);

#define Packet_Release(Packet)  Packet_ReleaseEx(Packet, FALSE)

#endif