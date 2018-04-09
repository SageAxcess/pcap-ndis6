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
// Author: Mikhail Burilov
// 
// Based on original WinPcap source code - https://www.winpcap.org/
// Copyright(c) 1999 - 2005 NetGroup, Politecnico di Torino(Italy)
// Copyright(c) 2005 - 2007 CACE Technologies, Davis(California)
// Filter driver based on Microsoft examples - https://github.com/Microsoft/Windows-driver-samples
// Copyrithg(C) 2015 Microsoft
// All rights reserved.
//////////////////////////////////////////////////////////////////////
#pragma once

#include <ndis.h>
#include "KmTypes.h"
#include "NdisMemoryManager.h"

///////////////////////////////////////////////////
// String helper functions
///////////////////////////////////////////////////

PUNICODE_STRING __stdcall CreateString(
    __in            PKM_MEMORY_MANAGER  MemoryManager,
    __in    const   char                *Str);

PUNICODE_STRING __stdcall CopyString(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PUNICODE_STRING     SourceString);

BOOLEAN __stdcall StringStartsWith(
    __in    PUNICODE_STRING     String,
    __in    PUNICODE_STRING     SubString);

void __stdcall FreeString(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PUNICODE_STRING     String);

PUNICODE_STRING __stdcall AllocateString(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    USHORT              StringLengthInBytes);

///////////////////////////////////////////////////
// Other helper functions
///////////////////////////////////////////////////

void __stdcall DriverSleep(long msec);

LARGE_INTEGER __stdcall KmGetTicks(
    __in    BOOLEAN SkipFrequency);

NTSTATUS __stdcall KmGetStartTime(
    __out   PKM_TIME    Time);

NTSTATUS __stdcall KmReferenceEvent(
    __in    HANDLE  EventObjectHandle,
    __out   PVOID   *EventObject);

int __stdcall CompareAdapterIds(
    __in    PPCAP_NDIS_ADAPTER_ID   AdapterId1,
    __in    PPCAP_NDIS_ADAPTER_ID   AdapterId2);

#define EqualAdapterIds(AdapterIdPtr1, AdapterIdPtr2) (CompareAdapterIds((AdapterIdPtr1), (AdapterIdPtr2)) == 0)

///////////////////////////////////////////////////
// Network eEvent info helpers
///////////////////////////////////////////////////
NTSTATUS __stdcall NetEventInfo_Allocate(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PNETWORK_EVENT_INFO *EventInfo);

NTSTATUS __stdcall NetEventInfo_FillFromBuffer(
    __in    PVOID               Buffer,
    __in    ULONG               BufferSize,
    __inout PNETWORK_EVENT_INFO EventInfo);

///////////////////////////////////////////////////
// IO buffer helpers
///////////////////////////////////////////////////

#define IOUTILS_PROBE_BUFFER_FLAG_READ	0x1
#define IOUTILS_PROBE_BUFFER_FLAG_WRITE	0x2
#define IOUTILS_PROBE_BUFFER_FLAG_BOTH	0x3
#define IOUTILS_PROBE_BUFFER_FLAG_MIN	IOUTILS_PROBE_BUFFER_FLAG_READ
#define IOUTILS_PROBE_BUFFER_FLAG_MAX	IOUTILS_PROBE_BUFFER_FLAG_BOTH
#define IOUtils_ValidateProbeFlags(Flags) \
    (((Flags) >= IOUTILS_PROBE_BUFFER_FLAG_MIN) && ((Flags) <= IOUTILS_PROBE_BUFFER_FLAG_MAX))


NTSTATUS __stdcall IOUtils_ProbeBuffer(
    __in    PVOID   Buffer,
    __in    ULONG   Length,
    __in    ULONG   Alignment,
    __in    ULONG   Flags);

NTSTATUS __stdcall IOUtils_ValidateAndGetIOBuffers(
    __in	PIRP	Irp,
    __out	PVOID	*InBuffer,
    __out	PULONG	InLength,
    __out	PVOID	*OutBuffer,
    __out	PULONG	OutLength);