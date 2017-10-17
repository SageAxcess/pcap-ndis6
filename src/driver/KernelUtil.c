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

#include <ntstatus.h>
#include <ntstrsafe.h>

#include "filter.h"
#include "KernelUtil.h"
#include <flt_dbg.h>

///////////////////////////////////////////////////
// Lock helper functions
///////////////////////////////////////////////////

NDIS_SPIN_LOCK *CreateSpinLock()
{
	NDIS_SPIN_LOCK *lock = (NDIS_SPIN_LOCK*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(NDIS_SPIN_LOCK));
	NdisZeroMemory(lock, sizeof(NDIS_SPIN_LOCK));
	NdisAllocateSpinLock(lock);
	return lock;
}

void FreeSpinLock(PNDIS_SPIN_LOCK lock)
{
	if(!lock)
	{
		return;
	}
	FILTER_FREE_LOCK(lock);
	FILTER_FREE_MEM(lock);
}


///////////////////////////////////////////////////
// String helper functions
///////////////////////////////////////////////////

UNICODE_STRING* CreateString(const char* str)
{
	DEBUGP(DL_TRACE, "===>CreateString(%s)...\n", str);
	if(!str)
	{
		return NULL;
	}
	UNICODE_STRING* string = (UNICODE_STRING*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(UNICODE_STRING));
	if(!string)
	{
		return NULL;
	}
	NdisZeroMemory(string, sizeof(UNICODE_STRING));
	NdisInitializeString(string, (unsigned char*)str);

	DEBUGP(DL_TRACE, "<===CreateString\n");
	return string;
}

UNICODE_STRING* CopyString(PUNICODE_STRING string)
{
	if(!string)
	{
		return NULL;
	}

	UNICODE_STRING* res = (UNICODE_STRING*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(UNICODE_STRING));
	if(!res)
	{
		return NULL;
	}
	res->Length = 0;
	res->MaximumLength = string->MaximumLength;
	res->Buffer = FILTER_ALLOC_MEM(FilterDriverObject, string->MaximumLength);
	RtlUnicodeStringCopy(res, string);
	return res;
}

void FreeString(UNICODE_STRING* string)
{
	if(!string)
	{
		return;
	}

	NdisFreeString(*string);
	FILTER_FREE_MEM(string);
}

///////////////////////////////////////////////////
// Other helper functions
///////////////////////////////////////////////////

void DriverSleep(long msec)
{
	LARGE_INTEGER interval;
	interval.QuadPart = (__int64)msec * 10000;

	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}
