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

#include <ntstrsafe.h>

#include "filter.h"
#include "KernelUtil.h"

///////////////////////////////////////////////////
// Lock helper functions
///////////////////////////////////////////////////

NDIS_SPIN_LOCK *CreateSpinLock()
{
	NDIS_SPIN_LOCK *lock = (NDIS_SPIN_LOCK*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(NDIS_SPIN_LOCK));
	NdisAllocateSpinLock(lock);
	return lock;
}

void FreeSpinLock(PNDIS_SPIN_LOCK lock)
{
	FILTER_FREE_LOCK(lock);
	FILTER_FREE_MEM(lock);
}


///////////////////////////////////////////////////
// String helper functions
///////////////////////////////////////////////////

UNICODE_STRING* CreateString(const char* str)
{
	UNICODE_STRING* string = (UNICODE_STRING*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(UNICODE_STRING));
	NdisInitializeString(string, (unsigned char*)str);
	return string;
}

UNICODE_STRING* CopyString(PUNICODE_STRING string)
{
	UNICODE_STRING* res = (UNICODE_STRING*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(UNICODE_STRING));
	res->MaximumLength = string->MaximumLength;
	res->Buffer = FILTER_ALLOC_MEM(FilterDriverObject, string->MaximumLength);
	RtlUnicodeStringCopy(res, string);
	return res;
}

void FreeString(UNICODE_STRING* string)
{
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
