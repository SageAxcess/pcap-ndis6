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
// All rights reserved.
//////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include "Util.h"

MUTEX* PacketCreateMutex()
{
	MUTEX* mutex = (MUTEX*)malloc(sizeof(MUTEX));
	if(!mutex)
	{
		return NULL;
	}
	memset(&mutex->cs, 0, sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(&mutex->cs);
	return mutex;
}

void PacketFreeMutex(MUTEX* lock)
{
	if(lock)
	{
		DeleteCriticalSection(&lock->cs);
		free(lock);
	}
}

void PacketLockMutex(MUTEX* lock)
{
	if(!lock)
	{
		return;
	}
	EnterCriticalSection(&lock->cs);
}

void PacketUnlockMutex(MUTEX* lock)
{
	if (!lock)
	{
		return;
	}
	LeaveCriticalSection(&lock->cs);
}

BOOL IsWow64()
{
#ifdef _AMD64
	return false;
#else
	BOOL b = FALSE;

	if (IsWow64Process(GetCurrentProcess(), &b) == FALSE)
	{
		return FALSE;
	}

	return b;
#endif
}


void *DisableWow64FsRedirection()
{
	void *p = NULL;

	if (IsWow64() == FALSE)
	{
		return NULL;
	}

	if (Wow64DisableWow64FsRedirection(&p) == FALSE)
	{
		return NULL;
	}

	return p;
}

void RestoreWow64FsRedirection(void *p)
{
	if (p == NULL)
	{
		return;
	}

	if (IsWow64() == FALSE)
	{
		return;
	}

	Wow64RevertWow64FsRedirection(p);
}
