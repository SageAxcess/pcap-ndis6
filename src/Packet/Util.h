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

#pragma once

#include <WinBase.h>

typedef struct MUTEX
{
	CRITICAL_SECTION cs;
} MUTEX;

MUTEX* PacketCreateMutex();
void PacketReleaseMutex(MUTEX* lock);
void PacketLockMutex(MUTEX* lock);
void PacketUnlockMutex(MUTEX* lock);