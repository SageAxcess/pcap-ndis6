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
#include "List.h"

//////////////////////////////////////////////////////////////////////
// Client definitions
//////////////////////////////////////////////////////////////////////

typedef struct CLIENT {
	struct DEVICE* Device;
	PFILE_OBJECT FileObject;
	struct EVENT* Event;
	NDIS_HANDLE NetBufferListPool;
	PLIST PacketList;
	PNDIS_SPIN_LOCK ReadLock;
	volatile ULONG PendingSendPackets;
	ULONG BytesSent;
}CLIENT;
typedef struct CLIENT* PCLIENT;

//////////////////////////////////////////////////////////////////////
// Client methods
//////////////////////////////////////////////////////////////////////

PCLIENT CreateClient(struct DEVICE* device, PFILE_OBJECT fileObject);
BOOL FreeClient(PCLIENT client);
void FreeClientList(PLIST list);
