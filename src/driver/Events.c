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



#include "precomp.h"
#include "Events.h"
#include "KernelUtil.h"

volatile ULONG _curEventId = 0;

EVENT* CreateEvent()
{
	EVENT *event = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(EVENT));
	NdisZeroMemory(event, sizeof(EVENT));

	InterlockedIncrement((volatile long*)&_curEventId);
	LARGE_INTEGER timestamp = KeQueryPerformanceCounter(NULL);
	
	sprintf(event->Name, EVENT_NAME_FMT, _curEventId, timestamp.QuadPart);

	char name[1024];
	sprintf(name, "\\BaseNamedObjects\\%s", event->Name);

	PUNICODE_STRING name_u = CreateString(name);

	event->Event = IoCreateNotificationEvent(event->Name, &event->EventHandle);

	FreeString(name_u);

	if (!event->Event)
	{
		
		FILTER_FREE_MEM(event);
		
		return NULL;
	}

	KeInitializeEvent(event->Event, NotificationEvent, FALSE);
	KeClearEvent(event->Event);

	return event;
}

BOOL FreeEvent(PEVENT event)
{
	if(!event)
	{
		return FALSE;
	}

	ZwClose(event->EventHandle);

	FILTER_FREE_MEM(event);
	return TRUE;
}