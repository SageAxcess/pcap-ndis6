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
	DEBUGP(DL_TRACE, "===>CreateEvent...\n");
	EVENT *event = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(EVENT));
	if(!event)
	{
		return NULL;
	}
	NdisZeroMemory(event, sizeof(EVENT));

	InterlockedIncrement((volatile long*)&_curEventId);
	LARGE_INTEGER timestamp = KeQueryPerformanceCounter(NULL);
	
	sprintf(event->Name, EVENT_NAME_FMT, _curEventId, timestamp.QuadPart);

	char name[1024];
	sprintf(name, "\\BaseNamedObjects\\%s", event->Name);

	DEBUGP(DL_TRACE, " event name %s\n", name);

	PUNICODE_STRING name_u = CreateString(name);

	if(!name_u)
	{
		DEBUGP(DL_TRACE, "<===CreateEvent failed to alloc string\n");
		FILTER_FREE_MEM(event);
		return NULL;
	}

	DEBUGP(DL_TRACE, " event name unicode = 0x%08x, handle=0x%08x\n", name, event->EventHandle);

	DEBUGP(DL_TRACE, "  calling IoCreateNotificationEvent\n");
	event->Event = IoCreateNotificationEvent(name_u, &event->EventHandle);

	if (!event->Event)
	{		
		FILTER_FREE_MEM(event);
		FreeString(name_u);

		DEBUGP(DL_TRACE, "<===CreateEvent failed\n");

		return NULL;
	}

	DEBUGP(DL_TRACE, "  initialize event\n");
	KeInitializeEvent(event->Event, NotificationEvent, FALSE);
	DEBUGP(DL_TRACE, "  reset event\n");
	KeClearEvent(event->Event);

	DEBUGP(DL_TRACE, "  free event name string\n");
	FreeString(name_u);

	DEBUGP(DL_TRACE, "<===CreateEvent\n");

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