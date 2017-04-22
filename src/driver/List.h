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
#include <minwindef.h>

//////////////////////////////////////////////////////////////////////
// List definitions
//////////////////////////////////////////////////////////////////////

typedef struct LIST_ITEM {
	void* Data;
	struct LIST_ITEM* Prev;
	struct LIST_ITEM* Next;
} LIST_ITEM;
typedef struct LIST_ITEM* PLIST_ITEM;

typedef struct LIST {
	PNDIS_SPIN_LOCK Lock;
	PLIST_ITEM First;
	PLIST_ITEM Last;

	ULONG Size;
} LIST;
typedef struct LIST* PLIST;

//////////////////////////////////////////////////////////////////////
// List functions
//////////////////////////////////////////////////////////////////////

LIST* CreateList();
void FreeList(LIST* list);
PLIST_ITEM AddToList(LIST* list, void* data);
BOOL RemoveFromList(LIST* list, PLIST_ITEM item);
BOOL RemoveFromListByData(LIST* list, PVOID data);