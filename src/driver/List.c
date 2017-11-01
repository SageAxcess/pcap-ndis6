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

#include "filter.h"
#include "List.h"
#include "KernelUtil.h"
#include <flt_dbg.h>

LIST* CreateList()
{
	LIST* list = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(LIST));
	NdisZeroMemory(list, sizeof(LIST));
	list->Lock = CreateSpinLock();
	list->Releasing = FALSE;
	return list;
}

void FreeList(LIST* list) //TODO: possible memory leak if you don't release data
{
	if(!list)
	{
		return;
	}

	NdisAcquireSpinLock(list->Lock);
	list->Releasing = TRUE;

	LIST_ITEM* cur = list->First;
	while(cur)
	{
		LIST_ITEM* tmp = cur;
		cur = cur->Next;

		FILTER_FREE_MEM(tmp);
	}

	NdisReleaseSpinLock(list->Lock);

	FreeSpinLock(list->Lock);
	FILTER_FREE_MEM(list);
}

PLIST_ITEM AddToList(LIST* list, void* data)
{
	NdisAcquireSpinLock(list->Lock);

	if(list->Releasing)
	{
		NdisReleaseSpinLock(list->Lock);
		return NULL;
	}

	LIST_ITEM* item = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(LIST_ITEM));
	NdisZeroMemory(item, sizeof(LIST_ITEM));
	item->Data = data;	

	if(!list->Last)
	{
		list->Last = list->First = item;
	} else
	{
		list->Last->Next = item;
		item->Prev = list->Last;
		list->Last = item;
	}
	list->Size++;

	NdisReleaseSpinLock(list->Lock);

	return item;
}

PLIST_ITEM PopListTop(LIST* list)
{
	if (!list || !list->First)
	{
		return NULL;
	}

	PLIST_ITEM item = list->First;
	list->First = item->Next;
	if (!item->Next)
		list->Last = 0;
	list->Size--;

	return item;
}

BOOL RemoveFromList(LIST* list, PLIST_ITEM item)
{
	if(!item || !list)
	{
		return FALSE;
	}
	DEBUGP(DL_TRACE, "===>RemoveFromList\n");
	BOOL res = TRUE;
	NdisAcquireSpinLock(list->Lock);

	if(item->Prev==NULL && item->Next==NULL)
	{
		if(list->Size>1 || list->First!=item)
		{
			res = FALSE;
		} else
		{
			list->First = 0;
			list->Last = 0;			
		}
	} else if(item->Next==NULL) {
		list->Last = item->Prev;
		item->Prev->Next = NULL;
	} else if(item->Prev==NULL)
	{
		list->First = item->Next;
		item->Next->Prev = NULL;
	} else
	{
		item->Prev->Next = item->Next;
		item->Next->Prev = item->Prev;
	}

	if (res) {
		FILTER_FREE_MEM(item);

		list->Size--;
	}

	NdisReleaseSpinLock(list->Lock);
	DEBUGP(DL_TRACE, "<===RemoveFromList, size=%u, res=%u\n", list->Size, res);
	return res;
}

BOOL RemoveFromListByData(LIST* list, PVOID data)
{
	DEBUGP(DL_TRACE, "===>RemoveFromListByData\n");

	if(!list)
	{
		return FALSE;
	}

	BOOL res = FALSE;
	NdisAcquireSpinLock(list->Lock);

	PLIST_ITEM item = NULL;
	PLIST_ITEM cur = list->First;
	while(cur)
	{
		DEBUGP(DL_TRACE, "  item data=0x%08x, compare to 0x%08x\n", cur->Data, data);

		if(cur->Data==data)
		{
			item = cur;
			break;
		}

		cur = cur->Next;
	}

	NdisReleaseSpinLock(list->Lock);

	if(item)
	{
		res = RemoveFromList(list, item);
	}

	DEBUGP(DL_TRACE, "<=== RemoveFromListByData, res=%u\n", res);

	return res;
}