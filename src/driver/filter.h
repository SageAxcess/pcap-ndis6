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
#ifndef _FILT_H
#define _FILT_H

#include <ndis.h>

#include "winpcap_ndis.h"

#pragma warning(disable:28930) // Unused assignment of pointer, by design in samples
#pragma warning(disable:28931) // Unused assignment of variable, by design in samples

#define FILTER_REQUEST_ID          'nyDC'
#define FILTER_ALLOC_TAG           'nyDC' //reverts to CDyn=ChangeDynamix
#define FILTER_TAG                 'nyDC' 

#define FILTER_MAJOR_NDIS_VERSION   6
#define FILTER_MINOR_NDIS_VERSION   0

DRIVER_INITIALIZE DriverEntry;

//
// Global variables
//
extern NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
extern NDIS_HANDLE         FilterProtocolHandle;

extern PDRIVER_OBJECT      FilterDriverObject;
extern NDIS_HANDLE         NdisFilterDeviceHandle;
extern PDEVICE_OBJECT      NdisDeviceObject;

#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)

PVOID FilterAllocMem(NDIS_HANDLE NdisHandle, UINT Size);
void FilterFreeMem(PVOID Data);

#define FILTER_ALLOC_MEM(_NdisHandle, _Size)     \
    FilterAllocMem(_NdisHandle, _Size)

#define FILTER_ALLOC_MEM_TYPED_WITH_SIZE(Type, _NdisHandle, _Size) \
    (Type *)FilterAllocMem((_NdisHandle), (_Size))

#define FILTER_ALLOC_MEM_TYPED(Type, _NdisHandle) \
    FILTER_ALLOC_MEM_TYPED_WITH_SIZE(Type, (_NdisHandle), sizeof(Type))

#define FILTER_FREE_MEM(_pMem)    FilterFreeMem(_pMem)
//NdisFreeMemory(_pMem, 0, 0)
#define FILTER_INIT_LOCK(_pLock)      NdisAllocateSpinLock(_pLock)
#define FILTER_FREE_LOCK(_pLock)      NdisFreeSpinLock(_pLock)


//
// function prototypes
//

void _Function_class_(DRIVER_UNLOAD) DriverUnload(DRIVER_OBJECT *driver_object);


#endif  //_FILT_H


