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
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef NDIS_MEMORY_MANAGER_H
#define NDIS_MEMORY_MANAGER_H

#include <ndis.h>
#include "KmLock.h"

typedef struct _NDIS_MM
{
    //  A handle received from one of the following NDIS routines:
    //  * NdisMRegisterMiniportDriver
    //  * MiniportInitializeEx
    //  * NdisRegisterProtocolDriver
    //  * NdisOpenAdapterEx,
    //  * NdisFRegisterFilterDriver
    //  * FilterAttach
    NDIS_HANDLE NdisObjectHandle;

    #ifdef _DEBUG
    //  Lock object
    KM_LOCK     Lock;

    //  List containing allocated memory blocks
    LIST_ENTRY  AllocatedBlocks;
    #endif

} NDIS_MM, *PNDIS_MM;

#endif