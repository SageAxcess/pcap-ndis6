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

//  ChangeDynamix wfp filter (CDwf)
#define WFP_FLT_MEMORY_TAG          'fwDC'

#define NDIS_FLT_MEMORY_TAG         'nyDC'

#define FILTER_MAJOR_NDIS_VERSION   6
#define FILTER_MINOR_NDIS_VERSION   0

DRIVER_INITIALIZE DriverEntry;

//
// Global variables
//
#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)


//
// function prototypes
//

void _Function_class_(DRIVER_UNLOAD) DriverUnload(DRIVER_OBJECT *driver_object);


#endif  //_FILT_H


