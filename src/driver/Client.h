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
#include "KmList.h"
#include "Device.h"
#include "Events.h"
#include "KmLock.h"

//////////////////////////////////////////////////////////////////////
// Client definitions
//////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////
// Client methods
//////////////////////////////////////////////////////////////////////

NTSTATUS CreateClient(
    __in    PDEVICE         Device,
    __in    PFILE_OBJECT    FileObject,
    __out   PCLIENT         *Client);

NTSTATUS FreeClient(
    __in    PCLIENT Client);

NTSTATUS RemoveClientFromList(
    __in    PKM_LIST    List,
    __in    PCLIENT     Client);

NTSTATUS ClearClientList(
    __in    PKM_LIST    List);