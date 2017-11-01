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
#include "List.h"

//////////////////////////////////////////////////////////////////////
// Device definitions
//////////////////////////////////////////////////////////////////////

typedef struct DEVICE {
	PUNICODE_STRING Name;
	PDEVICE_OBJECT Device;

	struct ADAPTER* Adapter;

	PNDIS_SPIN_LOCK OpenCloseLock;
	PLIST ClientList;

	BOOL Releasing;
	BOOL IsAdaptersList;
} DEVICE;
typedef struct DEVICE* PDEVICE;

//////////////////////////////////////////////////////////////////////
// Device methods
/////////////////////////////////////////////////////////////////////
DEVICE *CreateDevice(char* name);
BOOL FreeDevice(PDEVICE device);

//////////////////////////////////////////////////////////////////////
// Device callbacks
/////////////////////////////////////////////////////////////////////
NTSTATUS Device_CreateHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp);
NTSTATUS Device_CloseHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp);
NTSTATUS Device_ReadHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp);
NTSTATUS Device_WriteHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp);
NTSTATUS Device_IoControlHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp);
