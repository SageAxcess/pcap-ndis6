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
#include "Adapter.h"
#include "Client.h"
#include "Device.h"
#include "Events.h"
#include "Packet.h"
#include "KernelUtil.h"

//////////////////////////////////////////////////////////////////////
// Device methods
/////////////////////////////////////////////////////////////////////

DEVICE *CreateDevice(char* name)
{
	NDIS_STRING* name_u = CreateString(name);
	DEVICE_OBJECT *deviceObject = NULL;

	NTSTATUS ret = IoCreateDevice(FilterDriverObject, sizeof(DEVICE *), name_u, FILE_DEVICE_TRANSPORT, 0, FALSE, &deviceObject);
	if(ret !=STATUS_SUCCESS)
	{
		FreeString(name_u);
		return NULL;
	}

	DEVICE* device = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(DEVICE));

	device->Device = deviceObject;
	device->Name = name_u;
	device->OpenCloseLock = CreateSpinLock();
	device->ClientList = CreateList();

	*((DEVICE **)deviceObject->DeviceExtension) = device;

	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	return device;
}

// Delete a device
BOOL FreeDevice(PDEVICE device)
{
	if (device == NULL)
	{
		return FALSE;
	}

	IoDeleteDevice(device->Device);
	FreeString(device->Name);
	FreeSpinLock(device->OpenCloseLock);
	FreeClientList(device->ClientList);

	FILTER_FREE_MEM(device);

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// Device callbacks
/////////////////////////////////////////////////////////////////////

NTSTATUS Device_CreateHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	if (device->IsAdaptersList)
	{
		// Basic device
		ret = STATUS_SUCCESS;
	}
	else
	{
		NdisAcquireSpinLock(device->OpenCloseLock);
		
		if (device->Adapter != NULL && device->Adapter->Ready)
		{
			CLIENT* client = CreateClient(device, stack->FileObject);
			stack->FileObject->FsContext = client;			

			ret = STATUS_SUCCESS;
		}
		NdisReleaseSpinLock(device->OpenCloseLock);

		if (ret == STATUS_SUCCESS)
		{
			UINT filter = NDIS_PACKET_TYPE_PROMISCUOUS;
			SendOidRequest(device->Adapter, TRUE, OID_GEN_CURRENT_PACKET_FILTER, &filter, sizeof(filter));

			while (device->Adapter->PendingOidRequests > 0)
			{
				DriverSleep(50);
			}
		}
	}

	Irp->IoStatus.Status = ret;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ret;
}

NTSTATUS Device_CloseHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp)
{
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	if (device->IsAdaptersList)
	{
		ret = STATUS_SUCCESS;
	}
	else
	{
		// Adapter device
		PCLIENT client = (PCLIENT)stack->FileObject->FsContext;

		if (client)
		{
			NdisAcquireSpinLock(device->OpenCloseLock);
			RemoveFromListByData(device->ClientList, client);
			NdisReleaseSpinLock(device->OpenCloseLock);

			FreeClient(client);

			ret = STATUS_SUCCESS;
		}
	}

	Irp->IoStatus.Status = ret;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ret;
}

// Read procedure of the device
NTSTATUS Device_ReadHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	UINT responseSize = 0;
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	UINT requiredSize = sizeof(PCAP_NDIS_ADAPTER_LIST_HDR) + sizeof(PCAP_NDIS_ADAPTER_INFO) * AdapterList->Size;

	if (device->IsAdaptersList)
	{
		NdisAcquireSpinLock(AdapterList->Lock);

		if (stack->Parameters.Read.Length >= requiredSize)
		{
			UCHAR* dst = (UCHAR*)Irp->UserBuffer;

			if (dst != NULL)
			{
				MDL *mdl;

				ProbeForWrite(Irp->UserBuffer, sizeof(PCAP_NDIS_ADAPTER_LIST_HDR), 1);

				mdl = IoAllocateMdl(dst, requiredSize, FALSE, FALSE, NULL);
				if (mdl != NULL)
				{
					MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
				}

				PCAP_NDIS_ADAPTER_LIST_HDR hdr;
				memcpy(hdr.Signature, SIGNATURE, 8);
				hdr.Count = AdapterList->Size;

				RtlCopyBytes(dst, &hdr, sizeof(PCAP_NDIS_ADAPTER_LIST_HDR));
				dst += sizeof(PCAP_NDIS_ADAPTER_LIST_HDR);

				PLIST_ITEM item = AdapterList->First;
				while(item)
				{
					PADAPTER adapter = (PADAPTER)item->Data;

					PCAP_NDIS_ADAPTER_INFO info;
					info.MtuSize = adapter->MtuSize;
					//TODO: copy other data!

					RtlCopyBytes(dst, &info, sizeof(PCAP_NDIS_ADAPTER_INFO));
					dst += sizeof(PCAP_NDIS_ADAPTER_INFO);

					item = item->Next;
				}

				responseSize = requiredSize;
				ret = STATUS_SUCCESS;

				if (mdl != NULL)
				{
					MmUnlockPages(mdl);
					IoFreeMdl(mdl);
				}
			}
		}
		NdisReleaseSpinLock(AdapterList->Lock);
	}
	else
	{
		// Adapter device
		CLIENT* client = stack->FileObject->FsContext;

		UCHAR *buf = Irp->UserBuffer;

		UINT total = 0;
		NdisAcquireSpinLock(client->ReadLock);

		PLIST_ITEM item = client->PacketList->First;

		while(item && total<stack->Parameters.Read.Length)
		{
			PPACKET packet = (PPACKET)item->Data;

			if((total + packet->Size + sizeof(PACKET_HDR)) > stack->Parameters.Read.Length)
			{
				break;
			}

			total += packet->Size + sizeof(PACKET_HDR);
			item = item->Next;
		}

		if(total>0)
		{
			MDL *mdl;
			ProbeForWrite(buf, total, 1);

			mdl = IoAllocateMdl(buf, total, FALSE, FALSE, NULL);
			if (mdl != NULL)
			{
				MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
			}

			item = client->PacketList->First;
			total = 0;

			while (item && total<stack->Parameters.Read.Length)
			{
				PPACKET packet = (PPACKET)item->Data;

				if ((total + packet->Size + sizeof(PACKET_HDR)) > stack->Parameters.Read.Length)
				{
					break;
				}

				PACKET_HDR hdr;
				hdr.Size = packet->Size;
				hdr.Timestamp = packet->Timestamp;

				RtlCopyBytes(buf, &hdr, sizeof(PACKET_HDR));
				buf += sizeof(PACKET_HDR);

				RtlCopyBytes(buf, packet->Data, packet->Size);
				buf += packet->Size;

				total += packet->Size + sizeof(PACKET_HDR);

				item = item->Next;

				RemoveFromList(client->PacketList, item->Prev);
				FreePacket(packet);
			}

			if (mdl != NULL)
			{
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);
			}
		}

		if(client->PacketList->Size>0)
		{
			KeSetEvent(client->Event->Event, PASSIVE_LEVEL, FALSE);
		} else
		{
			KeResetEvent(client->Event->Event);
		}

		NdisReleaseSpinLock(client->ReadLock);

		ret = STATUS_SUCCESS;
		responseSize = total;
	}

	Irp->IoStatus.Status = ret;
	Irp->IoStatus.Information = responseSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ret;
}

NTSTATUS Device_WriteHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp)
{
	_CRT_UNUSED(DeviceObject);
	//TODO: Support for packet injection!

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}

NTSTATUS Device_IoControlHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	UINT ReturnSize = 0;

	if (!device->IsAdaptersList)
	{
		CLIENT* client = stack->FileObject->FsContext;

		UINT size = strlen(client->Event->Name) + 1;		
		if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_EVENT_NAME)
		{
			if (stack->Parameters.DeviceIoControl.OutputBufferLength >=size)
			{
				char* buf = (char*)Irp->UserBuffer;
				if (buf)
				{
					ProbeForWrite(buf, size, 1);

					strcpy_s(buf, size, client->Event->Name);

					ReturnSize = size;

					ret = STATUS_SUCCESS;
				}
			}
		}
	}

	Irp->IoStatus.Status = ret;
	Irp->IoStatus.Information = ReturnSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ret;
}