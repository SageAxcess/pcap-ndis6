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

#include <stdio.h>

#include "filter.h"
#include "Adapter.h"
#include "Client.h"
#include "Device.h"
#include "Events.h"
#include "Packet.h"
#include "KernelUtil.h"
#include <flt_dbg.h>

//////////////////////////////////////////////////////////////////////
// Device methods
/////////////////////////////////////////////////////////////////////

DEVICE* CreateDevice(char* name)
{
	DEBUGP(DL_TRACE, "===>CreateDevice(%s)...\n", name);

	char deviceName[1024];
	sprintf_s(deviceName, 1024, "\\Device\\" ADAPTER_ID_PREFIX "%s", name);

	char symlinkName[1024];
	sprintf_s(symlinkName, 1024, "\\DosDevices\\Global\\" ADAPTER_ID_PREFIX "%s", name);

	NDIS_STRING* name_u = CreateString(deviceName);
	if(!name_u)
	{
		return NULL;
	}

	NDIS_STRING* symlink_name_u = CreateString(symlinkName);
	if(!symlink_name_u)
	{
		FreeString(name_u);
		return NULL;
	}

	DEVICE* device = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(DEVICE));
	if(!device)
	{
		FreeString(name_u);
		FreeString(symlink_name_u);
		return NULL;
	}

	device->Name = name_u;
	device->OpenCloseLock = CreateSpinLock();
	device->ClientList = CreateList();
	
	NTSTATUS ret = IoCreateDevice(FilterDriverObject, sizeof(DEVICE *), name_u, FILE_DEVICE_TRANSPORT, 0, FALSE, &device->Device);
	if(ret !=STATUS_SUCCESS) //Nothing
	{
		//FreeString(name_u);
		//return NULL; 		
	}
	
	IoCreateSymbolicLink(symlink_name_u, name_u);
	FreeString(symlink_name_u);

	*((DEVICE **)device->Device->DeviceExtension) = device;
	device->Device->Flags &= ~DO_DEVICE_INITIALIZING;

	DEBUGP(DL_TRACE, "<===CreateDevice\n");

	return device;
}

// Delete a device
BOOL FreeDevice(PDEVICE device)
{
	DEBUGP(DL_TRACE, "===>FreeDevice...\n");
	if (device == NULL)
	{
		return FALSE;
	}

	IoDeleteDevice(device->Device);
	FreeString(device->Name);
	FreeSpinLock(device->OpenCloseLock);
	FreeClientList(device->ClientList);

	FILTER_FREE_MEM(device);

	DEBUGP(DL_TRACE, "<===CreateDevice\n");
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// Device callbacks
/////////////////////////////////////////////////////////////////////

NTSTATUS Device_CreateHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	DEBUGP(DL_TRACE, "===>Device_CreateHandler...\n");
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;

	if(!device)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);		
		DEBUGP(DL_TRACE, "<===Device_CreateHandler, ret=%d\n", ret);

		return ret;
	}

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

	DEBUGP(DL_TRACE, "<===Device_CreateHandler, ret=%d\n", ret);

	return ret;
}

NTSTATUS Device_CloseHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp)
{
	DEBUGP(DL_TRACE, "===>Device_CloseHandler...\n");
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;

	if(!device)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		DEBUGP(DL_TRACE, "<===Device_CloseHandler, ret=%d\n", ret);
		return ret;
	}

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

	DEBUGP(DL_TRACE, "<===Device_CloseHandler, ret=%d\n", ret);
	return ret;
}

/**
 * Device read callback
 */
NTSTATUS Device_ReadHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	DEBUGP(DL_TRACE, "===>Device_ReadHandler...\n");
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;

	if(!device)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		DEBUGP(DL_TRACE, "<===Device_ReadHandler, ret=%d\n", ret);

		return ret;
	}

	UINT responseSize = 0;
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	UINT requiredSize;

	CLIENT* client = (CLIENT*)stack->FileObject->FsContext;

	if (!client)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		DEBUGP(DL_TRACE, "<===Device_ReadHandler, ret=%d\n", ret);
		return ret;
	}

	if (device->IsAdaptersList)
	{
		NdisAcquireSpinLock(AdapterList->Lock);

		if(client->BytesSent>= sizeof(PCAP_NDIS_ADAPTER_LIST_HDR))
		{
			requiredSize = sizeof(struct PCAP_NDIS_ADAPTER_INFO);
		} else
		{
			requiredSize = sizeof(PCAP_NDIS_ADAPTER_LIST_HDR);
		}

		if (stack->Parameters.Read.Length >= requiredSize)
		{
			UCHAR* dst = (UCHAR*)Irp->UserBuffer;

			if (dst != NULL)
			{
				MDL *mdl;

				ProbeForWrite(Irp->UserBuffer, requiredSize, 1);

				mdl = IoAllocateMdl(dst, requiredSize, FALSE, FALSE, NULL);
				if (mdl != NULL)
				{
					MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
				}

				if(client->BytesSent==0)
				{
					PCAP_NDIS_ADAPTER_LIST_HDR hdr;
					memcpy(hdr.Signature, SIGNATURE, 8);
					hdr.Count = AdapterList->Size;

					RtlCopyBytes(dst, &hdr, requiredSize);

					responseSize = requiredSize;
				} else
				{
					ULONG size = sizeof(PCAP_NDIS_ADAPTER_INFO);

					PLIST_ITEM item = AdapterList->First;
					while (item)
					{
						if(size >= client->BytesSent)
						{
							PADAPTER adapter = (PADAPTER)item->Data;

							PCAP_NDIS_ADAPTER_INFO info;
							RtlCopyBytes(info.MacAddress, adapter->MacAddress, 6);
							RtlCopyBytes(info.AdapterId, adapter->AdapterId, 1024);
							RtlCopyBytes(info.DisplayName, adapter->DisplayName, 1024);

							info.MtuSize = adapter->MtuSize;

							RtlCopyBytes(dst, &info, sizeof(PCAP_NDIS_ADAPTER_INFO));

							responseSize = requiredSize;

							break;
						}

						size += sizeof(PCAP_NDIS_ADAPTER_INFO);
						item = item->Next;
					}
				}

				client->BytesSent += responseSize;
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
		UCHAR *buf = Irp->UserBuffer;

		UINT size = 0;
		NdisAcquireSpinLock(client->ReadLock);

		PLIST_ITEM item = client->PacketList->First;

		if(item)
		{
			PPACKET packet = (PPACKET)item->Data;

			BOOL header = stack->Parameters.Read.Length == sizeof(PACKET_HDR); //client wants to read header			

			if(header)
			{
				size = sizeof(PACKET_HDR);
			} else
			{
				size = packet->Size;
			}

			MDL *mdl;
			ProbeForWrite(buf, size, 1);

			mdl = IoAllocateMdl(buf, size, FALSE, FALSE, NULL);
			if (mdl != NULL)
			{
				MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
			}

			if(header) 
			{

				PACKET_HDR hdr;
				hdr.Size = packet->Size;
				hdr.Timestamp = packet->Timestamp;

				RtlCopyBytes(buf, &hdr, sizeof(PACKET_HDR));
			} else
			{
				RtlCopyBytes(buf, packet->Data, packet->Size);

				RemoveFromList(client->PacketList, item);
				FreePacket(packet);

				item = NULL;
				packet = NULL;
			}
		}

		//TODO: this is code to read multiple packets at once
		/*
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
		}*/

		if(client->PacketList->Size>0)
		{
			KeSetEvent(client->Event->Event, PASSIVE_LEVEL, FALSE);
		} else
		{
			KeResetEvent(client->Event->Event);
		}

		NdisReleaseSpinLock(client->ReadLock);

		ret = STATUS_SUCCESS;
		responseSize = size;
	}

	Irp->IoStatus.Status = ret;
	Irp->IoStatus.Information = responseSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<===Device_ReadHandler, ret=%d\n", ret);

	return ret;
}

NTSTATUS Device_WriteHandler(PDEVICE_OBJECT DeviceObject, IRP* Irp)
{
	DEBUGP(DL_TRACE, "===>Device_WriteHandler...\n");
	_CRT_UNUSED(DeviceObject);
	//TODO: Support for packet injection!

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<===Device_WriteHandler, ret=%d\n", STATUS_UNSUCCESSFUL);

	return Irp->IoStatus.Status;
}

NTSTATUS Device_IoControlHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	DEBUGP(DL_TRACE, "===>Device_IoControlHandler...\n");
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;

	if (!device)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		DEBUGP(DL_TRACE, "<===Device_IoControlHandler, ret=%d\n", ret);

		return ret;
	}

	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	UINT ReturnSize = 0;

	if (!device->IsAdaptersList)
	{
		CLIENT* client = stack->FileObject->FsContext;

		UINT size = (UINT)strlen(client->Event->Name) + 1;		
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

	DEBUGP(DL_TRACE, "<===Device_IoControlHandler, ret=%d\n", ret);

	return ret;
}
