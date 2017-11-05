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


struct timeval {
	long    tv_sec;         /* seconds */
	long    tv_usec;        /* and microseconds */
};

struct bpf_hdr {
	struct timeval	bh_tstamp;	/* time stamp */
	ULONG			bh_caplen;	/* length of captured portion */
	ULONG			bh_datalen;	/* original length of packet */
	USHORT			bh_hdrlen;	/* length of bpf header (this struct
									plus alignment padding) */
};

#ifndef ALIGN_SIZE
#define ALIGN_SIZE( sizeToAlign, PowerOfTwo )       \
        (((sizeToAlign) + (PowerOfTwo) - 1) & ~((PowerOfTwo) - 1))
#endif

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
	NdisZeroMemory(device, sizeof(DEVICE));

	device->Name = name_u;
	device->SymlinkName = symlink_name_u;
	device->OpenCloseLock = CreateSpinLock();
	device->ClientList = CreateList();
	device->Releasing = FALSE;
	
	NTSTATUS ret = IoCreateDevice(FilterDriverObject, sizeof(DEVICE *), name_u, FILE_DEVICE_TRANSPORT, 0, FALSE, &device->Device);
	if(ret !=STATUS_SUCCESS) //Nothing
	{
		//FreeString(name_u);
		//return NULL; 		
	}
	
	IoCreateSymbolicLink(symlink_name_u, name_u);

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

	IoDeleteSymbolicLink(device->SymlinkName);
	IoDeleteDevice(device->Device);
	DriverSleep(50);

	NdisAcquireSpinLock(device->ClientList->Lock);

	PLIST_ITEM item = device->ClientList->First;
	while (item)
	{
		PCLIENT client = (PCLIENT)item->Data;

		KeSetEvent(client->Event->Event, PASSIVE_LEVEL, FALSE);

		item = item->Next;
	}

	NdisReleaseSpinLock(device->ClientList->Lock);

	FreeString(device->Name);
	FreeString(device->SymlinkName);
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

	if(!device || device->Releasing)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);		
		DEBUGP(DL_TRACE, "<===Device_CreateHandler, ret=0x%8x\n", ret);

		return ret;
	}
	
	//if (device->Adapter) {
		DEBUGP(DL_TRACE, "  opened device for adapter %s %s\n", device->Adapter->AdapterId, device->Adapter->DisplayName);
	//} else
	//{
		DEBUGP(DL_TRACE, "  opened device for adapter list\n");
	//}

	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	DEBUGP(DL_TRACE, " Acquire lock at 0x%8x, adapter=0x%8x, stack=0x%8x\n", device->OpenCloseLock, device->Adapter, stack);
	NdisAcquireSpinLock(device->OpenCloseLock);
	DEBUGP(DL_TRACE, "    lock acquired\n");
	if(device->Adapter!=NULL && !device->Adapter->Ready)
	{
		DEBUGP(DL_TRACE, "    adapter is not ready!!!\n");
	}
	if (device->IsAdaptersList || (device->Adapter != NULL && device->Adapter->Ready))
	{
		if (!device->ClientList->Releasing) {
			CLIENT* client = CreateClient(device, stack->FileObject);			
			stack->FileObject->FsContext = client;			
		}

		ret = STATUS_SUCCESS;
	}
	NdisReleaseSpinLock(device->OpenCloseLock);

	if (!device->IsAdaptersList)
	{
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

	DEBUGP(DL_TRACE, "<===Device_CreateHandler, ret=0x%8x\n", ret);

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

		DEBUGP(DL_TRACE, "<===Device_CloseHandler (no handler), ret=0x%8x\n", ret);
		return ret;
	}

	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	NdisAcquireSpinLock(device->OpenCloseLock);
	if (device->IsAdaptersList)
	{
		DEBUGP(DL_TRACE, "   closing all adapters list device\n");
		ret = STATUS_SUCCESS;
	}
	else
	{
		DEBUGP(DL_TRACE, "   closing adapter device\n");
		// Adapter device
		PCLIENT client = (PCLIENT)stack->FileObject->FsContext;

		if (client)
		{
			DEBUGP(DL_TRACE, "   acquire lock for client list and remove\n");
			RemoveFromListByData(device->ClientList, client);

			FreeClient(client);			

			stack->FileObject->FsContext = NULL;

			ret = STATUS_SUCCESS;
		}
	}
	NdisReleaseSpinLock(device->OpenCloseLock);

	Irp->IoStatus.Status = ret;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<===Device_CloseHandler, ret=0x%8x\n", ret);
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

	if(!device || device->Releasing)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		DEBUGP(DL_TRACE, "<===Device_ReadHandler, no device ret=0x%8x\n", ret);

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

		DEBUGP(DL_TRACE, "<===Device_ReadHandler, no client ret=0x%8x\n", ret);
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

		DEBUGP(DL_TRACE, "  sent %u bytes to client, now need %u for buffer. Client provided %u\n", client->BytesSent, requiredSize, stack->Parameters.Read.Length);

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

				BOOL last = FALSE;

				if(client->BytesSent==0)
				{
					PCAP_NDIS_ADAPTER_LIST_HDR hdr;
					memcpy(hdr.Signature, SIGNATURE, 8);
					hdr.Count = AdapterList->Size;

					RtlCopyBytes(dst, &hdr, requiredSize);

					DEBUGP(DL_TRACE, "  there are %u adapters\n", hdr.Count);

					if(hdr.Count==0)
					{
						last = TRUE;
					}

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

							DEBUGP(DL_TRACE, "  returning adapter %s %s\n", adapter->AdapterId, adapter->DisplayName);

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

					if (item==NULL || item->Next==NULL)
					{
						last = TRUE;
					}
				}

				if(last)
				{
					client->BytesSent = 0;
				}
				else {
					client->BytesSent += responseSize;
				}

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

		DEBUGP(DL_TRACE, "  client provided buf = %d bytes\n", stack->Parameters.Read.Length);

		NdisAcquireSpinLock(client->ReadLock);

		UINT availableSize = stack->Parameters.Read.Length;

		if(client->PacketList==NULL || client->PacketList->Releasing) //Seems that driver is being unloaded, release is protected with ReadLock so no conflict
		{
			ret = STATUS_UNSUCCESSFUL;
			responseSize = 0;		

			Irp->IoStatus.Status = ret;
			Irp->IoStatus.Information = responseSize;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);

			return ret;
		}

		UINT size = 0;
		NdisAcquireSpinLock(client->PacketList->Lock);

		MDL *mdl = NULL;
		ProbeForWrite(buf, availableSize, 1);

		mdl = IoAllocateMdl(buf, availableSize, FALSE, FALSE, NULL);
		if (mdl != NULL)
		{
			MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
		}

		PLIST_ITEM item = PopListTop(client->PacketList);

		while(item)
		{
			PPACKET packet = (PPACKET)item->Data;

			USHORT hdrSize = ALIGN_SIZE(sizeof(struct bpf_hdr), 4);

			DEBUGP(DL_TRACE, "  packet size=%d, response size=%d, aligned header size=%d, real header size=%d\n", packet->Size, size, hdrSize, sizeof(struct bpf_hdr));

			struct bpf_hdr bpf;
			bpf.bh_caplen = packet->Size;
			bpf.bh_datalen = packet->Size;
			bpf.bh_hdrlen = hdrSize;
			bpf.bh_tstamp.tv_sec = (long)(packet->Timestamp.QuadPart / 1000); // Get seconds part
			bpf.bh_tstamp.tv_usec = (long)(packet->Timestamp.QuadPart - bpf.bh_tstamp.tv_sec * 1000) * 1000; // Construct microseconds from remaining
			
			RtlCopyBytes(buf, &bpf, sizeof(struct bpf_hdr));
			RtlCopyBytes(buf + hdrSize, packet->Data, packet->Size);

			size += ALIGN_SIZE(packet->Size + hdrSize, 1024);
			buf += ALIGN_SIZE(packet->Size + hdrSize, 1024);

			FreePacket(packet);

			if(item->Next!=NULL)
			{
				PPACKET next = (PPACKET)item->Next->Data;
				if(size + next->Size + hdrSize > availableSize)
				{
					FILTER_FREE_MEM(item);

					break;
				}
			}

			FILTER_FREE_MEM(item);
			item = PopListTop(client->PacketList);
		}

		NdisReleaseSpinLock(client->PacketList->Lock);

		if (mdl != NULL)
		{
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
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
		responseSize = size;
	}

	Irp->IoStatus.Status = ret;
	Irp->IoStatus.Information = responseSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<===Device_ReadHandler, response size = %d, items in buffer=%d, ret=0x%8x\n", responseSize, client->PacketList->Size, ret);

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

	DEBUGP(DL_TRACE, "<===Device_WriteHandler, ret=0x%8x\n", STATUS_UNSUCCESSFUL);

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
		DEBUGP(DL_TRACE, "<===Device_IoControlHandler, no device, ret=0x%8x\n", ret);

		return ret;
	}

	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	UINT ReturnSize = 0;

	if (!device->IsAdaptersList)
	{
		CLIENT* client = stack->FileObject->FsContext;
		if(!client)
		{
			Irp->IoStatus.Status = ret;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			DEBUGP(DL_TRACE, "<===Device_IoControlHandler, no client, ret=0x%8x\n", ret);

			return ret;
		}

		UINT size = (UINT)strlen(client->Event->Name) + 1;
		DEBUGP(DL_TRACE, "    event name length=%u, client provided %u\n", size, stack->Parameters.DeviceIoControl.OutputBufferLength);

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

	DEBUGP(DL_TRACE, "<===Device_IoControlHandler, size=%u, ret=0x%8x\n", ReturnSize, ret);

	return ret;
}
