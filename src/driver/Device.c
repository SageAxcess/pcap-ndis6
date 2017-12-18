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
#include "..\shared\CommonDefs.h"

#include "..\shared\win_bpf.h"

#include <flt_dbg.h>

extern NDIS_HANDLE         FilterProtocolHandle;

//////////////////////////////////////////////////////////////////////
// Device methods
/////////////////////////////////////////////////////////////////////

DEVICE* CreateDevice(char* name)
{
    char            deviceName[256] = { 0, };
    char            symlinkName[256] = { 0, };
    PNDIS_STRING    name_u = NULL;
    PNDIS_STRING    symlink_name_u = NULL;
    NTSTATUS        Status = STATUS_SUCCESS;
    PDEVICE         device = NULL;

    DEBUGP(DL_TRACE, "===>CreateDevice(%s)...\n", name);

	sprintf_s(deviceName, 256, "\\Device\\" ADAPTER_ID_PREFIX "%s", name);
	sprintf_s(symlinkName, 256, "\\DosDevices\\Global\\" ADAPTER_ID_PREFIX "%s", name);

    name_u = CreateString(deviceName);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(name_u),
        STATUS_INSUFFICIENT_RESOURCES);

	symlink_name_u = CreateString(symlinkName);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(symlink_name_u),
        STATUS_INSUFFICIENT_RESOURCES);

	device = FILTER_ALLOC_MEM(FilterDriverObject, sizeof(DEVICE));
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(device),
        STATUS_INSUFFICIENT_RESOURCES);
	
    NdisZeroMemory(device, sizeof(DEVICE));

	device->Name = name_u;
	device->SymlinkName = symlink_name_u;
	device->OpenCloseLock = CreateSpinLock();
	device->ClientList = CreateList();
	device->Releasing = FALSE;
	
	Status = IoCreateDevice(
        FilterDriverObject, 
        sizeof(DEVICE *), 
        name_u, 
        FILE_DEVICE_TRANSPORT, 
        0, 
        FALSE, 
        &device->Device);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
	
	IoCreateSymbolicLink(symlink_name_u, name_u);

	if (device->Device)
    {
		*((PDEVICE *)device->Device->DeviceExtension) = device;
		device->Device->Flags &= ~DO_DEVICE_INITIALIZING;
	}

cleanup:
    if (!NT_SUCCESS(Status))
    {
        if (Assigned(name_u))
        {
            FreeString(name_u);
        }
        if (Assigned(symlink_name_u))
        {
            FreeString(symlink_name_u);
        }
        if (Assigned(device))
        {
            FreeSpinLock(device->OpenCloseLock);
            FreeClientList(device->ClientList);
            FILTER_FREE_MEM(device);
        }
    }

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
		PCLIENT Client = (PCLIENT)item->Data;

        KeSetEvent(Client->Event.Event, 0, FALSE);

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

NTSTATUS _Function_class_(DRIVER_DISPATCH) _Dispatch_type_(IRP_MJ_CREATE) Device_CreateHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	DEVICE* device = *((DEVICE **)DeviceObject->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;

    DEBUGP_FUNC_ENTER(DL_TRACE);

	if(!device || device->Releasing)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);		
		DEBUGP(DL_TRACE, "<===Device_CreateHandler, ret=0x%8x\n", ret);

		return ret;
	}
	
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	if ((device->IsAdaptersList) || 
        ((device->Adapter != NULL) && (device->Adapter->Ready)))
	{
        if (!device->ClientList->Releasing)
        {
            PCLIENT NewClient = NULL;
            NTSTATUS Status = CreateClient(device, stack->FileObject, &NewClient);
            if (NT_SUCCESS(Status))
            {
                stack->FileObject->FsContext = NewClient;
            }
		}

		ret = STATUS_SUCCESS;
	}

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

    DEBUGP_FUNC_LEAVE_WITH_STATUS(DL_TRACE, ret);

	return ret;
}

NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_CLOSE)
Device_CloseHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    IRP             *Irp)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PDEVICE             Device = NULL;
    PIO_STACK_LOCATION  IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
       
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceObject),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceObject->DeviceExtension),
        STATUS_INVALID_PARAMETER_1);

    Device = *((PDEVICE *)DeviceObject->DeviceExtension);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Device),
        STATUS_UNSUCCESSFUL);

cleanup:
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
	
	

	//NdisAcquireSpinLock(device->OpenCloseLock);
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
	//NdisReleaseSpinLock(device->OpenCloseLock);

	Irp->IoStatus.Status = ret;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<===Device_CloseHandler, ret=0x%8x\n", ret);
	return ret;
}

NTSTATUS __stdcall Device_ReadPackets(
    __in    PCLIENT Client,
    __out   LPVOID  Buffer,
    __in    DWORD   BufferSize,
    __out   PDWORD  BytesRead)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    DWORD           BytesCopied = 0;
    LONGLONG        BytesLeft = BufferSize;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (Assigned(Client)) &&
        (Assigned(Buffer)) &&
        (BufferSize > 0) &&
        (Assigned(BytesRead)),
        STATUS_INVALID_PARAMETER);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        !Client->Releasing,
        STATUS_UNSUCCESSFUL);

    Km_List_Lock(&Client->PacketList);
    __try
    {
        PUCHAR      CurrentPtr = (PUCHAR)Buffer;

        for (PLIST_ENTRY ListEntry = Client->PacketList.Head.Flink, NextEntry = Client->PacketList.Head.Flink;
             ListEntry != &Client->PacketList.Head;
             ListEntry = NextEntry, NextEntry = NextEntry->Flink)
        {
            PPACKET Packet = CONTAINING_RECORD(ListEntry, PACKET, Link);
            USHORT  HeaderSize = (USHORT)sizeof(bpf_hdr);
            bpf_hdr bpf;
            ULONG   TotalPacketSize = Packet->DataSize + HeaderSize;

            BREAK_IF_FALSE(BytesLeft >= TotalPacketSize);

            bpf.bh_caplen = Packet->DataSize;
            bpf.bh_datalen = Packet->DataSize;
            bpf.bh_hdrlen = HeaderSize;
            bpf.bh_tstamp.tv_sec = (long)(Packet->Timestamp.QuadPart / 1000); // Get seconds part
            bpf.bh_tstamp.tv_usec = (long)(Packet->Timestamp.QuadPart - bpf.bh_tstamp.tv_sec * 1000) * 1000; // Construct microseconds from remaining

            RtlCopyMemory(CurrentPtr, &bpf, sizeof(struct bpf_hdr));
            RtlCopyMemory(CurrentPtr + HeaderSize, Packet->Data, Packet->DataSize);

            BytesCopied += TotalPacketSize;
            CurrentPtr += TotalPacketSize;
            BytesLeft -= TotalPacketSize;

            Km_List_RemoveItemEx(
                &Client->PacketList,
                ListEntry,
                FALSE,
                FALSE);

            FreePacket(Packet);
        }

        //  We must not set/clear this event outside of the PacketsList's lock
        //  since it can result in double reads from usermode otherwise
        if (Client->PacketList.Count.QuadPart == 0)
        {
            KeClearEvent(Client->Event.Event);
        }
    }
    __finally
    {
        Km_List_Unlock(&Client->PacketList);
    }

    *BytesRead = BytesCopied;

cleanup:
    return Status;
};

/**
 * Device read callback
 */
NTSTATUS _Function_class_(DRIVER_DISPATCH) _Dispatch_type_(IRP_MJ_READ) Device_ReadHandler(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	NTSTATUS            ret = STATUS_UNSUCCESSFUL;
    UINT                responseSize = 0;
    PDEVICE             device = *((PDEVICE *)DeviceObject->DeviceExtension);
    PIO_STACK_LOCATION  IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    UINT                requiredSize;
    PCLIENT             client = (PCLIENT)IoStackLocation->FileObject->FsContext;

	if(!FilterProtocolHandle || !device || device->Releasing)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		DEBUGP(DL_TRACE, "<===Device_ReadHandler, no device ret=0x%8x\n", ret);

		return ret;
	}

	if (!client)
	{
		Irp->IoStatus.Status = ret;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		DEBUGP(DL_TRACE, "<===Device_ReadHandler, no client ret=0x%8x\n", ret);
		return ret;
	}

	if (device->IsAdaptersList)
	{
		if(client->BytesSent>= sizeof(PCAP_NDIS_ADAPTER_LIST_HDR))
		{
			requiredSize = sizeof(struct PCAP_NDIS_ADAPTER_INFO);
		}
        else
		{
			requiredSize = sizeof(PCAP_NDIS_ADAPTER_LIST_HDR);
		}

		DEBUGP(
            DL_TRACE, 
            "  sent %u bytes to client, now need %u for buffer. Client provided %u\n", 
            client->BytesSent, 
            requiredSize, 
            IoStackLocation->Parameters.Read.Length);

		if (IoStackLocation->Parameters.Read.Length >= requiredSize)
		{
			UCHAR* dst = (UCHAR*)Irp->UserBuffer;

			if (dst != NULL)
			{
				MDL *mdl;

				__try
                {
					ProbeForWrite(Irp->UserBuffer, requiredSize, 1);
				}
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
					DEBUGP(DL_ERROR, " invalid buffer received at DeviceRead handler");

					ret = STATUS_UNSUCCESSFUL;
					responseSize = 0;

					Irp->IoStatus.Status = ret;
					Irp->IoStatus.Information = responseSize;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);

					return ret;
				}

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
				} 
                else
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
							RtlCopyBytes(info.AdapterId, adapter->AdapterId, 256);
							RtlCopyBytes(info.DisplayName, adapter->DisplayName, 256);

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
	}
    else
    {
        ret = STATUS_NOT_SUPPORTED;
    }

	Irp->IoStatus.Status = ret;
	Irp->IoStatus.Information = responseSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<===Device_ReadHandler, response size = %d, items in buffer=%d, ret=0x%8x\n", responseSize, client->PacketList->Size, ret);

	return ret;
}

NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_WRITE)
Device_WriteHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    PIRP            Irp)
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

NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
Device_IoControlHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    IRP             *Irp)
{
    PDEVICE             Device = NULL;
    NTSTATUS            Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  IoStackLocation = NULL;
    ULONG_PTR           ReturnSize = 0;
    PCLIENT             Client = NULL;
    LPVOID              InBuffer = NULL;
    LPVOID              OutBuffer = NULL;
    DWORD               InBufferSize = 0;
    DWORD               OutBufferSize = 0;

    DEBUGP_FUNC_ENTER(DL_TRACE);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (Assigned(DeviceObject)) &&
        (Assigned(Irp)),
        STATUS_UNSUCCESSFUL);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceObject->DeviceExtension),
        STATUS_UNSUCCESSFUL);

    Device = *((PDEVICE *)DeviceObject->DeviceExtension);
    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

    GOTO_CLEANUP_IF_TRUE_SET_STATUS(
        Device->Releasing,
        STATUS_UNSUCCESSFUL);

    GOTO_CLEANUP_IF_TRUE_SET_STATUS(
        Device->IsAdaptersList,
        STATUS_UNSUCCESSFUL);

    Client = (PCLIENT)IoStackLocation->FileObject->FsContext;
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Client),
        STATUS_UNSUCCESSFUL);

    Status = IOUtils_ValidateAndGetIOBuffers(
        Irp,
        &InBuffer,
        &InBufferSize,
        &OutBuffer,
        &OutBufferSize);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    switch (IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_GET_EVENT_NAME:
        {
            ULONG   Size = (ULONG)strlen(Client->Event.Name) + 1;

            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                OutBufferSize >= Size,
                STATUS_UNSUCCESSFUL);
            
            RtlZeroMemory(OutBuffer, Size);
            RtlCopyMemory(OutBuffer, Client->Event.Name, Size - 1);

            ReturnSize = Size;
        }break;

    case IOCTL_READ_PACKETS:
        {
            DWORD   BytesRead = 0;
            Status = Device_ReadPackets(
                Client,
                OutBuffer,
                OutBufferSize,
                &BytesRead);
            if (NT_SUCCESS(Status))
            {
                ReturnSize = BytesRead;
            }
        }break;

    default:
        {
            Status = STATUS_UNSUCCESSFUL;
        }break;
    };

cleanup:
    if (Assigned(Irp))
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = ReturnSize;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    if (NT_SUCCESS(Status))
    {
        DEBUGP(
            DL_TRACE, 
            "<===Device_IoControlHandler, ReturnSize = %u, Status = %x\n", 
            ReturnSize, 
            Status);
    }
    else
    {
        DEBUGP(
            DL_TRACE,
            "<===Device_IoControlHandler, failed. DeviceObject = %p, Irp = %p, Client = %p, Status = %x\n",
            DeviceObject,
            Irp,
            Client,
            Status);
    }

    return Status;
};