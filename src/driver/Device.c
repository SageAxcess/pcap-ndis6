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

//////////////////////////////////////////////////////////////////////
// Device methods
/////////////////////////////////////////////////////////////////////

PDEVICE CreateDevice(
    __in    PDRIVER_OBJECT  DriverObject,
    __in    PDRIVER_DATA    Data,
    __in    PUNICODE_STRING Name)
{
    ULONG           DeviceNameLength = 0;
    ULONG           SymLinkNameLength = 0;
    PUNICODE_STRING DeviceName = NULL;
    PUNICODE_STRING SymLinkName = NULL;
    NTSTATUS        Status = STATUS_SUCCESS;
    PDEVICE         Device = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DriverObject),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Name),
        STATUS_INVALID_PARAMETER_3);

    DeviceNameLength =
        sizeof(ADAPTER_DEVICE_NAME_PREFIX_W) +
        Name->Length +
        sizeof(wchar_t);

    SymLinkNameLength =
        sizeof(ADAPTER_DEVICE_SYM_LINK_NAME_PREFIX_W) +
        Name->Length +
        sizeof(wchar_t);

    DeviceName = AllocateString(
        &Data->Ndis.MemoryManager,
        (USHORT)DeviceNameLength);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceName),
        STATUS_INSUFFICIENT_RESOURCES);

    Status = RtlAppendUnicodeToString(
        DeviceName,
        ADAPTER_DEVICE_NAME_PREFIX_W);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = RtlAppendUnicodeStringToString(
        DeviceName,
        Name);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    SymLinkName = AllocateString(
        &Data->Ndis.MemoryManager,
        (USHORT)SymLinkNameLength);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(SymLinkName),
        STATUS_INSUFFICIENT_RESOURCES);

    Status = RtlAppendUnicodeToString(
        SymLinkName, 
        ADAPTER_DEVICE_SYM_LINK_NAME_PREFIX_W);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Status = RtlAppendUnicodeStringToString(
        SymLinkName,
        Name);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Device = Km_MM_AllocMemTyped(
        &Data->Ndis.MemoryManager,
        DEVICE);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Device),
        STATUS_INSUFFICIENT_RESOURCES);
	
    RtlZeroMemory(Device, sizeof(DEVICE));

    Status = Km_Lock_Initialize(&Device->OpenCloseLock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    Device->Name = DeviceName;
    Device->SymlinkName = SymLinkName;
    Device->DriverData = Data;
	
    Status = Km_List_Initialize(&Device->ClientList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

	Status = IoCreateDevice(
        DriverObject, 
        sizeof(DEVICE *), 
        DeviceName, 
        FILE_DEVICE_TRANSPORT, 
        0, 
        FALSE, 
        &Device->Device);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
	
    Status = IoCreateSymbolicLink(SymLinkName, DeviceName);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    if (Assigned(Device->Device))
    {
		*((PDEVICE *)Device->Device->DeviceExtension) = Device;
		Device->Device->Flags &= ~DO_DEVICE_INITIALIZING;
	}

cleanup:
    if (!NT_SUCCESS(Status))
    {
        if (Assigned(DeviceName))
        {
            FreeString(
                &Data->Ndis.MemoryManager,
                DeviceName);
        }
        if (Assigned(SymLinkName))
        {
            FreeString(
                &Data->Ndis.MemoryManager,
                SymLinkName);
        }

        if (Assigned(Device))
        {
            ClearClientList(&Device->ClientList);
            
            Km_MM_FreeMem(
                &Data->Ndis.MemoryManager,
                Device);

            Device = NULL;
        }
    }

	return Device;
};

PDEVICE CreateDevice2(
    __in    PDRIVER_OBJECT  DriverObject,
    __in    PDRIVER_DATA    Data,
    __in    LPCWSTR         Name)
{
    UNICODE_STRING  NameStr = { 0, };

    RtlInitUnicodeString(&NameStr, Name);

    return CreateDevice(
        DriverObject,
        Data,
        &NameStr);
};

// Delete a device
BOOL FreeDevice(
    __in    PDEVICE Device)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(Device),
        FALSE);
    RETURN_VALUE_IF_FALSE(
        Assigned(Device->DriverData),
        FALSE);

    if (Assigned(Device->SymlinkName))
    {
        IoDeleteSymbolicLink(Device->SymlinkName);
        FreeString(
            &Device->DriverData->Ndis.MemoryManager,
            Device->SymlinkName);
    }

    if (Assigned(Device->Device))
    {
        IoDeleteDevice(Device->Device);
    }

    if (Assigned(Device->Name))
    {
        FreeString(
            &Device->DriverData->Ndis.MemoryManager,
            Device->Name);
    }
	
    ClearClientList(&Device->ClientList);

    Km_MM_FreeMem(
        &Device->DriverData->Ndis.MemoryManager,
        Device);

	return TRUE;
};

//////////////////////////////////////////////////////////////////////
// Device callbacks
/////////////////////////////////////////////////////////////////////

NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_CREATE)
Device_CreateHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    PIRP            Irp)
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
        ((Assigned(device->Adapter)) && (device->Adapter->Ready)))
	{
        if (!device->Releasing)
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

    //NdisAcquireSpinLock(device->OpenCloseLock);
    if (!Device->IsAdaptersList)
    {
        PCLIENT Client = (PCLIENT)IoStackLocation->FileObject->FsContext;
        if (Assigned(Client))
        {
            Status = RemoveClientFromList(
                &Device->ClientList,
                Client);
            if (NT_SUCCESS(Status))
            {
                IoStackLocation->FileObject->FsContext = NULL;
                FreeClient(Client);
            }
        }
    }

cleanup:
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
};

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

    Km_Lock_Acquire(&Client->ReadLock);
    __try
    {
        Km_List_Lock(&Client->PacketList);
        __try
        {
            PUCHAR      CurrentPtr = (PUCHAR)Buffer;

            for (PLIST_ENTRY ListEntry = Client->PacketList.Head.Flink, NextEntry = ListEntry->Flink;
                ListEntry != &Client->PacketList.Head;
                ListEntry = NextEntry, NextEntry = NextEntry->Flink)
            {
                PPACKET     Packet = CONTAINING_RECORD(ListEntry, PACKET, Link);
                USHORT      HeaderSize = (USHORT)sizeof(bpf_hdr2);
                bpf_hdr2    bpf;
                ULONG       TotalPacketSize = Packet->DataSize + HeaderSize;

                BREAK_IF_FALSE(BytesLeft >= TotalPacketSize);

                bpf.bh_caplen = Packet->DataSize;
                bpf.bh_datalen = Packet->DataSize;
                bpf.bh_hdrlen = HeaderSize;
                bpf.bh_tstamp.tv_sec = (long)(Packet->Timestamp.QuadPart / 1000); // Get seconds part
                bpf.bh_tstamp.tv_usec = (long)(Packet->Timestamp.QuadPart - bpf.bh_tstamp.tv_sec * 1000) * 1000; // Construct microseconds from remaining
                bpf.ProcessId = Packet->ProcessId;

                RtlCopyMemory(CurrentPtr, &bpf, HeaderSize);
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
    }
    __finally
    {
        Km_Lock_Release(&Client->ReadLock);
    }

    *BytesRead = BytesCopied;

cleanup:
    return Status;
};

NTSTATUS __stdcall Device_GetAdapters(
    __in    PDRIVER_DATA    Data,
    __in    PVOID           Buffer,
    __in    DWORD           BufferSize,
    __out   PDWORD          BytesRead)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    DWORD       BytesCopied = 0;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Data),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Buffer),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        BufferSize >= (DWORD)sizeof(PCAP_NDIS_ADAPTER_INFO_LIST),
        STATUS_BUFFER_TOO_SMALL);

    Status = Km_List_Lock(&Data->AdaptersList);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        DWORD                           BytesRequired = 0;
        ULARGE_INTEGER                  Count = { 0, };
        unsigned int                    k;
        PLIST_ENTRY                     ListEntry;
        PPCAP_NDIS_ADAPTER_INFO_LIST    List;

        Status = Km_List_GetCountEx(
            &Data->AdaptersList,
            &Count,
            FALSE,
            FALSE);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));

        BytesRequired =
            (DWORD)sizeof(PCAP_NDIS_ADAPTER_INFO_LIST) +
            (DWORD)((Count.QuadPart - 1) * sizeof(PCAP_NDIS_ADAPTER_INFO));

        LEAVE_IF_FALSE_SET_STATUS(
            BytesRequired <= BufferSize,
            STATUS_BUFFER_TOO_SMALL);

        RtlZeroMemory(Buffer, BufferSize);

        List = (PPCAP_NDIS_ADAPTER_INFO_LIST)Buffer;
        List->NumberOfAdapters = (unsigned int)Count.QuadPart;

        BytesCopied += sizeof(PCAP_NDIS_ADAPTER_INFO_LIST) - sizeof(PCAP_NDIS_ADAPTER_INFO);

        for (ListEntry = Data->AdaptersList.Head.Flink, k = 0;
             ListEntry != &Data->AdaptersList.Head;
             ListEntry = ListEntry->Flink, k++)
        {
            PADAPTER    Adapter = CONTAINING_RECORD(ListEntry, ADAPTER, Link);

            if (Adapter->Name.Length > 0)
            {
                ULONG   IdLength =
                    Adapter->Name.Length > PCAP_NDIS_ADAPTER_ID_SIZE_MAX * sizeof(wchar_t) ?
                    PCAP_NDIS_ADAPTER_ID_SIZE_MAX * sizeof(wchar_t) :
                    Adapter->Name.Length;

                RtlCopyMemory(
                    List->Items[k].AdapterId,
                    Adapter->Name.Buffer,
                    IdLength);

                List->Items[k].AdapterIdLength = IdLength;
            }

            if (Adapter->MacAddressSize > 0)
            {
                ULONG   MacLength =
                    Adapter->MacAddressSize > PCAP_NDIS_ADAPTER_MAC_ADDRESS_SIZE ?
                    PCAP_NDIS_ADAPTER_MAC_ADDRESS_SIZE :
                    Adapter->MacAddressSize;

                RtlCopyMemory(
                    List->Items[k].MacAddress,
                    Adapter->MacAddress,
                    MacLength);
            }

            List->Items[k].MtuSize = Adapter->MtuSize;

            BytesCopied += sizeof(PCAP_NDIS_ADAPTER_INFO);
        }
    }
    __finally
    {
        Km_List_Unlock(&Data->AdaptersList);
    }


cleanup:

    if (Assigned(BytesRead))
    {
        *BytesRead = BytesCopied;
    }

    return Status;
};

/**
 * Device read callback
 */
NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_READ)
Device_ReadHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    PIRP            Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Irp->IoStatus.Status;
};

NTSTATUS
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_WRITE)
Device_WriteHandler(
    __in    PDEVICE_OBJECT  DeviceObject,
    __in    PIRP            Irp)
{
	DEBUGP(DL_TRACE, "===>Device_WriteHandler...\n");
	UNREFERENCED_PARAMETER(DeviceObject);
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
    DWORD               BytesRead = 0;

    DEBUGP_FUNC_ENTER(DL_TRACE);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (Assigned(DeviceObject)) &&
        (Assigned(Irp)),
        STATUS_UNSUCCESSFUL);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(DeviceObject->DeviceExtension),
        STATUS_UNSUCCESSFUL);

    Device = *((PDEVICE *)DeviceObject->DeviceExtension);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Device),
        STATUS_UNSUCCESSFUL);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        !Device->DriverData->DriverUnload,
        STATUS_UNSUCCESSFUL);

    GOTO_CLEANUP_IF_TRUE_SET_STATUS(
        Device->Releasing,
        STATUS_UNSUCCESSFUL);

    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

    Client = (PCLIENT)IoStackLocation->FileObject->FsContext;
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        (Assigned(Client)) || 
        (Device->IsAdaptersList),
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

    case IOCTL_GET_ADAPTERS_COUNT:
        {
            ULARGE_INTEGER  NumberOfAdapters;

            GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                OutBufferSize >= sizeof(DWORD),
                STATUS_BUFFER_TOO_SMALL);

            Status = Km_List_GetCount(&Device->DriverData->AdaptersList, &NumberOfAdapters);
            if (NT_SUCCESS(Status))
            {
                *((PDWORD)OutBuffer) = (DWORD)NumberOfAdapters.QuadPart;
                ReturnSize = (ULONG_PTR)sizeof(DWORD);
            }

        }break;

    case IOCTL_GET_ADAPTERS:
        {
            Status = Device_GetAdapters(
                Device->DriverData,
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

	DEBUGP_FUNC_LEAVE_WITH_STATUS(DL_TRACE, Status);

    return Status;
};