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

#include <ntstatus.h>
#include <ntstrsafe.h>

#include "filter.h"
#include "KernelUtil.h"
#include "..\shared\CommonDefs.h"
#include <flt_dbg.h>

///////////////////////////////////////////////////
// String helper functions
///////////////////////////////////////////////////

PUNICODE_STRING CreateString(
    __in            PKM_MEMORY_MANAGER  MemoryManager,
    __in    const   char                *Str)
{
    PUNICODE_STRING NewString = NULL;
    USHORT          StrLen = 0;

    RETURN_VALUE_IF_FALSE(
        (Assigned(MemoryManager)) &&
        (Assigned(Str)),
        NULL);

    StrLen = (USHORT)strlen(Str);

    NewString = AllocateString(
        MemoryManager,
        StrLen);
    RETURN_VALUE_IF_FALSE(
        Assigned(NewString),
        NULL);

    RtlCopyMemory(
        NewString->Buffer,
        Str,
        StrLen);

    NewString->Length = StrLen;

	return NewString;
}

PUNICODE_STRING CopyString(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PUNICODE_STRING     SourceString)
{
    PUNICODE_STRING Result = NULL;

    RETURN_VALUE_IF_FALSE(
        (Assigned(MemoryManager)) &&
        (Assigned(SourceString)),
        NULL);

    Result = AllocateString(
        MemoryManager, 
        SourceString->MaximumLength);
    RETURN_VALUE_IF_FALSE(
        Assigned(Result),
        NULL);
    
    if (SourceString->Length > 0)
    {
        RtlCopyMemory(
            Result->Buffer,
            SourceString->Buffer,
            SourceString->Length);

        Result->Length = SourceString->Length;
    }

    return Result;
};

void FreeString(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    PUNICODE_STRING     String)
{
    RETURN_IF_FALSE(
        (Assigned(MemoryManager)) &&
        (Assigned(String)));

    if (Assigned(String->Buffer))
    {
        Km_MM_FreeMem(
            MemoryManager,
            String->Buffer);
    }

    Km_MM_FreeMem(
        MemoryManager,
        String);
};

PUNICODE_STRING AllocateString(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __in    USHORT              StringLengthInBytes)
{
    NTSTATUS        Status = STATUS_SUCCESS;
    PUNICODE_STRING Result = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INSUFFICIENT_RESOURCES);

    Result = Km_MM_AllocMemTyped(
        MemoryManager,
        UNICODE_STRING);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Result),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(Result, sizeof(UNICODE_STRING));

    if (StringLengthInBytes > 0)
    {
        Result->Buffer = Km_MM_AllocMemTypedWithSize(
            MemoryManager,
            wchar_t,
            StringLengthInBytes);

        GOTO_CLEANUP_IF_FALSE_SET_STATUS(
            Assigned(Result->Buffer),
            STATUS_INSUFFICIENT_RESOURCES);

        RtlZeroMemory(
            Result->Buffer,
            StringLengthInBytes);

        Result->MaximumLength = StringLengthInBytes;
    }

cleanup:
    
    if (!NT_SUCCESS(Status))
    {
        if (Assigned(Result))
        {
            Km_MM_FreeMem(
                MemoryManager,
                Result);
            Result = NULL;
        }
    }

    return Result;
};

///////////////////////////////////////////////////
// Other helper functions
///////////////////////////////////////////////////

void DriverSleep(long msec)
{
	KTIMER timer;
	RtlZeroMemory(&timer, sizeof(KTIMER));

	LARGE_INTEGER duetime;
	duetime.QuadPart = (__int64)msec * -10000;

	KeInitializeTimerEx(&timer, NotificationTimer);
	KeSetTimerEx(&timer, duetime, 0, NULL);

	KeWaitForSingleObject(&timer, Executive, KernelMode, FALSE, NULL);	
};

NTSTATUS __stdcall NetEventInfo_Allocate(
    __in    PKM_MEMORY_MANAGER  MemoryManager,
    __out   PNETWORK_EVENT_INFO *EventInfo)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PNETWORK_EVENT_INFO NewInfo = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EventInfo),
        STATUS_INVALID_PARAMETER_2);

    NewInfo = Km_MM_AllocMemTyped(
        MemoryManager,
        NETWORK_EVENT_INFO);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewInfo),
        STATUS_INSUFFICIENT_RESOURCES);

    RtlZeroMemory(
        NewInfo,
        sizeof(NETWORK_EVENT_INFO));

    *EventInfo = NewInfo;

cleanup:
    return Status;
};

NTSTATUS __stdcall NetEventInfo_FFB_TCP(
    __in    PVOID               Buffer,
    __in    ULONG               BufferSize,
    __inout PNETWORK_EVENT_INFO EventInfo)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PTCP_HEADER Header = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Buffer),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        BufferSize >= sizeof(TCP_HEADER),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EventInfo),
        STATUS_INVALID_PARAMETER_3);

    Header = (PTCP_HEADER)Buffer;

    EventInfo->Local.Port = Header->SourcePort;
    EventInfo->Remote.Port = Header->DestinationPort;

cleanup:
    return Status;
};

NTSTATUS __stdcall NetEventInfo_FFB_UDP(
    __in    PVOID               Buffer,
    __in    ULONG               BufferSize,
    __inout PNETWORK_EVENT_INFO EventInfo)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PUDP_HEADER Header = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Buffer),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        BufferSize >= sizeof(UDP_HEADER),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EventInfo),
        STATUS_INVALID_PARAMETER_3);

    Header = (PUDP_HEADER)Buffer;

    EventInfo->Local.Port = Header->SourcePort;
    EventInfo->Remote.Port = Header->DestinationPort;

cleanup:
    return Status;
};

NTSTATUS __stdcall NetEventInfo_FillFromBuffer(
    __in    PVOID               Buffer,
    __in    ULONG               BufferSize,
    __inout PNETWORK_EVENT_INFO EventInfo)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PETH_HEADER EthHeader = NULL;
    DWORD       IpHeaderLength;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Buffer),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        BufferSize > sizeof(ETH_HEADER),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EventInfo),
        STATUS_INVALID_PARAMETER_3);

    EthHeader = (PETH_HEADER)Buffer;

    switch (EthHeader->EthType)
    {
    case ETH_TYPE_IP_BE:
        {
            PIP4_HEADER Header = (PIP4_HEADER)(((PUCHAR)EthHeader) + sizeof(ETH_HEADER));

            IpHeaderLength = (Header->VerLen & 15) * 4;
            
            EventInfo->AddressFamily = AF_INET;

            EventInfo->IpProtocol = Header->Protocol;

            EventInfo->Local.Address.v4.l = Header->SourceAddress.l;

            EventInfo->Remote.Address.v4.l = Header->DestinationAddress.l;

            switch (Header->Protocol)
            {
            case IPPROTO_TCP:
                {
                    Status = NetEventInfo_FFB_TCP(
                        (PVOID)((PUCHAR)Header + IpHeaderLength),
                        BufferSize - sizeof(ETH_HEADER) - IpHeaderLength,
                        EventInfo);
                }break;

            case IPPROTO_UDP:
                {
                    Status = NetEventInfo_FFB_UDP(
                        (PVOID)((PUCHAR)Header + IpHeaderLength),
                        BufferSize - sizeof(ETH_HEADER) - IpHeaderLength,
                        EventInfo);
                }break;
            };

        }break;

    case ETH_TYPE_IP6_BE:
        {
            PIP6_HEADER Header = (PIP6_HEADER)((PUCHAR)Buffer + sizeof(ETH_HEADER));

            IpHeaderLength = sizeof(IP6_HEADER);
            
            EventInfo->AddressFamily = AF_INET6;
            EventInfo->IpProtocol = Header->NextHeader;

            RtlCopyMemory(
                &EventInfo->Local.Address,
                &Header->SourceAddress,
                sizeof(IP_ADDRESS_V6));
            RtlCopyMemory(
                &EventInfo->Remote.Address,
                &Header->DestinationAddress,
                sizeof(IP_ADDRESS_V6));

            switch (Header->NextHeader)
            {
            case IPPROTO_TCP:
                {
                    Status = NetEventInfo_FFB_TCP(
                        (PVOID)((PUCHAR)Header + IpHeaderLength),
                        BufferSize - sizeof(ETH_HEADER) - IpHeaderLength,
                        EventInfo);
                }break;

            case IPPROTO_UDP:
                {
                    Status = NetEventInfo_FFB_UDP(
                        (PVOID)((PUCHAR)Header + IpHeaderLength),
                        BufferSize - sizeof(ETH_HEADER) - IpHeaderLength,
                        EventInfo);
                }break;
            };

        }break;

    default:
        {
            Status = STATUS_NOT_SUPPORTED;
        }break;
    };
    
cleanup:
    return Status;
};

NTSTATUS __stdcall IOUtils_ProbeBuffer(
    __in    PVOID   Buffer,
    __in    ULONG   Length,
    __in    ULONG   Alignment,
    __in    ULONG   Flags)
{
    NTSTATUS	Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Buffer),
        STATUS_INVALID_PARAMETER_1);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Length > 0,
        STATUS_INVALID_PARAMETER_2);

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        IOUtils_ValidateProbeFlags(Flags),
        STATUS_INVALID_PARAMETER_4);

    __try
    {
        if (IsBitFlagSet(Flags, IOUTILS_PROBE_BUFFER_FLAG_READ))
        {
            ProbeForRead(Buffer, Length, Alignment);
        }
        if (IsBitFlagSet(Flags, IOUTILS_PROBE_BUFFER_FLAG_WRITE))
        {
            ProbeForWrite(Buffer, Length, Alignment);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_ACCESS_VIOLATION;
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall IOUtils_ValidateAndGetIOBuffers(
    __in	PIRP	Irp,
    __out	PVOID	*InBuffer,
    __out	PULONG	InLength,
    __out	PVOID	*OutBuffer,
    __out	PULONG	OutLength)
{
    NTSTATUS			Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION	IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ULONG				ControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;

    switch (METHOD_FROM_CTL_CODE(ControlCode))
    {
    #pragma region BUFFERED
    case METHOD_BUFFERED:
        {
            *InBuffer =
                *OutBuffer = Irp->AssociatedIrp.SystemBuffer;
            *InLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
            *OutLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
        }break;
    #pragma endregion

    #pragma region NEITHER
    case METHOD_NEITHER:
        {
            /*
                Caution: accessing the buffers should be performed at irql PASSIVE_LEVEL only
            */
            *InBuffer = IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
            *OutBuffer = Irp->UserBuffer;
            *InLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
            *OutLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

            if (*InLength > 0)
            {
                Status = IOUtils_ProbeBuffer(
                    *InBuffer,
                    *InLength,
                    1,
                    IOUTILS_PROBE_BUFFER_FLAG_READ);
                GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                    NT_SUCCESS(Status),
                    Status);
            }

            if (*OutLength > 0)
            {
                Status = IOUtils_ProbeBuffer(
                    *OutBuffer,
                    *OutLength,
                    1,
                    IOUTILS_PROBE_BUFFER_FLAG_WRITE);
                GOTO_CLEANUP_IF_FALSE_SET_STATUS(
                    NT_SUCCESS(Status),
                    Status);
            }
        }break;
    #pragma endregion

    #pragma region IN_DIRECT
    case METHOD_IN_DIRECT:
        {
            *InLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
            *OutLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

            *InBuffer = (*InLength > 0) ? Irp->AssociatedIrp.SystemBuffer : NULL;
            *OutBuffer =
                ((*OutLength > 0) && Assigned(Irp->MdlAddress)) ?
                MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority) :
                NULL;
        }break;
    #pragma endregion

    #pragma region OUT_DIRECT
    case METHOD_OUT_DIRECT:
        {
            *InLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
            *OutLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

            *InBuffer = (*InLength > 0) ? Irp->AssociatedIrp.SystemBuffer : NULL;
            *OutBuffer =
                ((*OutLength > 0) && Assigned(Irp->MdlAddress)) ?
                MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority) :
                NULL;
        }break;
    #pragma endregion

    #pragma region INVALID_METHOD
    default:
        {
            Status = STATUS_INVALID_PARAMETER;
        }break;
    #pragma endregion
    };

cleanup:
    return Status;
};