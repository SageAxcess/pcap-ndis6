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
// Lock helper functions
///////////////////////////////////////////////////

NDIS_SPIN_LOCK *CreateSpinLock()
{
	NDIS_SPIN_LOCK *lock = (NDIS_SPIN_LOCK*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(NDIS_SPIN_LOCK));
	NdisZeroMemory(lock, sizeof(NDIS_SPIN_LOCK));
	NdisAllocateSpinLock(lock);
	return lock;
}

void FreeSpinLock(PNDIS_SPIN_LOCK lock)
{
	if(!lock)
	{
		return;
	}
	FILTER_FREE_LOCK(lock);
	FILTER_FREE_MEM(lock);
}


///////////////////////////////////////////////////
// String helper functions
///////////////////////////////////////////////////

UNICODE_STRING* CreateString(const char* str)
{
	DEBUGP(DL_TRACE, "===>CreateString(%s)...\n", str);
	if(!str)
	{
		return NULL;
	}
	UNICODE_STRING* string = (UNICODE_STRING*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(UNICODE_STRING));
	if(!string)
	{
		return NULL;
	}

	NdisZeroMemory(string, sizeof(UNICODE_STRING));
	// Disable warning C6102: Using '*string' from failed function call at line '69'. 
	// Anyways, memory is allocated
#pragma warning( disable:6102 )
	NdisInitializeString(string, (unsigned char*)str);

	DEBUGP(DL_TRACE, "<===CreateString\n");
	return string;
}

UNICODE_STRING* CopyString(PUNICODE_STRING string)
{
	if(!string)
	{
		return NULL;
	}

	UNICODE_STRING* res = (UNICODE_STRING*)FILTER_ALLOC_MEM(FilterDriverObject, sizeof(UNICODE_STRING));
	if(!res)
	{
		return NULL;
	}
	res->Length = 0;
	res->MaximumLength = string->MaximumLength;
	res->Buffer = FILTER_ALLOC_MEM(FilterDriverObject, string->MaximumLength);
	RtlUnicodeStringCopy(res, string);
	return res;
}

void FreeString(UNICODE_STRING* string)
{
	if(!string)
	{
		return;
	}
	
	NdisFreeString(*string);
	FILTER_FREE_MEM(string);
}

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
}

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