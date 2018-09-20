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
// All rights reserved.
//////////////////////////////////////////////////////////////////////

#include <winsock2.h>
#include <windows.h>

#include "..\shared\win_bpf.h"

#include "Packet32.h"
#include "NdisDriver.h"
#include "..\shared\CommonDefs.h"
#include <stdio.h>

#include <string>

#include "..\shared\StrUtils.h"
#include "PacketParser.h"

#include "Logging.h"

#include "..\shared\UmMemoryManager.h"

#include "..\shared\SharedTypes.h"

#ifdef DEBUG_CONSOLE
#define DEBUG_PRINT(x,...) printf(x, __VA_ARGS__)
#else
#define DEBUG_PRINT(x,...)
#endif

BOOL NdisDriver_ControlDevice(
    __in        HANDLE  DeviceHandle,
    __in        DWORD   ControlCode,
    __in_opt    LPVOID  InBuffer,
    __in_opt    DWORD   InBufferSize,
    __out_opt   LPVOID  OutBuffer,
    __out_opt   DWORD   OutBufferSize,
    __out_opt   LPDWORD BytesReturned = nullptr,
    __out_opt   LPDWORD ErrorCode = nullptr);

LPPCAP_NDIS NdisDriverOpen()
{
    LPPCAP_NDIS     Result = nullptr;
    HANDLE          FileHandle = INVALID_HANDLE_VALUE;
    DWORD           ErrorCode = 0;
    std::wstring    DeviceName = UTILS::STR::FormatW(
        L"\\\\.\\Global\\%s",
        FILTER_DEVICE_NAME_W);

    FileHandle = CreateFileW(
        DeviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        NULL);
    ErrorCode = GetLastError();

    RETURN_VALUE_IF_FALSE(
        FileHandle != INVALID_HANDLE_VALUE,
        nullptr);
    try
    {
        Result = UMM_AllocTyped<PCAP_NDIS>();
        if (Assigned(Result))
        {
            Result->Handle = FileHandle;
        }
    }
    catch (...)
    {
    }
    if (!Assigned(Result))
    {
        CloseHandle(FileHandle);
    }

    return Result;
};

void NdisDriverClose(
    __in    LPPCAP_NDIS Ndis)
{
    RETURN_IF_FALSE(Assigned(Ndis));

    if (Ndis->Handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(Ndis->Handle);
    }

    UMM_FreeMem(reinterpret_cast<LPVOID>(Ndis));
};

PPCAP_NDIS_ADAPTER NdisDriverOpenAdapter(
    __in    PPCAP_NDIS              Ndis,
    __in    PPCAP_NDIS_ADAPTER_ID   AdapterId)
{
    PPCAP_NDIS_ADAPTER                  Adapter = nullptr;
    PCAP_NDIS_OPEN_ADAPTER_REQUEST_DATA OpenRequestData;
    HANDLE                              NewPacketEvent = NULL;

    RETURN_VALUE_IF_FALSE(
        Assigned(Ndis),
        nullptr);

    NewPacketEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    RETURN_VALUE_IF_FALSE(
        NewPacketEvent != NULL,
        nullptr);

    RtlCopyMemory(
        &OpenRequestData.AdapterId,
        AdapterId,
        sizeof(PCAP_NDIS_ADAPTER_ID));

    OpenRequestData.EventHandle = ULONG_PTR(NewPacketEvent);
    RETURN_VALUE_IF_FALSE(
        OpenRequestData.EventHandle != NULL,
        nullptr);

    try
    {
        Adapter = UMM_AllocTyped<PCAP_NDIS_ADAPTER>();

        if (Assigned(Adapter))
        {
            RtlZeroMemory(Adapter, sizeof(PCAP_NDIS_ADAPTER));

            if (!NdisDriver_ControlDevice(
                Ndis->Handle,
                static_cast<DWORD>(IOCTL_OPEN_ADAPTER),
                reinterpret_cast<LPVOID>(&OpenRequestData),
                static_cast<DWORD>(sizeof(OpenRequestData)),
                reinterpret_cast<LPVOID>(&Adapter->ClientId),
                static_cast<DWORD>(sizeof(PCAP_NDIS_CLIENT_ID))))
            {
                UMM_FreeMem(reinterpret_cast<void *>(Adapter));
                return nullptr;
            }

            Adapter->NewPacketEvent = NewPacketEvent;
            Adapter->Ndis = Ndis;
        }
    }
    catch (...)
    {
    }
    if (!Assigned(Adapter))
    {
        CloseHandle(NewPacketEvent);
    }

    return Adapter;
};

void NdisDriverCloseAdapter(
    __in    LPPCAP_NDIS_ADAPTER Adapter)
{
    RETURN_IF_FALSE(Assigned(Adapter));
    
    if (Assigned(Adapter->Ndis))
    {
        NdisDriver_ControlDevice(
            Adapter->Ndis->Handle,
            static_cast<DWORD>(IOCTL_CLOSE_ADAPTER),
            reinterpret_cast<LPVOID>(&Adapter->ClientId),
            static_cast<DWORD>(sizeof(PCAP_NDIS_CLIENT_ID)),
            nullptr,
            0);
    }

    if (Adapter->NewPacketEvent != NULL)
    {
        CloseHandle(Adapter->NewPacketEvent);
    }

    UMM_FreeMem(Adapter);
};

BOOL NdisDriver_ControlDevice(
    __in        HANDLE  DeviceHandle,
    __in        DWORD   ControlCode,
    __in_opt    LPVOID  InBuffer,
    __in_opt    DWORD   InBufferSize,
    __out_opt   LPVOID  OutBuffer,
    __out_opt   DWORD   OutBufferSize,
    __out_opt   LPDWORD BytesReturned,
    __out_opt   LPDWORD ErrorCode)
{
    BOOL Result = FALSE;
    RETURN_VALUE_IF_FALSE(
        (DeviceHandle != NULL) &&
        (DeviceHandle != INVALID_HANDLE_VALUE),
        FALSE);

    DWORD BytesCnt = 0;
    if (BytesReturned == NULL)
    {
        BytesReturned = &BytesCnt;
    }

    Result = DeviceIoControl(
        DeviceHandle,
        ControlCode,
        InBuffer,
        InBufferSize,
        OutBuffer,
        OutBufferSize,
        BytesReturned,
        nullptr);
    if (Assigned(ErrorCode))
    {
        *ErrorCode = GetLastError();
    }
    return Result;
};

BOOL NdisDriverNextPacket(
    __in        LPPCAP_NDIS_ADAPTER Adapter,
    __out       LPVOID              *Buffer,
    __in        size_t              Size,
    __out       PDWORD              BytesReceived,
    __out_opt   PULONGLONG          ProcessId)
{
    RETURN_VALUE_IF_FALSE(
        (Assigned(Adapter)) &&
        (Assigned(BytesReceived)),
        FALSE);
    RETURN_VALUE_IF_FALSE(
        Assigned(Adapter->Ndis),
        FALSE);

    *BytesReceived = 0;

    RETURN_VALUE_IF_FALSE(
        Size >= sizeof(bpf_hdr),
        FALSE);

    if (Adapter->BufferedPackets == 0)
    {
        DWORD   BytesRead = 0;
        DWORD   ErrorCode = 0;

		Sleep(100); //This is for performance

        RETURN_VALUE_IF_FALSE(
            NdisDriver_ControlDevice(
                Adapter->Ndis->Handle,
                static_cast<DWORD>(IOCTL_READ_PACKETS),
                reinterpret_cast<LPVOID>(&Adapter->ClientId),
                static_cast<DWORD>(sizeof(PCAP_NDIS_CLIENT_ID)),
                Adapter->ReadBuffer,
                READ_BUFFER_SIZE,
                &BytesRead,
                &ErrorCode),
            FALSE);

        Adapter->BufferOffset = 0;
        
        DWORD   CurrentSize = 0;

        for (PUCHAR CurrentPtr = Adapter->ReadBuffer;
             (CurrentSize < BytesRead) && (CurrentSize < READ_BUFFER_SIZE);
             CurrentPtr = Adapter->ReadBuffer + CurrentSize)
        {
            pbpf_hdr2   bpf = reinterpret_cast<pbpf_hdr2>(CurrentPtr);
            CurrentSize += bpf->bh_datalen + bpf->bh_hdrlen;

            Adapter->BufferedPackets++;
        }
    }

    if (Adapter->BufferedPackets == 0)
    {
        *BytesReceived = 0;
    }

    if (Adapter->BufferedPackets > 0)
    {
        pbpf_hdr2   bpf = reinterpret_cast<pbpf_hdr2>(Adapter->ReadBuffer + Adapter->BufferOffset);
        ULONG       RequiredSize = bpf->bh_hdrlen + bpf->bh_datalen;
        PUCHAR      CurrentPtr;

		//printf("[packet.dll] Header: datalen=%d, caplen=%d, hdrlen=%d, pid=%d\n", bpf->bh_datalen, bpf->bh_caplen, bpf->bh_hdrlen, bpf->ProcessId);

        RETURN_VALUE_IF_FALSE(
            Size >= RequiredSize,
            FALSE);

        CurrentPtr = reinterpret_cast<PUCHAR>(*Buffer);

        RtlCopyMemory(
            reinterpret_cast<LPVOID>(CurrentPtr),
            reinterpret_cast<LPVOID>(bpf),
            RequiredSize);

        CurrentPtr += RequiredSize;

        *BytesReceived = RequiredSize;

        if (Assigned(ProcessId))
        {
            *ProcessId = bpf->ProcessId;
        }

        Adapter->BufferedPackets--;
        Adapter->BufferOffset += RequiredSize;
    }

    return TRUE;
};

BOOL NdisDriverQueryDiagInfo(
    __in    LPPCAP_NDIS_ADAPTER Adapter,
    __out   PULONGLONG          AllocationsCount,
    __out   PULONGLONG          AllocationSize)
{
    DRIVER_DIAG_INFORMATION DiagInfo;

    RETURN_VALUE_IF_FALSE(
        Assigned(Adapter),
        FALSE);
    RETURN_VALUE_IF_FALSE(
        Assigned(Adapter->Ndis),
        FALSE);

    RtlZeroMemory(&DiagInfo, sizeof(DiagInfo));

    RETURN_VALUE_IF_FALSE(
        NdisDriver_ControlDevice(
            Adapter->Ndis->Handle,
            static_cast<DWORD>(IOCTL_GET_DIAG_INFO),
            nullptr,
            0,
            reinterpret_cast<LPVOID>(&DiagInfo),
            static_cast<DWORD>(sizeof(DiagInfo))),
        FALSE);

    if (Assigned(AllocationsCount))
    {
        *AllocationsCount = 
            0 + 
            IsBitFlagSet(DiagInfo.Flags, DRIVER_DIAG_INFORMATION_FLAG_NDIS_MM_STATS) ? DiagInfo.NdisMMStats.AllocationsCount : 0 +
            IsBitFlagSet(DiagInfo.Flags, DRIVER_DIAG_INFORMATION_FLAG_WFP_MM_STATS) ? DiagInfo.WfpMMStats.AllocationsCount : 0;
    }

    if (Assigned(AllocationSize))
    {
        *AllocationSize =
            0 +
            IsBitFlagSet(DiagInfo.Flags, DRIVER_DIAG_INFORMATION_FLAG_NDIS_MM_STATS) ? DiagInfo.NdisMMStats.TotalBytesAllocated : 0 +
            IsBitFlagSet(DiagInfo.Flags, DRIVER_DIAG_INFORMATION_FLAG_WFP_MM_STATS) ? DiagInfo.WfpMMStats.TotalBytesAllocated : 0;
    }

    return TRUE;
};

// Get adapter list
LPPCAP_NDIS_ADAPTER_LIST NdisDriverGetAdapterList(PCAP_NDIS* ndis)
{
    ULONG                       AdaptersCount = 0;
    LPPCAP_NDIS_ADAPTER_LIST    List = nullptr;
    SIZE_T                      SizeRequired = 0;
    BOOL                        Failed = FALSE;

    RETURN_VALUE_IF_FALSE(
        Assigned(ndis),
        nullptr);

    RETURN_VALUE_IF_FALSE(
        NdisDriver_ControlDevice(
            ndis->Handle,
            static_cast<DWORD>(IOCTL_GET_ADAPTERS_COUNT),
            nullptr,
            0UL,
            reinterpret_cast<LPVOID>(&AdaptersCount),
            static_cast<DWORD>(sizeof(AdaptersCount))),
        nullptr);

    SizeRequired =
        sizeof(PCAP_NDIS_ADAPTER_LIST) +
        (AdaptersCount - 1) * sizeof(PCAP_NDIS_ADAPTER_INFO);

    List = UMM_AllocTypedWithSize<PCAP_NDIS_ADAPTER_LIST>(SizeRequired);
    RETURN_VALUE_IF_FALSE(
        Assigned(List),
        nullptr);
    __try
    {
        Failed = !NdisDriver_ControlDevice(
            ndis->Handle,
            static_cast<DWORD>(IOCTL_GET_ADAPTERS),
            nullptr,
            0,
            reinterpret_cast<LPVOID>(List),
			static_cast<DWORD>(SizeRequired));
    }
    __finally
    {
        if (Failed)
        {
            UMM_FreeMem(reinterpret_cast<void *>(List));
            List = nullptr;
        }
    }
    
    return List;
};

void NdisDriverFreeAdapterList(
    __in    LPPCAP_NDIS_ADAPTER_LIST    List)
{
    RETURN_IF_FALSE(Assigned(List));

    UMM_FreeMem(reinterpret_cast<LPVOID>(List));
};

std::wstring NdisDriver_PacketToString(
    __in    LPPACKET    Packet)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(Packet),
        L"");

    PACKET_DESC PacketDesc;

    RETURN_VALUE_IF_FALSE(
        UTILS::PKT::Parse(
            Packet->Buffer,
            Packet->Length,
            0,
            &PacketDesc),
        L"");

    return UTILS::PKT::PacketDescToStringW(&PacketDesc);
};

std::wstring NdisDriver_PacketExToString(
    __in    LPPACKET_EX Packet)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(Packet),
        L"");

    PACKET_DESC PacketDesc;

    RETURN_VALUE_IF_FALSE(
        UTILS::PKT::Parse(
            Packet->Packet.Buffer,
            Packet->Packet.Length,
            static_cast<ULONG>(Packet->ProcessId),
            &PacketDesc),
        L"");

    return UTILS::PKT::PacketDescToStringW(&PacketDesc);
};

void NdisDriverLogPacket(
    __in    LPPACKET    Packet)
{
    RETURN_IF_FALSE(Assigned(Packet));

    std::wstring    PacketStr = NdisDriver_PacketToString(Packet) + L'\n';

    LOG::LogMessage(PacketStr);
};

void NdisDriverLogPacketEx(
    __in    LPPACKET_EX Packet)
{
    RETURN_IF_FALSE(Assigned(Packet));

    std::wstring    PacketStr = NdisDriver_PacketExToString(Packet);

    LOG::LogMessage(PacketStr);
};