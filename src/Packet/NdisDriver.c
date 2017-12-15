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

#include "Packet32.h"
#include "NdisDriver.h"
#include "..\shared\CommonDefs.h"
#include <stdio.h>

#ifdef DEBUG_CONSOLE
#define DEBUG_PRINT(x,...) printf(x, __VA_ARGS__)
#else
#define DEBUG_PRINT(x,...)
#endif

#ifndef ALIGN_SIZE
#define ALIGN_SIZE( sizeToAlign, PowerOfTwo )       \
        (((sizeToAlign) + (PowerOfTwo) - 1) & ~((PowerOfTwo) - 1))
#endif

PCAP_NDIS* NdisDriverOpen()
{	
    DEBUG_PRINT("===>NdisDriverOpen\n");

    HANDLE hFile = CreateFileA("\\\\.\\" ADAPTER_ID_PREFIX "" ADAPTER_NAME_FORLIST, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);	

    if(hFile == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT("    unable to open pipe!\n");
        return NULL; //TODO: install pcap-ndis6.sys?
    }

    PCAP_NDIS* ndis = (PCAP_NDIS*)malloc(sizeof(PCAP_NDIS));
    if(!ndis)
    {
        DEBUG_PRINT("    unable to allocate memory!\n");
        CloseHandle(hFile);
        return NULL;
    }

    ndis->handle = hFile;

    DEBUG_PRINT("<===NdisDriverOpen\n");

    return ndis;
}

void NdisDriverClose(PCAP_NDIS* ndis)
{
    DEBUG_PRINT("===>NdisDriverClose\n");
    if(!ndis)
    {
        return;
    }
    if(ndis->handle)
    {
        CloseHandle(ndis->handle);
    }
    free(ndis);
    DEBUG_PRINT("<===NdisDriverClose\n");
}

PCAP_NDIS_ADAPTER* NdisDriverOpenAdapter(PCAP_NDIS* ndis, const char* szAdapterId)
{
    DEBUG_PRINT("===>NdisDriverOpenAdapter(%s)\n", szAdapterId);
    if(!ndis)
    {
        return NULL;
    }

    char szFileName[1024];
    sprintf_s(szFileName, 1024, "\\\\.\\" ADAPTER_ID_PREFIX "%s", szAdapterId);

    HANDLE hFile = CreateFileA(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return NULL; //TODO: install?
    }

    PCAP_NDIS_ADAPTER* adapter = (PCAP_NDIS_ADAPTER*)malloc(sizeof(struct PCAP_NDIS_ADAPTER));
    if(!adapter)
    {
        DEBUG_PRINT("    unable to allocate memory!\n");
        CloseHandle(hFile);
        return NULL;
    }

    adapter->Handle = hFile;
    adapter->Stat.Captured = 0;
    adapter->Stat.Dropped = 0;
    adapter->Stat.Received = 0;
    adapter->BufferedPackets = 0;	
    adapter->BufferOffset = 0;

    DEBUG_PRINT("<===NdisDriverOpenAdapter\n");

    return adapter;
}

void NdisDriverCloseAdapter(PCAP_NDIS_ADAPTER* adapter)
{
    DEBUG_PRINT("===>NdisDriverCloseAdapter\n");

    if(!adapter)
    {
        return;
    }
    if(adapter->Handle)
    {
        CloseHandle(adapter->Handle);
    }
    free(adapter);

    DEBUG_PRINT("<===NdisDriverCloseAdapter\n");
}

BOOL NdisDriver_ControlDevice(
    __in        HANDLE  DeviceHandle,
    __in        DWORD   ControlCode,
    __in_opt    LPVOID  InBuffer,
    __in_opt    DWORD   InBufferSize,
    __out_opt   LPVOID  OutBuffer,
    __out_opt   DWORD   OutBufferSize,
    __out_opt   LPDWORD BytesReturned = NULL,
    __out_opt   LPDWORD ErrorCode = NULL)
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
        NULL);
    if (Assigned(ErrorCode))
    {
        *ErrorCode = GetLastError();
    }
    return Result;
};

BOOL NdisDriverNextPacket(
    __in    PCAP_NDIS_ADAPTER   *adapter,
    __out   void                **buf,
    __in    size_t              size,
    __out   DWORD*              dwBytesReceived)
{
    DEBUG_PRINT("===>NdisDriverNextPacket, buf size=%u\n", size);

    RETURN_VALUE_IF_FALSE(
        (Assigned(adapter)) &&
        (adapter->Handle != INVALID_HANDLE_VALUE),
        FALSE);

    *dwBytesReceived = 0;

    RETURN_VALUE_IF_FALSE(
        size >= sizeof(struct bpf_hdr),
        FALSE);

    if(adapter->BufferedPackets == 0)
    {
        DWORD   BytesReceived = 0;
        DWORD   ErrorCode = 0;

        if (!NdisDriver_ControlDevice(
            adapter->Handle,
            static_cast<DWORD>(IOCTL_READ_PACKETS),
            nullptr,
            0,
            adapter->ReadBuffer,
            READ_BUFFER_SIZE,
            &BytesReceived,
            &ErrorCode))
        {
            return FALSE;
        }

        adapter->BufferOffset = 0;
        DWORD curSize = 0;
        while (curSize < BytesReceived)
        {
            struct bpf_hdr* bpf = (struct bpf_hdr*)((unsigned char*)adapter->ReadBuffer + curSize);

            curSize += ALIGN_SIZE(bpf->bh_datalen + bpf->bh_hdrlen, 1024);
            adapter->BufferedPackets++;
        }
		Sleep(200);
    }

    if (adapter->BufferedPackets == 0)
    {
        *dwBytesReceived = 0;
    }
    else 
    {
        struct bpf_hdr* bpf = (struct bpf_hdr*)((unsigned char*)adapter->ReadBuffer + adapter->BufferOffset);

        UINT packetLen = bpf->bh_datalen + bpf->bh_hdrlen;
        if(size < packetLen)
        {
            *dwBytesReceived = 0;
            return FALSE;
        }

        memcpy(*buf, bpf, packetLen);
        *dwBytesReceived = packetLen;

        adapter->BufferedPackets--;
        adapter->BufferOffset += ALIGN_SIZE(packetLen, 1024);
    }

    DEBUG_PRINT("<===NdisDriverNextPacket(true)\n");

    return TRUE;
}

// Get adapter list
PCAP_NDIS_ADAPTER_LIST* NdisDriverGetAdapterList(PCAP_NDIS* ndis)
{
    DEBUG_PRINT("===>NdisDriverGetAdapterList\n");
    if (!ndis) {
        return NULL;
    }

    PCAP_NDIS_ADAPTER_LIST* list = (PCAP_NDIS_ADAPTER_LIST*)malloc(sizeof(PCAP_NDIS_ADAPTER_LIST));
    if(!list)
    {
        return NULL;
    }

    list->count = 0;
    list->adapters = NULL;

    DWORD dwBytesRead = 0;
    PCAP_NDIS_ADAPTER_LIST_HDR hdr;

    if(ReadFile(ndis->handle, &hdr, sizeof(PCAP_NDIS_ADAPTER_LIST_HDR), &dwBytesRead, NULL))
    {
        if(memcmp(hdr.Signature, SIGNATURE, 8))
        {
            NdisDriverFreeAdapterList(list);
            return NULL;
        }

        list->count = hdr.Count > MAX_ADAPTERS ? MAX_ADAPTERS : hdr.Count;		
        list->adapters = (PCAP_NDIS_ADAPTER_INFO*)malloc(sizeof(PCAP_NDIS_ADAPTER_INFO) * list->count);
        if(!list->adapters)
        {
            NdisDriverFreeAdapterList(list);
            return NULL;
        }

        for (int i = 0; i < list->count && i < MAX_ADAPTERS;i++)
        {
            if (!ReadFile(ndis->handle, &list->adapters[i], sizeof(PCAP_NDIS_ADAPTER_INFO), &dwBytesRead, NULL))
            {
                memset(list->adapters[i].AdapterId, 0, sizeof(list->adapters[i].AdapterId));
                memset(list->adapters[i].DisplayName, 0, sizeof(list->adapters[i].DisplayName));
                memset(list->adapters[i].MacAddress, 0, sizeof(list->adapters[i].MacAddress));
                list->adapters[i].MtuSize = 0;
            }
        }
    } else
    {
        NdisDriverFreeAdapterList(list);
        return NULL;
    }

    DEBUG_PRINT("<===NdisDriverGetAdapterList, size=%u\n", list->count);

    return list;
}

void NdisDriverFreeAdapterList(PCAP_NDIS_ADAPTER_LIST* list)
{
    DEBUG_PRINT("===>NdisDriverFreeAdapterList\n");

    if(!list)
    {
        return;
    }
    if(list->adapters)
    {
        free(list->adapters);
    }
    free(list);

    DEBUG_PRINT("<===NdisDriverFreeAdapterList\n");
}