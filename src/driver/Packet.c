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
#include "Packet.h"
#include "..\shared\CommonDefs.h"

//////////////////////////////////////////////////////////////////////
// Packet methods
//////////////////////////////////////////////////////////////////////

PACKET* CreatePacket(
    __in    PVOID           Data,
    __in    ULONG           DataSize,
    __in    PLARGE_INTEGER  Timestamp)
{
    PPACKET NewPacket = NULL;
    ULONG   SizeRequired = (ULONG)sizeof(PACKET) + DataSize - 1;

    RETURN_VALUE_IF_FALSE(
        (Assigned(Data)) &&
        (DataSize > 0) &&
        (Assigned(Timestamp)),
        NULL);

    NewPacket = FILTER_ALLOC_MEM_TYPED_WITH_SIZE(PACKET, FilterDriverHandle, SizeRequired);
    RETURN_VALUE_IF_FALSE(
        Assigned(NewPacket),
        NULL);

    RtlZeroMemory(NewPacket, SizeRequired);

    NewPacket->DataSize = DataSize;
    RtlCopyMemory(
        &NewPacket->Timestamp, 
        Timestamp, 
        sizeof(LARGE_INTEGER));
    RtlCopyMemory(
        &NewPacket->Data,
        Data,
        DataSize);

    return NewPacket;
};

void FreePacket(
    __in    PPACKET Packet)
{
    RETURN_IF_FALSE(Assigned(Packet));

    FILTER_FREE_MEM(Packet);
}

void __stdcall ClearPacketList_ItemCallback(
    __in    PKM_LIST    List,
    __in    PLIST_ENTRY Item)
{
    PPACKET Packet = CONTAINING_RECORD(Item, PACKET, Link);

    UNREFERENCED_PARAMETER(List);

    RETURN_IF_FALSE(Assigned(Item));

    FreePacket(Packet);
};

void ClearPacketList(
    __in    PKM_LIST    List)
{
    RETURN_IF_FALSE(Assigned(List));

    Km_List_Clear(List, ClearPacketList_ItemCallback);
};