/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 This file contains the support functions used by packet.dll to retrieve information about installed 
 adapters, like

	- the adapter list
	- the device associated to any adapter and the description of the adapter
	- physical parameters like the linkspeed or the link layer type
	- the IP and link layer addresses  */

#define UNICODE 1

#pragma warning (disable : 4127)  //conditional expression is constant. Used for do{}while(FALSE) loops.

#if (MSC_VER < 1300)
#pragma warning (disable : 4710) // inline function not expanded. used for strsafe functions
#endif

//
// this should be removed in the long term.  GV 20080807
//
#define _CRT_SECURE_NO_DEPRECATE

#include <packet32.h>
#include "Packet32-Int.h"
#include "debug.h"

#include <windows.h>
#include <windowsx.h>
#include <Iphlpapi.h>
#include <strsafe.h>
#include <WpcapNames.h>


PADAPTER_INFO g_AdaptersInfoList = NULL;	///< Head of the adapter information list. This list is populated when packet.dll is linked by the application.
HANDLE g_AdaptersInfoMutex = NULL;		///< Mutex that protects the adapter information list. NOTE: every API that takes an ADAPTER_INFO as parameter assumes that it has been called with the mutex acquired.

extern FARPROC g_GetAdaptersAddressesPointer;

/// Title of error windows
TCHAR szWindowTitle[] = L"PACKET.DLL";

ULONG inet_addrU(const WCHAR *cp);

extern HKEY WinpcapKey;
extern WCHAR *WinPcapKeyBuffer;


/*! 
  \brief Gets the link layer of an adapter, querying the registry.
  \param AdapterObject Handle to an open adapter.
  \param type Pointer to a NetType structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero, otherwise the return value is zero.

  This function retrieves from the registry the link layer and the speed (in bps) of an opened adapter.
  These values are copied in the NetType structure provided by the user.
  The LinkType field of the type parameter can have one of the following values:

  - NdisMedium802_3: Ethernet (802.3) 
  - NdisMediumWan: WAN 
  - NdisMedium802_5: Token Ring (802.5) 
  - NdisMediumFddi: FDDI 
  - NdisMediumAtm: ATM 
  - NdisMediumArcnet878_2: ARCNET (878.2) 
*/
static BOOLEAN PacketGetLinkLayerFromRegistry(LPADAPTER AdapterObject, NetType *type)
{
	BOOLEAN    Status;
	ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
	PPACKET_OID_DATA  OidData;

	TRACE_ENTER("PacketGetLinkLayerFromRegistry");

	OidData=GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
	if (OidData == NULL) {
		TRACE_PRINT("PacketGetLinkLayerFromRegistry failed");
		TRACE_EXIT("PacketGetLinkLayerFromRegistry");
		return FALSE;
	}
	//get the link-layer type
	OidData->Oid = OID_GEN_MEDIA_IN_USE;
	OidData->Length = sizeof (ULONG);
	Status = PacketRequest(AdapterObject,FALSE,OidData);
	type->LinkType=*((UINT*)OidData->Data);

	//get the link-layer speed
	OidData->Oid = OID_GEN_LINK_SPEED;
	OidData->Length = sizeof (ULONG);
	Status = PacketRequest(AdapterObject,FALSE,OidData);

	if (Status == TRUE)
	{
		type->LinkSpeed=*((UINT*)OidData->Data)*100;
	}

	GlobalFreePtr (OidData);

	TRACE_PRINT2("Media:%.010d" "\t" "Speed=%0.10I64u",
		type->LinkType,
		type->LinkSpeed);

	TRACE_EXIT("PacketGetLinkLayerFromRegistry");
	return Status;
}


/*!
  \brief Scan the registry to retrieve the IP addresses of an adapter.
  \param AdapterName String that contains the name of the adapter.
  \param ppItems a caller allocated pointer to a pointer to address item, the function
    will set the pointer to the addresses retrieved from the registry
  \return If the function succeeds, the return value is nonzero.

  This function grabs from the registry information like the IP addresses, the netmasks 
  and the broadcast addresses of an interface. The buffer passed by the user is filled with 
  npf_if_addr structures, each of which contains the data for a single address. If the buffer
  is full, the reaming addresses are dropeed, therefore set its dimension to sizeof(npf_if_addr)
  if you want only the first address.
*/
static BOOLEAN PacketGetAddressesFromRegistry(LPCSTR AdapterNameA, PNPF_IF_ADDRESS_ITEM *ppItems)
{
	WCHAR	*IfNameW;
	WCHAR	AdapterNameW[ADAPTER_NAME_LENGTH];
	HKEY	SystemKey;
	HKEY	InterfaceKey;
	HKEY	ParametersKey;
	HKEY	TcpIpKey;
	HKEY	UnderTcpKey;
	LONG	status;
	WCHAR	String[1024+1];
	DWORD	RegType;
	ULONG	BufLen;
	DWORD	DHCPEnabled;
	struct	sockaddr_in *TmpAddr, *TmpBroad;
	LONG	naddrs,nmasks,StringPos;
	DWORD	ZeroBroadcast;
	PNPF_IF_ADDRESS_ITEM pHead = NULL;
	PNPF_IF_ADDRESS_ITEM pTail = NULL;
	PNPF_IF_ADDRESS_ITEM pItem;
//  
//	Old registry based WinPcap names
//
//	UINT	RegQueryLen;
//	WCHAR	npfDeviceNamesPrefix[MAX_WINPCAP_KEY_CHARS];
	WCHAR	npfDeviceNamesPrefix[MAX_WINPCAP_KEY_CHARS] = NPF_DEVICE_NAMES_PREFIX_WIDECHAR;
	
	TRACE_ENTER("PacketGetAddressesFromRegistry");
	
	StringCchPrintfW(AdapterNameW, ADAPTER_NAME_LENGTH, L"%S", AdapterNameA);

	IfNameW = wcsrchr(AdapterNameW, L'\\');
	if (IfNameW == NULL)
		IfNameW = AdapterNameW;
	else
		IfNameW++;

//  
//	Old registry based WinPcap names
//
//	RegQueryLen = sizeof(npfDeviceNamesPrefix)/sizeof(npfDeviceNamesPrefix[0]);
//	
//	if (QueryWinPcapRegistryStringW(TEXT(NPF_DEVICES_PREFIX_REG_KEY), npfDeviceNamesPrefix, &RegQueryLen, NPF_DEVICE_NAMES_PREFIX_WIDECHAR) == FALSE && RegQueryLen == 0)
//		return FALSE;
//	
//	if (wcsncmp(ifname, npfDeviceNamesPrefix, RegQueryLen) == 0)
//		ifname += RegQueryLen;

	if (wcsncmp(IfNameW, npfDeviceNamesPrefix, wcslen(npfDeviceNamesPrefix)) == 0)
				IfNameW += wcslen(npfDeviceNamesPrefix);

	if(	RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"), 0, KEY_READ, &UnderTcpKey) == ERROR_SUCCESS)
	{
		status = RegOpenKeyEx(UnderTcpKey,IfNameW,0,KEY_READ,&TcpIpKey);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
	}
	else
	{
		// Query the registry key with the interface's adresses
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,TEXT("SYSTEM\\CurrentControlSet\\Services"),0,KEY_READ,&SystemKey);
		if (status != ERROR_SUCCESS)
			goto fail;
		status = RegOpenKeyEx(SystemKey,IfNameW,0,KEY_READ,&InterfaceKey);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(SystemKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
		RegCloseKey(SystemKey);
		status = RegOpenKeyEx(InterfaceKey,TEXT("Parameters"),0,KEY_READ,&ParametersKey);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(InterfaceKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
		RegCloseKey(InterfaceKey);
		status = RegOpenKeyEx(ParametersKey,TEXT("TcpIp"),0,KEY_READ,&TcpIpKey);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(ParametersKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
		RegCloseKey(ParametersKey);
		BufLen = sizeof String;
	}

	BufLen = 4;
	/* Try to detect if the interface has a zero broadcast addr */
	status=RegQueryValueEx(TcpIpKey,TEXT("UseZeroBroadcast"),NULL,&RegType,(LPBYTE)&ZeroBroadcast,&BufLen);
	if (status != ERROR_SUCCESS)
		ZeroBroadcast=0;
	
	BufLen = 4;
	/* See if DHCP is used by this system */
	status=RegQueryValueEx(TcpIpKey,TEXT("EnableDHCP"),NULL,&RegType,(LPBYTE)&DHCPEnabled,&BufLen);
	if (status != ERROR_SUCCESS)
		DHCPEnabled=0;
	
	
	/* Retrieve the adrresses */
	if(DHCPEnabled)
	{
		naddrs = 0;
		BufLen = sizeof String;
		// Open the key with the addresses
		status = RegQueryValueEx(TcpIpKey,TEXT("DhcpIPAddress"),NULL,&RegType,(LPBYTE)String,&BufLen);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(TcpIpKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}

		// scan the key to obtain the addresses
		StringPos = 0;
		do
		{
			pItem = (PNPF_IF_ADDRESS_ITEM)GlobalAllocPtr(GPTR, sizeof(NPF_IF_ADDRESS_ITEM));
			if (pItem == NULL)
			{
				goto fail;
			}
			
			pItem->Next = NULL;

			TmpAddr = (struct sockaddr_in *) &pItem->Addr.IPAddress;
			TmpAddr->sin_addr.S_un.S_addr = inet_addrU(String + StringPos);
			
			if(TmpAddr->sin_addr.S_un.S_addr != -1)
			{
				TmpAddr->sin_family = AF_INET;
				
				TmpBroad = (struct sockaddr_in *) &pItem->Addr.Broadcast;
				TmpBroad->sin_family = AF_INET;
				if(ZeroBroadcast==0)
					TmpBroad->sin_addr.S_un.S_addr = 0xffffffff; // 255.255.255.255
				else
					TmpBroad->sin_addr.S_un.S_addr = 0; // 0.0.0.0

				while(*(String + StringPos) != 0)StringPos++;
			
				StringPos++;
				
				if (pHead == NULL)
				{
					pHead = pItem;
				}
				else
				{
					pTail->Next = pItem;
				}

				pTail = pItem;
				naddrs++;

				if(*(String + StringPos) == 0 || (StringPos * sizeof (WCHAR)) >= BufLen)
					break;				
			}
			else
			{
				GlobalFreePtr(pItem);
				pItem = NULL;
				break;
			}
		}while(TRUE);		
		
		BufLen = sizeof String;
		// Open the key with the netmasks
		status = RegQueryValueEx(TcpIpKey,TEXT("DhcpSubnetMask"),NULL,&RegType,(LPBYTE)String,&BufLen);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(TcpIpKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
		
		// scan the key to obtain the masks
		StringPos = 0;
		nmasks = 0;
		pItem = pHead;
		do
		{
			if (pItem == NULL)
			{
				//
				// there's an error
				//
				goto fail;
			}
			TmpAddr = (struct sockaddr_in *) &pItem->Addr.SubnetMask;
			
			if((TmpAddr->sin_addr.S_un.S_addr = inet_addrU(String + StringPos))!= -1){
				TmpAddr->sin_family = AF_INET;
				
				while(*(String + StringPos) != 0)StringPos++;
				StringPos++;
								
				pItem = pItem->Next;
				nmasks++;
				if(*(String + StringPos) == 0 || (StringPos * sizeof (WCHAR)) >= BufLen)
					break;


			}
			else break;
		}while(TRUE);		
		
		// The number of masks MUST be equal to the number of adresses
		if(nmasks != naddrs){
			RegCloseKey(TcpIpKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
				
	}
	else{
		
		naddrs = 0;
		BufLen = sizeof String;
		// Open the key with the addresses
		status = RegQueryValueEx(TcpIpKey,TEXT("IPAddress"),NULL,&RegType,(LPBYTE)String,&BufLen);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(TcpIpKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
		
		// scan the key to obtain the addresses
		StringPos = 0;
		do
		{
			pItem = (PNPF_IF_ADDRESS_ITEM)GlobalAllocPtr(GPTR, sizeof(NPF_IF_ADDRESS_ITEM));
			if (pItem == NULL)
			{
				goto fail;
			}
			
			pItem->Next = NULL;

			TmpAddr = (struct sockaddr_in *) &pItem->Addr.IPAddress;
			
			if((TmpAddr->sin_addr.S_un.S_addr = inet_addrU(String + StringPos))!= -1){
				TmpAddr->sin_family = AF_INET;

				TmpBroad = (struct sockaddr_in *) &pItem->Addr.Broadcast;
				TmpBroad->sin_family = AF_INET;
				if(ZeroBroadcast==0)
					TmpBroad->sin_addr.S_un.S_addr = 0xffffffff; // 255.255.255.255
				else
					TmpBroad->sin_addr.S_un.S_addr = 0; // 0.0.0.0
				
				while(*(String + StringPos) != 0)StringPos++;
				StringPos++;

				if (pHead == NULL)
				{
					pHead = pItem;
				}
				else
				{
					pTail->Next = pItem;
				}

				pTail = pItem;
				naddrs++;
				
				if(*(String + StringPos) == 0 || (StringPos * sizeof (WCHAR)) >= BufLen)
					break;
			}
			else
			{
				GlobalFreePtr(pItem);
				pItem = NULL;
				break;
			}
		}while(TRUE);		
		
		BufLen = sizeof String;
		// Open the key with the netmasks
		status = RegQueryValueEx(TcpIpKey,TEXT("SubnetMask"),NULL,&RegType,(LPBYTE)String,&BufLen);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(TcpIpKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
		
		// scan the key to obtain the masks
		StringPos = 0;
		nmasks = 0;
		pItem = pHead;

		do
		{
			if (pItem == NULL)
			{
				//
				// there's an error
				//
				goto fail;
			}

			TmpAddr = (struct sockaddr_in *) &pItem->Addr.SubnetMask;
			
			if((TmpAddr->sin_addr.S_un.S_addr = inet_addrU(String + StringPos))!= -1){
				TmpAddr->sin_family = AF_INET;
				
				while(*(String + StringPos) != 0)StringPos++;
				StringPos++;
				
				pItem = pItem->Next;
				nmasks++;

				if(*(String + StringPos) == 0 || (StringPos * sizeof (WCHAR)) >= BufLen)
					break;
			}
			else break;
		}while(TRUE);		
		
		// The number of masks MUST be equal to the number of adresses
		if(nmasks != naddrs){
			RegCloseKey(TcpIpKey);
			RegCloseKey(UnderTcpKey);
			goto fail;
		}
				
	}
	
	RegCloseKey(TcpIpKey);
	RegCloseKey(UnderTcpKey);
	
	if (status != ERROR_SUCCESS) {
		goto fail;
	}
	
	TRACE_PRINT("Successfully retrieved the addresses from the registry.");
	TRACE_EXIT("PacketGetAddressesFromRegistry");

	*ppItems = pHead;

	return TRUE;
	
fail:

	while(pHead != NULL)
	{
		pItem = pHead->Next;
		GlobalFreePtr(pHead);
		pHead = pItem;
	}

	TRACE_PRINT("Failed retrieving the addresses from the registry.");
	TRACE_EXIT("PacketGetAddressesFromRegistry");
    return FALSE;
}

BOOLEAN IsFireWire(TCHAR *AdapterDesc)
{
	TRACE_ENTER("IsFireWire");
	if(wcsstr(AdapterDesc, FIREWIRE_SUBSTR) != NULL)
	{		
		TRACE_EXIT("IsFireWire");
		return TRUE;
	}

	TRACE_EXIT("IsFireWire");
	return FALSE;
}

/*!
  \brief Adds an entry to the adapter description list.
  \param AdName Name of the adapter to add
  \return If the function succeeds, the return value is nonzero.

  Used by PacketGetAdapters(). Queries the registry to fill the PADAPTER_INFO describing the new adapter.
*/
static BOOLEAN PacketAddAdapterNPF(PCHAR AdName, UINT flags)
{
	//this function should acquire the g_AdaptersInfoMutex, since it's NOT called with an ADAPTER_INFO as parameter
	LONG		Status;
	LPADAPTER	adapter = NULL;
	PPACKET_OID_DATA  OidData = NULL;
	PADAPTER_INFO	TmpAdInfo;
	PADAPTER_INFO TAdInfo;	
	
	TRACE_ENTER("PacketAddAdapterNPF");
 	TRACE_PRINT1("Trying to add adapter %s", AdName);
	
	//
	// let's check that the adapter name will fit in the space available within ADAPTER_INFO::Name
	// If not, simply fail, since we cannot properly save the adapter name
	//
	if (strlen(AdName) + 1 > sizeof(TmpAdInfo->Name))
	{
		TRACE_PRINT("PacketAddAdapterNPF: adapter name is too long to be stored into ADAPTER_INFO::Name, simply skip it");
		return FALSE;
	}

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	
	for(TAdInfo = g_AdaptersInfoList; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(strcmp(AdName, TAdInfo->Name) == 0)
		{
			TRACE_PRINT("PacketAddAdapterNPF: Adapter already present in the list");
			ReleaseMutex(g_AdaptersInfoMutex);
			TRACE_EXIT("PacketAddAdapterNPF");
			return TRUE;
		}
	}
	
	//here we could have released the mutex, but what happens if two threads try to add the same adapter? 
	//The adapter would be duplicated on the linked list
	
	if(flags != INFO_FLAG_DONT_EXPORT)
	{	
 		TRACE_PRINT("Trying to open the NPF adapter and see if it's available...");

		// Try to Open the adapter
		adapter = PacketOpenAdapterNPF(AdName);
		
		if(adapter != NULL)
		{
			
			// Allocate a buffer to get the vendor description from the driver
			OidData = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,512);
			if (OidData == NULL) 
			{
				TRACE_PRINT("PacketAddAdapterNPF: GlobalAlloc Failed allocating the buffer for the OID request to obtain the NIC description. Returning."); 				
				PacketCloseAdapter(adapter);
				ReleaseMutex(g_AdaptersInfoMutex);
				TRACE_EXIT("PacketAddAdapterNPF");
				return FALSE;
			}
		}
		else
		{
			TRACE_PRINT("NPF Adapter not available, do not add it to the global list");
			// We are not able to open this adapter. Skip to the next one.
			ReleaseMutex(g_AdaptersInfoMutex);
			TRACE_EXIT("AddAdapter");
			return FALSE;
		}			
	}

	
	//
	// PacketOpenAdapter was succesful. Consider this a valid adapter and allocate an entry for it
	// In the adapter list
	//
	
	TmpAdInfo = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(ADAPTER_INFO));
	if (TmpAdInfo == NULL) 
	{
		TRACE_PRINT("AddAdapter: GlobalAlloc Failed");
	
		if(flags != INFO_FLAG_DONT_EXPORT)
		{ 
	 		TRACE_PRINT("AddAdapter: GlobalAlloc Failed allocating the buffer for the AdInfo to be added to the global list. Returning.");
			if (OidData != NULL) GlobalFreePtr(OidData);
			PacketCloseAdapter(adapter);
		}		
		
		ReleaseMutex(g_AdaptersInfoMutex);
 		TRACE_EXIT("AddAdapter");
		return FALSE;
	}
	
	// Copy the device name
	strncpy(TmpAdInfo->Name, AdName, sizeof(TmpAdInfo->Name)/ sizeof(TmpAdInfo->Name[0]) - 1);

	//we do not need to terminate the string TmpAdInfo->Name, since we have left a char at the end, and
	//the memory for TmpAdInfo was zeroed upon allocation

	if(flags != INFO_FLAG_DONT_EXPORT)
	{
		PNPF_IF_ADDRESS_ITEM pAddressesFromRegistry;

		// Retrieve the adapter description querying the NIC driver
		OidData->Oid = OID_GEN_VENDOR_DESCRIPTION;
		OidData->Length = 256;
		ZeroMemory(OidData->Data, 256);
		
		Status = PacketRequest(adapter, FALSE, OidData);
		
		if(Status==0 || ((char*)OidData->Data)[0]==0)
		{
			TRACE_PRINT("AddAdapter: unable to get a valid adapter description from the NIC driver");
		}
		
		TRACE_PRINT1("Adapter Description = %s",OidData->Data);
		
		// Copy the description
		strncpy(TmpAdInfo->Description, (PCHAR)OidData->Data, sizeof(TmpAdInfo->Description)/ sizeof(TmpAdInfo->Description[0]) - 1);
		//we do not need to terminate the string TmpAdInfo->Description, since we have left a char at the end, and
		//the memory for TmpAdInfo was zeroed upon allocation
		
		Status = PacketGetLinkLayerFromRegistry(adapter, &(TmpAdInfo->LinkLayer));

		if (Status == FALSE)
		{
			TRACE_PRINT("AddAdapter: PacketGetLinkLayerFromRegistry failed. Returning.");
			PacketCloseAdapter(adapter);
			GlobalFreePtr(OidData);
			GlobalFreePtr(TmpAdInfo);
			ReleaseMutex(g_AdaptersInfoMutex);
			TRACE_EXIT("AddAdapter");
			return FALSE;
		}
		
		// Retrieve the adapter MAC address querying the NIC driver
		OidData->Oid = OID_802_3_CURRENT_ADDRESS;	// XXX At the moment only Ethernet is supported.
													// Waiting a patch to support other Link Layers
		OidData->Length = 256;
		ZeroMemory(OidData->Data, 256);
		
		TRACE_PRINT("Trying to obtain the MAC address for the NIC...");
		Status = PacketRequest(adapter, FALSE, OidData);
		if(Status)
		{
			memcpy(TmpAdInfo->MacAddress, OidData->Data, 6);
			TmpAdInfo->MacAddressLen = 6;

			TRACE_PRINT6("Successfully obtained the MAC address, it's "
				"%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
				TmpAdInfo->MacAddress[0],
				TmpAdInfo->MacAddress[1],
				TmpAdInfo->MacAddress[2],
				TmpAdInfo->MacAddress[3],
				TmpAdInfo->MacAddress[4],
				TmpAdInfo->MacAddress[5]);


		}
		else
		{
			TRACE_PRINT("Failed obtaining the MAC address, put a fake 00:00:00:00:00:00");
			memset(TmpAdInfo->MacAddress, 0, 6);
			TmpAdInfo->MacAddressLen = 0;
		}
		
		// Retrieve IP addresses
		TmpAdInfo->pNetworkAddresses = NULL;
		
		if(!PacketGetAddressesFromRegistry(TmpAdInfo->Name, &pAddressesFromRegistry))
		{
		}
		else
		{
			PNPF_IF_ADDRESS_ITEM pCursor;

			if (TmpAdInfo->pNetworkAddresses == NULL)
			{
				TmpAdInfo->pNetworkAddresses = pAddressesFromRegistry;
			}
			else
			{
				pCursor = TmpAdInfo->pNetworkAddresses;
				while(pCursor->Next != NULL) pCursor = pCursor->Next;

				pCursor->Next = pAddressesFromRegistry;
			}
		}
		
		TmpAdInfo->Flags = INFO_FLAG_NDIS_ADAPTER;	// NdisWan adapters are not exported by the NPF driver,
													// therefore it's impossible to see them here
		
		// Free storage
		PacketCloseAdapter(adapter);
		GlobalFreePtr(OidData);
	}
	else
	{
		// Write in the flags that this adapter is firewire
		// This will block it in all successive calls
		TmpAdInfo->Flags = INFO_FLAG_DONT_EXPORT;
	}
	
	// Update the AdaptersInfo list
	TmpAdInfo->Next = g_AdaptersInfoList;
	g_AdaptersInfoList = TmpAdInfo;
	
	ReleaseMutex(g_AdaptersInfoMutex);

	TRACE_EXIT("AddAdapter");
	return TRUE;
}


/*!
  \brief Updates the list of the adapters querying the registry.
  \return If the function succeeds, the return value is nonzero.

  This function populates the list of adapter descriptions, retrieving the information from the registry. 
*/
static BOOLEAN PacketGetAdaptersNPF()
{
	HKEY		LinkageKey,AdapKey, OneAdapKey;
	DWORD		RegKeySize=0;
	LONG		Status;
	ULONG		Result;
	INT			i;
	DWORD		dim;
	DWORD		RegType;
	WCHAR		TName[256];
	CHAR		TAName[256];
	TCHAR		AdapName[256];
	CHAR		*TcpBindingsMultiString;
	UINT		FireWireFlag;
//  
//	Old registry based WinPcap names
//
//	CHAR		npfCompleteDriverPrefix[MAX_WINPCAP_KEY_CHARS];
//	UINT		RegQueryLen;

	CHAR		npfCompleteDriverPrefix[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_COMPLETE_DEVICE_PREFIX;
	CHAR		DeviceGuidName[256];

	TRACE_ENTER("PacketGetAdaptersNPF");
	
//  
//	Old registry based WinPcap names
//
//	// Get device prefixes from the registry
//	RegQueryLen = sizeof(npfCompleteDriverPrefix)/sizeof(npfCompleteDriverPrefix[0]);
//	
//	if (QueryWinPcapRegistryStringA(NPF_DRIVER_COMPLETE_DEVICE_PREFIX_REG_KEY, npfCompleteDriverPrefix, &RegQueryLen, NPF_DRIVER_COMPLETE_DEVICE_PREFIX) == FALSE && RegQueryLen == 0)
//		return FALSE;

	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"),
		0,
		KEY_READ,
		&AdapKey);
	
	if ( Status != ERROR_SUCCESS ){
		TRACE_PRINT("PacketGetAdaptersNPF: RegOpenKeyEx ( Class\\{networkclassguid} ) Failed");
		goto tcpip_linkage;
	}

	i = 0;

	TRACE_PRINT("PacketGetAdaptersNPF: RegOpenKeyEx ( Class\\{networkclassguid} ) was successful");
	TRACE_PRINT("PacketGetAdaptersNPF: Cycling through the adapters in the registry:");

	// 
	// Cycle through the entries inside the {4D36E972-E325-11CE-BFC1-08002BE10318} key
	// To get the names of the adapters
	//
	while((Result = RegEnumKey(AdapKey, i, AdapName, sizeof(AdapName)/2)) == ERROR_SUCCESS)
	{
		i++;
		FireWireFlag = 0;

		// 
		// Get the adapter name from the registry key
		//
		Status=RegOpenKeyEx(AdapKey, AdapName, 0, KEY_READ, &OneAdapKey);
		if ( Status != ERROR_SUCCESS )
		{
			TRACE_PRINT1("%d) RegOpenKey( OneAdapKey ) Failed, skipping the adapter.",i);
			continue;			
		}

		//
		//
		// Check if this is a FireWire adapter, looking for "1394" in its ComponentId string. 
		// We prevent listing FireWire adapters because winpcap can open them, but their interface
		// with the OS is broken and they can cause blue screens.
		//
		dim = sizeof(TName);
        Status = RegQueryValueEx(OneAdapKey, 
			TEXT("ComponentId"),
			NULL,
			NULL,
			(PBYTE)TName, 
			&dim);

		if(Status == ERROR_SUCCESS)
		{
			if(IsFireWire(TName))
			{
				FireWireFlag = INFO_FLAG_DONT_EXPORT;
			}
		}

		Status=RegOpenKeyEx(OneAdapKey, TEXT("Linkage"), 0, KEY_READ, &LinkageKey);
		if (Status != ERROR_SUCCESS)
		{
			RegCloseKey(OneAdapKey);
			TRACE_PRINT1("%d) RegOpenKeyEx ( LinkageKey ) Failed, skipping the adapter",i);
			continue;
		}
		
		dim = sizeof(DeviceGuidName);
        Status=RegQueryValueExA(LinkageKey, 
			"Export", 
			NULL, 
			NULL, 
			(PBYTE)DeviceGuidName, 
			&dim);

		if(Status != ERROR_SUCCESS)
		{
			RegCloseKey(OneAdapKey);
			RegCloseKey(LinkageKey);
			TRACE_PRINT1("%d) Name = SKIPPED (error reading the key)", i);
			continue;
		}

		if (strlen(DeviceGuidName) >= strlen("\\Device\\"))
		{
			// Put the \Device\NPF_ string at the beginning of the name
			StringCchPrintfA(TAName, sizeof(TAName), "%s%s",
			npfCompleteDriverPrefix,
			DeviceGuidName + strlen("\\Device\\"));
		}
		else
			continue;

		//terminate the string, just in case
		TAName[sizeof(TAName) - 1] = '\0';

		TRACE_PRINT2("%d) Successfully retrieved info for adapter %s, trying to add it to the global list...", i, TAName);
		// If the adapter is valid, add it to the list.
		PacketAddAdapterNPF(TAName, FireWireFlag);

		RegCloseKey(OneAdapKey);
		RegCloseKey(LinkageKey);
		
	} // while enum reg keys

	RegCloseKey(AdapKey);

tcpip_linkage:
	//
	// no adapters were found under {4D36E972-E325-11CE-BFC1-08002BE10318}. This means with great probability
	// that we are under Windows NT 4, so we try to look under the tcpip bindings.
	//
	
	TRACE_PRINT("Adapters not found under SYSTEM\\CurrentControlSet\\Control\\Class. Using the TCP/IP bindings.");
		
	Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Linkage"),
		0,
		KEY_READ,
		&LinkageKey);

	if (Status == ERROR_SUCCESS)
	{
		// Retrieve the length of th binde key
		// This key contains the name of the devices as \device\foo
		//in ASCII, separated by a single '\0'. The list is terminated
		//by another '\0'
		Status=RegQueryValueExA(LinkageKey,
			"bind",
			NULL,
			&RegType,
			NULL,
			&RegKeySize);

		// Allocate the buffer
		TcpBindingsMultiString = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, RegKeySize + 2);

		if (TcpBindingsMultiString == NULL)
		{
			TRACE_PRINT("GlobalAlloc failed allocating memory for the registry key, returning.");
			TRACE_EXIT("PacketGetAdaptersNPF");
			return FALSE;
		}
		
		// Query the key again to get its content		
		Status = RegQueryValueExA(LinkageKey,
			"bind",
			NULL,
			&RegType,
			(LPBYTE)TcpBindingsMultiString,
			&RegKeySize);
		
		RegCloseKey(LinkageKey);

		// Scan the buffer with the device names
		for(i = 0;;)
		{
			if (TcpBindingsMultiString[i] == '\0')
				break;
			
			StringCchPrintfA(TAName, sizeof(TAName), "%s%s", 
				npfCompleteDriverPrefix,
				TcpBindingsMultiString + i + strlen("\\Device\\"));

			//
			// TODO GV: this cast to avoid a compilation warning is
			//			actually stupid. We shouls check not to go over the buffer boundary!
			// 
			i += (INT)strlen(&TcpBindingsMultiString[i]) + 1;

			TRACE_PRINT1("Successfully retrieved info for adapter %s, trying to add it to the global list...", TAName);

			
			// If the adapter is valid, add it to the list.
			PacketAddAdapterNPF(TAName, 0);
		}
	
 		GlobalFreePtr(TcpBindingsMultiString);
	}
	
	TRACE_EXIT("PacketGetAdaptersNPF");
	return TRUE;
}

/*!
\brief Find the information about an adapter scanning the global ADAPTER_INFO list.
  \param AdapterName Name of the adapter whose information has to be retrieved.
  \return If the function succeeds, the return value is non-null.
*/
PADAPTER_INFO PacketFindAdInfo(PCHAR AdapterName)
{
	//this function should NOT acquire the g_AdaptersInfoMutex, since it does return an ADAPTER_INFO structure
	PADAPTER_INFO TAdInfo;

	TRACE_ENTER("PacketFindAdInfo");
	
	if (g_AdaptersInfoList == NULL)
	{
		TRACE_PRINT("Repopulating the adapters info list...");
		PacketPopulateAdaptersInfoList();
	}

	TAdInfo = g_AdaptersInfoList;
	
	while(TAdInfo != NULL)
	{
		if(strcmp(TAdInfo->Name, AdapterName) == 0) 
		{
			TRACE_PRINT1("Found AdInfo for adapter %s", AdapterName);
			break;
		}

		TAdInfo = TAdInfo->Next;
	}

	if (TAdInfo == NULL)
	{
		TRACE_PRINT1("NOT found AdInfo for adapter %s", AdapterName);
	}

	TRACE_EXIT("PacketFindAdInfo");
	return TAdInfo;
}



/*!
  \brief Updates information about an adapter in the global ADAPTER_INFO list.
  \param AdapterName Name of the adapter whose information has to be retrieved.
  \return If the function succeeds, the return value is TRUE. A false value means that the adapter is no
  more valid or that it is disconnected.
*/
BOOLEAN PacketUpdateAdInfo(PCHAR AdapterName)
{
	//this function should acquire the g_AdaptersInfoMutex, since it's NOT called with an ADAPTER_INFO as parameter
	PADAPTER_INFO TAdInfo, PrevAdInfo;

//  
//	Old registry based WinPcap names
//
//	UINT	RegQueryLen;
//	CHAR	FakeNdisWanAdapterName[MAX_WINPCAP_KEY_CHARS];
//
//	// retrieve the name for the fake ndis wan adapter
//	RegQueryLen = sizeof(FakeNdisWanAdapterName)/sizeof(FakeNdisWanAdapterName[0]);
//	if (QueryWinPcapRegistryStringA(NPF_FAKE_NDISWAN_ADAPTER_NAME_REG_KEY, FakeNdisWanAdapterName, &RegQueryLen, FAKE_NDISWAN_ADAPTER_NAME) == FALSE && RegQueryLen == 0)
//		return FALSE;
	
	TRACE_ENTER("PacketUpdateAdInfo");

	TRACE_PRINT1("Updating adapter info for adapter %s", AdapterName);
	
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	
	PrevAdInfo = TAdInfo = g_AdaptersInfoList;

	//
	// If an entry for this adapter is present in the list, we destroy it
	//
	while(TAdInfo != NULL)
	{
		if(strcmp(TAdInfo->Name, AdapterName) == 0)
		{
			if(TAdInfo == g_AdaptersInfoList)
			{
				g_AdaptersInfoList = TAdInfo->Next;
			}
			else
			{
				PrevAdInfo->Next = TAdInfo->Next;
			}

			if (TAdInfo->pNetworkAddresses != NULL)
			{
				PNPF_IF_ADDRESS_ITEM pItem, pNext;

				pItem = TAdInfo->pNetworkAddresses;

				while(pItem != NULL)
				{
					pNext = pItem->Next;

					GlobalFreePtr(pItem);
					pItem = pNext;
				}
			}
			
			GlobalFreePtr(TAdInfo);

			break;
		}

		PrevAdInfo = TAdInfo;

		TAdInfo = TAdInfo->Next;
	}

	ReleaseMutex(g_AdaptersInfoMutex);

	//
	// Now obtain the information about this adapter
	//
	if(PacketAddAdapterNPF(AdapterName, 0) == TRUE)
	{
		TRACE_EXIT("PacketUpdateAdInfo");
		return TRUE;
	}

	TRACE_EXIT("PacketUpdateAdInfo");
	return TRUE;
}

/*!
  \brief Populates the list of the adapters.

  This function populates the list of adapter descriptions, invoking first PacketGetAdapters() and then
  PacketGetAdaptersIPH(). 
*/
void PacketPopulateAdaptersInfoList()
{
	//this function should acquire the g_AdaptersInfoMutex, since it's NOT called with an ADAPTER_INFO as parameter
	PADAPTER_INFO TAdInfo;
	PVOID Mem2;

	TRACE_ENTER("PacketPopulateAdaptersInfoList");

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);

	if(g_AdaptersInfoList)
	{
		// Free the old list
		TAdInfo = g_AdaptersInfoList;
		while(TAdInfo != NULL)
		{
			PNPF_IF_ADDRESS_ITEM pItem, pCursor;
			Mem2 = TAdInfo;
			
			pCursor = TAdInfo->pNetworkAddresses;
			TAdInfo = TAdInfo->Next;
			
			while(pCursor != NULL)
			{
				pItem = pCursor->Next;
				GlobalFreePtr(pCursor);
				pCursor = pItem;
			}
			GlobalFreePtr(Mem2);
		}
		
		g_AdaptersInfoList = NULL;
	}

	//
	// Fill the new list
	//
	if(!PacketGetAdaptersNPF())
	{
		// No info about adapters in the registry. (NDIS adapters, i.e. exported by NPF)
		TRACE_PRINT("PacketPopulateAdaptersInfoList: registry scan for adapters failed!");
	}

	ReleaseMutex(g_AdaptersInfoMutex);
	TRACE_EXIT("PacketPopulateAdaptersInfoList");
}

