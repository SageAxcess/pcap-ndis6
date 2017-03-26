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
#define UNICODE 1

#pragma warning (disable : 4127)  //conditional expression is constant. Used for do{}while(FALSE) loops.

#if (MSC_VER < 1300)
#pragma warning (disable : 4710) // inline function not expanded. used for strsafe functions
#endif

//
// this should be removed in the long term.  GV 20080807
//
#define _CRT_SECURE_NO_WARNINGS

#include <packet32.h>
#include <StrSafe.h>

#include "Packet32-Int.h"
#include "NdisDriver.h"

#include "debug.h"
#include "Util.h"

#ifndef UNUSED
#define UNUSED(_x) (_x)
#endif

static PCAP_NDIS *ndis = NULL;

#ifdef _DEBUG_TO_FILE
LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName);
CHAR g_LogFileName[1024] = "winpcap_debug.txt";
#endif //_DEBUG_TO_FILE

#include <windows.h>
#include <windowsx.h>
#include <Iphlpapi.h>
#include <IPIfCons.h>

#include <WpcapNames.h>

char PacketLibraryVersion[64];  // Current packet-ndis6.dll Version. It can be retrieved directly or through the PacketGetVersion() function.
char PacketDriverVersion[64];   // Current pcap-ndis6.sys Version. It can be retrieved directly or through the PacketGetVersion() function.
char PacketDriverName[64];		// Current pcap-ndis6.sys driver name.

//
// Global adapters list related variables
//
extern PADAPTER_INFO g_AdaptersInfoList;
extern HANDLE g_AdaptersInfoMutex;

//
// Dynamic dependencies variables and declarations
//
volatile LONG g_DynamicLibrariesLoaded = 0;
HANDLE g_DynamicLibrariesMutex;

BOOLEAN PacketAddAdapterDag(PCHAR name, PCHAR description, BOOLEAN IsAFile);

//---------------------------------------------------------------------------

BOOL APIENTRY DllMain(HANDLE DllHandle,DWORD Reason,LPVOID lpReserved)
{
    BOOLEAN Status=TRUE;
	PADAPTER_INFO NewAdInfo;
	TCHAR DllFileName[MAX_PATH];

	UNUSED(lpReserved);

    switch(Reason)
    {
	case DLL_PROCESS_ATTACH:

		TRACE_PRINT_DLLMAIN("************Packet32: DllMain************");

#ifdef _DEBUG_TO_FILE
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" NPF_DRIVER_NAME,"aegis.reg");
		
		// dump a bunch of registry keys useful for debug to file
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
			"adapters.reg");
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip",
			"tcpip.reg");
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
			"services.reg");

#endif

		// Create the mutex that will protect the adapter information list
		g_AdaptersInfoMutex = CreateMutex(NULL, FALSE, NULL);		
		// Create the mutex that will protect the PacketLoadLibrariesDynamically() function		
		g_DynamicLibrariesMutex = CreateMutex(NULL, FALSE, NULL);

		//
		// Retrieve packet.dll version information from the file
		//
		if(GetModuleFileName(DllHandle, DllFileName, sizeof(DllFileName) / sizeof(DllFileName[0])) > 0)
		{
			PacketGetFileVersion(DllFileName, PacketLibraryVersion, sizeof(PacketLibraryVersion));
		}

		strcpy_s(PacketDriverVersion, sizeof(PacketDriverVersion), "unknown");
		strcpy_s(PacketDriverName, sizeof(PacketDriverName), "pcap-ndis6");

		//
		// Retrieve driver version information from the file. 
    	// TODO: check in x64, probably doesn't work well
		//
		PacketGetFileVersion(TEXT("drivers\\") TEXT(NPF_DRIVER_NAME) TEXT(".sys"), PacketDriverVersion, sizeof(PacketDriverVersion));
		
		break;
		
	case DLL_PROCESS_DETACH:
		CloseHandle(g_AdaptersInfoMutex);
		
		g_AdaptersInfoList;
		
		//TODO: Move to function
		while(g_AdaptersInfoList != NULL)
		{
			PNPF_IF_ADDRESS_ITEM pCursor, pNext;

			NewAdInfo = g_AdaptersInfoList->Next;

			pCursor = g_AdaptersInfoList->pNetworkAddresses;

			while(pCursor != NULL)
			{
				pNext = pCursor->Next;
				GlobalFreePtr(pCursor);
				pCursor = pNext;
			}

			GlobalFreePtr(g_AdaptersInfoList);
			
			g_AdaptersInfoList = NewAdInfo;
		}

#ifdef WPCAP_OEM_UNLOAD_H 
		if(g_WoemLeaveDllH)
		{
			g_WoemLeaveDllH();
		}
#endif // WPCAP_OEM_UNLOAD_H

		break;
		
	default:
		break;
    }
	
    return Status;
}

/*! 
  \brief Convert a Unicode dotted-quad to a 32-bit IP address.
  \param cp A string containing the address.
  \return the converted 32-bit numeric address.

   Doesn't check to make sure the address is valid.
*/
ULONG inet_addrU(const WCHAR *cp)
{
	ULONG val, part;
	WCHAR c;
	int i;

	val = 0;
	for (i = 0; i < 4; i++) {
		part = 0;
		while ((c = *cp++) != '\0' && c != '.') {
			if (c < '0' || c > '9')
				return (ULONG)-1;
			part = part*10 + (c - '0');
		}
		if (part > 255)
			return (ULONG)-1;	
		val = val | (part << i*8);
		if (i == 3) {
			if (c != '\0')
				return (ULONG)-1;	// extra gunk at end of string 
		} else {
			if (c == '\0')
				return (ULONG)-1;	// string ends early 
		}
	}
	return val;
}

/*! 
  \brief Converts an ASCII string to UNICODE. Uses the MultiByteToWideChar() system function.
  \param string The string to convert.
  \return The converted string.
*/
static PWCHAR SChar2WChar(PCHAR string)
{
	PWCHAR TmpStr;
	TmpStr = (WCHAR*) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, (DWORD)(strlen(string)+2)*sizeof(WCHAR));

	MultiByteToWideChar(CP_ACP, 0, string, -1, TmpStr, (DWORD)(strlen(string)+2));

	return TmpStr;
}

/*! 
  \brief Converts an UNICODE string to ASCII. Uses the WideCharToMultiByte() system function.
  \param string The string to convert.
  \return The converted string.
*/
static PCHAR WChar2SChar(PWCHAR string)
{
	PCHAR TmpStr;
	TmpStr = (CHAR*) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, (DWORD)(wcslen(string)+2));

	// Conver to ASCII
	WideCharToMultiByte(
		CP_ACP,
		0,
		string,
		-1,
		TmpStr,
		(DWORD)(wcslen(string)+2),          // size of buffer
		NULL,
		NULL);

	return TmpStr;
}

/*! 
  \brief Sets the maximum possible lookahead buffer for the driver's Packet_tap() function.
  \param AdapterObject Handle to the service control manager.
  \return If the function succeeds, the return value is nonzero.

  The lookahead buffer is the portion of packet that Packet_tap() can access from the NIC driver's memory
  without performing a copy. This function tries to increase the size of that buffer.

  NOTE: this function is used for NPF adapters, only.
*/

BOOLEAN PacketSetMaxLookaheadsize (LPADAPTER AdapterObject)
{
    BOOLEAN    Status;
    ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
    PPACKET_OID_DATA  OidData;

	TRACE_ENTER("PacketSetMaxLookaheadsize");

    OidData = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
    if (OidData == NULL) {
        TRACE_PRINT("PacketSetMaxLookaheadsize failed");
        Status = FALSE;
    }
	else
	{
		//set the size of the lookahead buffer to the maximum available by the the NIC driver
		OidData->Oid=OID_GEN_MAXIMUM_LOOKAHEAD;
		OidData->Length=sizeof(ULONG);
		Status=PacketRequest(AdapterObject,FALSE,OidData);
		OidData->Oid=OID_GEN_CURRENT_LOOKAHEAD;
		Status=PacketRequest(AdapterObject,TRUE,OidData);
		GlobalFreePtr(OidData);
	}

	TRACE_EXIT("PacketSetMaxLookaheadsize");
	return Status;
}

BOOLEAN PacketSetReadEvt(LPADAPTER AdapterObject)
{
	DWORD BytesReturned;
	HANDLE hEvent;

 	TRACE_ENTER("PacketSetReadEvt");

	if (AdapterObject->ReadEvent != NULL)
	{
		SetLastError(ERROR_INVALID_FUNCTION);
		return FALSE;
	}

 	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (hEvent == NULL)
	{
		//SetLastError done by CreateEvent	
 		TRACE_EXIT("PacketSetReadEvt");
		return FALSE;
	}

	AdapterObject->ReadEvent = hEvent;
	AdapterObject->ReadTimeOut = 0;

	TRACE_EXIT("PacketSetReadEvt");
	return TRUE;
}

/*! 
  \brief Installs the NPF device driver.
  \return If the function succeeds, the return value is nonzero.

  This function installs the driver's service in the system using the CreateService function.
*/

BOOLEAN PacketInstallDriver()
{
	BOOLEAN result = FALSE;
	ULONG err = 0;
	SC_HANDLE svcHandle;
	SC_HANDLE scmHandle;
//  
//	Old registry based WinPcap names
//
//	CHAR driverName[MAX_WINPCAP_KEY_CHARS];
//	CHAR driverDesc[MAX_WINPCAP_KEY_CHARS];
//	CHAR driverLocation[MAX_WINPCAP_KEY_CHARS;
//	UINT len;

	CHAR driverName[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_NAME;
	CHAR driverDesc[MAX_WINPCAP_KEY_CHARS] = NPF_SERVICE_DESC;
	CHAR driverLocation[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_COMPLETE_PATH;

 	TRACE_ENTER("PacketInstallDriver");

//  
//	Old registry based WinPcap names
//
//	len = sizeof(driverName)/sizeof(driverName[0]);
//	if (QueryWinPcapRegistryStringA(NPF_DRIVER_NAME_REG_KEY, driverName, &len, NPF_DRIVER_NAME) == FALSE && len == 0)
//		return FALSE;
//
//	len = sizeof(driverDesc)/sizeof(driverDesc[0]);
//	if (QueryWinPcapRegistryStringA(NPF_SERVICE_DESC_REG_KEY, driverDesc, &len, NPF_SERVICE_DESC) == FALSE && len == 0)
//		return FALSE;
//
//	len = sizeof(driverLocation)/sizeof(driverLocation[0]);
//	if (QueryWinPcapRegistryStringA(NPF_DRIVER_COMPLETE_PATH_REG_KEY, driverLocation, &len, NPF_DRIVER_COMPLETE_PATH) == FALSE && len == 0)
//		return FALSE;
	
	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	
	if(scmHandle == NULL)
		return FALSE;

	svcHandle = CreateServiceA(scmHandle, 
		driverName,
		driverDesc,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		driverLocation,
		NULL, NULL, NULL, NULL, NULL);
	if (svcHandle == NULL) 
	{
		err = GetLastError();
		if (err == ERROR_SERVICE_EXISTS) 
		{
			TRACE_PRINT("Service npf.sys already exists");
			//npf.sys already existed
			err = 0;
			result = TRUE;
		}
	}
	else 
	{
		TRACE_PRINT("Created service for npf.sys");
		//Created service for npf.sys
		result = TRUE;
	}

	if (svcHandle != NULL)
		CloseServiceHandle(svcHandle);

	if(result == FALSE)
	{
		TRACE_PRINT1("PacketInstallDriver failed, Error=%u",err);
	}

	CloseServiceHandle(scmHandle);
	SetLastError(err);
	TRACE_EXIT("PacketInstallDriver");
	return result;
	
}

/*! 
  \brief Dumps a registry key to disk in text format. Uses regedit.
  \param KeyName Name of the ket to dump. All its subkeys will be saved recursively.
  \param FileName Name of the file that will contain the dump.
  \return If the function succeeds, the return value is nonzero.

  For debugging purposes, we use this function to obtain some registry keys from the user's machine.
*/

#ifdef _DEBUG_TO_FILE

LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName)
{
	CHAR Command[256];

	TRACE_ENTER("PacketDumpRegistryKey");
	StringCchPrintfA(Command, sizeof(Command), "regedit /e %s %s", FileName, KeyName);

	/// Let regedit do the dirty work for us
	system(Command);

	TRACE_EXIT("PacketDumpRegistryKey");
	return TRUE;
}
#endif

/*! 
  \brief Returns the version of a dll or exe file 
  \param FileName Name of the file whose version has to be retrieved.
  \param VersionBuff Buffer that will contain the string with the file version.
  \param VersionBuffLen Length of the buffer poited by VersionBuff.
  \return If the function succeeds, the return value is TRUE.

  \note uses the GetFileVersionInfoSize() and GetFileVersionInfo() WIN32 API functions
*/
BOOL PacketGetFileVersion(LPTSTR FileName, PCHAR VersionBuff, UINT VersionBuffLen)
{
    DWORD   dwVerInfoSize;  // Size of version information block
    DWORD   dwVerHnd=0;   // An 'ignored' parameter, always '0'
	LPSTR   lpstrVffInfo;
	UINT	cbTranslate, dwBytes;
	TCHAR	SubBlock[64];
	PVOID	lpBuffer;
	PCHAR	TmpStr;
	
	// Structure used to store enumerated languages and code pages.
	struct LANGANDCODEPAGE {
	  WORD wLanguage;
	  WORD wCodePage;
	} *lpTranslate;

	TRACE_ENTER("PacketGetFileVersion");

	// Now lets dive in and pull out the version information:
    dwVerInfoSize = GetFileVersionInfoSize(FileName, &dwVerHnd);
    if (dwVerInfoSize) 
	{
        lpstrVffInfo = GlobalAllocPtr(GMEM_MOVEABLE, dwVerInfoSize);
		if (lpstrVffInfo == NULL)
		{
			TRACE_PRINT("PacketGetFileVersion: failed to allocate memory");
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		if(!GetFileVersionInfo(FileName, dwVerHnd, dwVerInfoSize, lpstrVffInfo)) 
		{
			TRACE_PRINT("PacketGetFileVersion: failed to call GetFileVersionInfo");
            GlobalFreePtr(lpstrVffInfo);
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		// Read the list of languages and code pages.
		if(!VerQueryValue(lpstrVffInfo,	TEXT("\\VarFileInfo\\Translation"),	(LPVOID*)&lpTranslate, &cbTranslate))
		{
			TRACE_PRINT("PacketGetFileVersion: failed to call VerQueryValue");
            GlobalFreePtr(lpstrVffInfo);
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}
		
		// Create the file version string for the first (i.e. the only one) language.
		StringCchPrintf(SubBlock,
			sizeof(SubBlock)/sizeof(SubBlock[0]),
			TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"),
			(*lpTranslate).wLanguage,
			(*lpTranslate).wCodePage);
		
		// Retrieve the file version string for the language.
		if(!VerQueryValue(lpstrVffInfo, SubBlock, &lpBuffer, &dwBytes))
		{
			TRACE_PRINT("PacketGetFileVersion: failed to call VerQueryValue");
            GlobalFreePtr(lpstrVffInfo);
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		// Convert to ASCII
		TmpStr = WChar2SChar(lpBuffer);

		if(strlen(TmpStr) >= VersionBuffLen)
		{
			TRACE_PRINT("PacketGetFileVersion: Input buffer too small");
            GlobalFreePtr(lpstrVffInfo);
            GlobalFreePtr(TmpStr);
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		StringCchCopyA(VersionBuff, VersionBuffLen, TmpStr);

        GlobalFreePtr(lpstrVffInfo);
        GlobalFreePtr(TmpStr);
		
	  } 
	else 
	{
		TRACE_PRINT1("PacketGetFileVersion: failed to call GetFileVersionInfoSize, LastError = %8.8x", GetLastError());
		TRACE_EXIT("PacketGetFileVersion");
		return FALSE;
	
	} 
	
	TRACE_EXIT("PacketGetFileVersion");
	return TRUE;
}


//---------------------------------------------------------------------------
// PUBLIC API
//---------------------------------------------------------------------------

PCHAR PacketGetVersion()
{
	return PacketLibraryVersion;
}

PCHAR PacketGetDriverVersion()
{
	return PacketDriverVersion;
}

PCHAR PacketGetDriverName()
{
	TRACE_ENTER();
	TRACE_EXIT();
	return PacketDriverName;
}

BOOL PacketStopDriver()
{
	return FALSE; // Not possible to unload ndis 6.x driver
}

LPADAPTER PacketOpenAdapter(PCHAR AdapterNameWA)
{
	if (!ndis) {
		ndis = NdisDriverOpen();
		//TODO: use mutex here!
	}

	PCAP_NDIS_ADAPTER_INFO *adapter = NULL;
	ADAPTER *result = NULL;

	PCAP_NDIS_ADAPTER_LIST* list = NdisDriverGetAdapterList(ndis);
	if (list) {
		for (int i = 0; i < list->count; i++)
		{
			if (!strcmp(list->adapters[i].AdapterId, AdapterNameWA))
			{
				adapter = &list->adapters[i];
				break;
			}
		}

		if (adapter)
		{
			result = (ADAPTER*)malloc(sizeof(ADAPTER));

			result->hFile = NdisDriverOpenAdapter(ndis, adapter->AdapterId);
			result->FilterLock = PacketCreateMutex();
			result->Flags = INFO_FLAG_NDIS_ADAPTER;

			strcpy_s(result->SymbolicLink, sizeof(result->SymbolicLink), adapter->DeviceName);
			strcpy_s(result->Name, sizeof(result->Name), adapter->AdapterId);
		}

		NdisDriverFreeAdapterList(list);
	}

	return result;
}

/*! 
  \brief Closes an adapter.
  \param lpAdapter the pointer to the adapter to close. 

  PacketCloseAdapter closes the given adapter and frees the associated ADAPTER structure
*/
VOID PacketCloseAdapter(LPADAPTER lpAdapter)
{
	TRACE_ENTER("PacketCloseAdapter");
	if(!lpAdapter)
	{
        TRACE_PRINT("PacketCloseAdapter: attempt to close a NULL adapter");
		TRACE_EXIT("PacketCloseAdapter");
		return;
	}
	NdisDriverCloseAdapter((struct PCAP_NDIS_ADAPTER*)lpAdapter->hFile);

	if(lpAdapter->Filter!=NULL)
	{
		PacketLockMutex(lpAdapter->FilterLock);

		free(lpAdapter->Filter->bf_insns);
		free(lpAdapter->Filter);

		lpAdapter->Filter = NULL;

		PacketUnlockMutex(lpAdapter->FilterLock);
	}

	PacketReleaseMutex(lpAdapter->FilterLock);

	GlobalFreePtr(lpAdapter);
}

LPPACKET PacketAllocatePacket(void)
{
    LPPACKET    lpPacket;

	TRACE_ENTER("PacketAllocatePacket");
    
	lpPacket=(LPPACKET)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,sizeof(PACKET));
    if (lpPacket==NULL)
    {
        TRACE_PRINT("PacketAllocatePacket: GlobalAlloc Failed");
    }

	TRACE_EXIT("PacketAllocatePacket");
    
	return lpPacket;
}

VOID PacketFreePacket(LPPACKET lpPacket)

{
	TRACE_ENTER("PacketFreePacket");
    GlobalFreePtr(lpPacket);
	TRACE_EXIT("PacketFreePacket");
}

VOID PacketInitPacket(LPPACKET lpPacket,PVOID Buffer,UINT Length)

{
	TRACE_ENTER("PacketInitPacket");

    lpPacket->Buffer = Buffer;
    lpPacket->Length = Length;
	lpPacket->ulBytesReceived = 0;
	lpPacket->bIoComplete = FALSE;

	TRACE_EXIT("PacketInitPacket");
}

BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
	BOOLEAN res;

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		if((int)AdapterObject->ReadTimeOut != -1)
			WaitForSingleObject(AdapterObject->ReadEvent, (AdapterObject->ReadTimeOut==0)?INFINITE:AdapterObject->ReadTimeOut);
	
		res = (BOOLEAN)ReadFile(AdapterObject->hFile, lpPacket->Buffer, lpPacket->Length, &lpPacket->ulBytesReceived,NULL);
	}
	else
	{
		TRACE_PRINT1("Request to read on an unknown device type (%u)", AdapterObject->Flags);
		res = FALSE;
	}
	
	TRACE_EXIT("PacketReceivePacket");
	return res;
}

BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
	TRACE_PRINT("PacketSendPacket not supported in this version");
	return FALSE; //TODO: Not supported at the moment
}

INT PacketSendPackets(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync)
{
	TRACE_PRINT("PacketSendPackets not supported in this version");
	return 0; //TODO: Not supported at the moment
}

BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes)
{
	TRACE_PRINT("PacketSetMinToCopy not supported in this version");
	return TRUE;
}


BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode)
{
	TRACE_PRINT("PacketSetMode not supported in this version");
	if(mode==PACKET_MODE_CAPT)
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len)
{
	TRACE_PRINT("PacketSetDumpName not supported in this version");
	return FALSE;
}

BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks)
{
	TRACE_PRINT("PacketSetDumpLimits not supported in this version");
	return FALSE;
}

BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync)
{
	TRACE_PRINT("PacketIsDumpEnded not supported in this version");
	return FALSE;
}

HANDLE PacketGetReadEvent(LPADAPTER AdapterObject)
{
	TRACE_ENTER("PacketGetReadEvent");
	TRACE_EXIT("PacketGetReadEvent");
    return AdapterObject->ReadEvent;
}

BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites)
{
	TRACE_PRINT("PacketSetNumWrites not supported in this version");
	return FALSE;
}

BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout)
{
	if(AdapterObject==NULL)
	{
		return FALSE;
	}
	if(timeout<0)
	{
		timeout = 0;
	}
	PCAP_NDIS_ADAPTER* adapter = (PCAP_NDIS_ADAPTER*)AdapterObject->hFile;
	adapter->ReadTimeout = timeout;

	return TRUE;	
}

BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim)
{
	TRACE_PRINT("PacketSetBuff not supported in this version");
	return TRUE;
}

BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, struct bpf_program *fp)
{
	TRACE_ENTER("PacketSetBpf");
	
	if (AdapterObject == NULL)
	{
		return FALSE;
	}

	struct bpf_program *filter = NULL;
	if (fp != NULL)
	{
		filter = (struct bpf_program*)malloc(sizeof(struct bpf_program));
		filter->bf_len = fp->bf_len;

		size_t size = sizeof(struct bpf_insn) * filter->bf_len;
		if (size > 0) {
			filter->bf_insns = (struct bpf_insn*)malloc(size);
			memcpy(filter->bf_insns, fp->bf_insns, size);
		}
		else {
			filter->bf_insns = NULL;
		}
	}

	PacketLockMutex(AdapterObject->FilterLock);
	{
		if (AdapterObject->Filter != NULL)
		{
			if (AdapterObject->Filter->bf_insns) {
				free(AdapterObject->Filter->bf_insns);
			}
			free(AdapterObject->Filter);
		}

		AdapterObject->Filter = filter;
	}
	PacketReleaseMutex(AdapterObject->FilterLock);

	TRACE_EXIT("PacketSetBpf");
		
	return TRUE;
}


BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior)
{
	TRACE_PRINT("PacketSetLoopbackBehavior not supported in this version");
	return FALSE;
}

INT PacketSetSnapLen(LPADAPTER AdapterObject, int snaplen)
{
	TRACE_PRINT("PacketSetLoopbackBehavior not supported in this version");
	return 0;
}


BOOLEAN PacketGetStats(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	PCAP_NDIS_ADAPTER *a;
	if (AdapterObject == NULL)
	{
		return FALSE;
	}

	a = (PCAP_NDIS_ADAPTER *)AdapterObject->hFile;

	s->ps_ifdrop = 0;

	s->bs_capt = a->Stat.Captured;
	s->bs_drop = a->Stat.Dropped;
	s->bs_recv = a->Stat.Received;

	return TRUE;
}

BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	return PacketGetStats(AdapterObject, s);
}

BOOLEAN PacketRequest(LPADAPTER AdapterObject, BOOLEAN Set, PPACKET_OID_DATA OidData)
{
	TRACE_PRINT("PacketRequest not supported in this version");
	return FALSE;
}

BOOLEAN PacketSetHwFilter(LPADAPTER  AdapterObject,ULONG Filter)
{
	TRACE_PRINT("PacketRequest not supported in this version");
	return TRUE;
}

/*!
  \brief Retrieve the list of available network adapters and their description.
  \param pStr User allocated string that will be filled with the names of the adapters.
  \param BufferSize Length of the buffer pointed by pStr. If the function fails, this variable contains the 
         number of bytes that are needed to contain the adapter list.
  \return If the function succeeds, the return value is nonzero. If the return value is zero, BufferSize contains 
          the number of bytes that are needed to contain the adapter list.

  Usually, this is the first function that should be used to communicate with the driver.
  It returns the names of the adapters installed on the system <B>and supported by WinPcap</B>. 
  After the names of the adapters, pStr contains a string that describes each of them.

  After a call to PacketGetAdapterNames pStr contains, in succession:
  - a variable number of ASCII strings, each with the names of an adapter, separated by a "\0"
  - a double "\0"
  - a number of ASCII strings, each with the description of an adapter, separated by a "\0". The number 
   of descriptions is the same of the one of names. The fisrt description corresponds to the first name, and
   so on.
  - a double "\0". 
*/

BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize)
{
	PADAPTER_INFO	TAdInfo;
	ULONG	SizeNeeded = 0;
	ULONG	SizeNames = 0;
	ULONG	SizeDesc;
	ULONG	OffDescriptions;

	TRACE_ENTER("PacketGetAdapterNames");

	TRACE_PRINT_OS_INFO();

	TRACE_PRINT2("Packet DLL version %s, Driver version %s", PacketLibraryVersion, PacketDriverVersion);

	TRACE_PRINT1("PacketGetAdapterNames: BufferSize=%u", *BufferSize);

	//
	// Create the adapter information list
	//
	TRACE_PRINT("Populating the adapter list...");

	PacketPopulateAdaptersInfoList();

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);

	if(!g_AdaptersInfoList) 
	{
		ReleaseMutex(g_AdaptersInfoMutex);
		*BufferSize = 0;

		TRACE_PRINT("No adapters found in the system. Failing.");
		
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
 	
 		TRACE_EXIT("PacketGetAdapterNames");
		return FALSE;		// No adapters to return
	}

	// 
	// First scan of the list to calculate the offsets and check the sizes
	//
	for(TAdInfo = g_AdaptersInfoList; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Update the size variables
			SizeNeeded += (ULONG)strlen(TAdInfo->Name) + (ULONG)strlen(TAdInfo->Description) + 2;
			SizeNames += (ULONG)strlen(TAdInfo->Name) + 1;
		}
	}

	// Check that we don't overflow the buffer.
	// Note: 2 is the number of additional separators needed inside the list
	if(SizeNeeded + 2 > *BufferSize || pStr == NULL)
	{
		ReleaseMutex(g_AdaptersInfoMutex);

 		TRACE_PRINT1("PacketGetAdapterNames: input buffer too small, we need %u bytes", *BufferSize);
 
		*BufferSize = SizeNeeded + 2;  // Report the required size

 		TRACE_EXIT("PacketGetAdapterNames");
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	OffDescriptions = SizeNames + 1;

	// 
	// Second scan of the list to copy the information
	//
	for(TAdInfo = g_AdaptersInfoList, SizeNames = 0, SizeDesc = 0; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Copy the data
			StringCchCopyA(
				((PCHAR)pStr) + SizeNames, 
				*BufferSize - SizeNames, 
				TAdInfo->Name);
			StringCchCopyA(
				((PCHAR)pStr) + OffDescriptions + SizeDesc, 
				*BufferSize - OffDescriptions - SizeDesc,
				TAdInfo->Description);

			// Update the size variables
			SizeNames += (ULONG)strlen(TAdInfo->Name) + 1;
			SizeDesc += (ULONG)strlen(TAdInfo->Description) + 1;
		}
	}

	// Separate the two lists
	((PCHAR)pStr)[SizeNames] = 0;

	// End the list with a further \0
	((PCHAR)pStr)[SizeNeeded + 1] = 0;


	ReleaseMutex(g_AdaptersInfoMutex);
	TRACE_EXIT("PacketGetAdapterNames");
	return TRUE;
}

/*!
  \brief Returns comprehensive information the addresses of an adapter.
  \param AdapterName String that contains the name of the adapter.
  \param buffer A user allocated array of npf_if_addr that will be filled by the function.
  \param NEntries Size of the array (in npf_if_addr).
  \return If the function succeeds, the return value is nonzero.

  This function grabs from the registry information like the IP addresses, the netmasks 
  and the broadcast addresses of an interface. The buffer passed by the user is filled with 
  npf_if_addr structures, each of which contains the data for a single address. If the buffer
  is full, the reaming addresses are dropeed, therefore set its dimension to sizeof(npf_if_addr)
  if you want only the first address.
*/
BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries)
{
	PADAPTER_INFO TAdInfo;
	PCHAR Tname;
	BOOLEAN Res, FreeBuff;

	TRACE_ENTER("PacketGetNetInfoEx");

	// Provide conversion for backward compatibility
	if(AdapterName[1] != 0)
	{ //ASCII
		Tname = AdapterName;
		FreeBuff = FALSE;
	}
	else
	{
		Tname = WChar2SChar((PWCHAR)AdapterName);
		FreeBuff = TRUE;
	}

	//
	// Update the information about this adapter
	//
	if(!PacketUpdateAdInfo(Tname))
	{
		TRACE_PRINT("PacketGetNetInfoEx. Failed updating the adapter list. Failing.");
		if(FreeBuff)
			GlobalFreePtr(Tname);

		TRACE_EXIT("PacketGetNetInfoEx");
		
		return FALSE;
	}
	
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(Tname);

	if(TAdInfo != NULL)
	{
		LONG numEntries = 0, i;
		PNPF_IF_ADDRESS_ITEM pCursor;
		TRACE_PRINT("Adapter found.");

		pCursor = TAdInfo->pNetworkAddresses;

		while(pCursor != NULL)
		{
			numEntries ++;
			pCursor = pCursor->Next;
		}

		if (numEntries < *NEntries)
		{
			*NEntries = numEntries;
		}

		pCursor = TAdInfo->pNetworkAddresses;
		for (i = 0; (i < *NEntries) && (pCursor != NULL); i++)
		{
			buffer[i] = pCursor->Addr;
			pCursor = pCursor->Next;
		}

		Res = TRUE;
	}
	else
	{
		TRACE_PRINT("PacketGetNetInfoEx: Adapter not found");
		Res = FALSE;
	}
	
	ReleaseMutex(g_AdaptersInfoMutex);
	
	if(FreeBuff)GlobalFreePtr(Tname);
	
	TRACE_EXIT("PacketGetNetInfoEx");
	return Res;
}

/*! 
  \brief Returns information about the MAC type of an adapter.
  \param AdapterObject The adapter on which information is needed.
  \param type Pointer to a NetType structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero, otherwise the return value is zero.

  This function return the link layer and the speed (in bps) of an opened adapter.
  The LinkType field of the type parameter can have one of the following values:

  - NdisMedium802_3: Ethernet (802.3) 
  - NdisMediumWan: WAN 
  - NdisMedium802_5: Token Ring (802.5) 
  - NdisMediumFddi: FDDI 
  - NdisMediumAtm: ATM 
  - NdisMediumArcnet878_2: ARCNET (878.2) 
*/
BOOLEAN PacketGetNetType(LPADAPTER AdapterObject, NetType *type)
{
	PADAPTER_INFO TAdInfo;
	BOOLEAN ret;	
	TRACE_ENTER("PacketGetNetType");

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(AdapterObject->Name);

	if(TAdInfo != NULL)
	{
		TRACE_PRINT("Adapter found");
		// Copy the data
		memcpy(type, &(TAdInfo->LinkLayer), sizeof(struct NetType));
		ret = TRUE;
	}
	else
	{
		TRACE_PRINT("PacketGetNetType: Adapter not found");
		ret =  FALSE;
	}

	ReleaseMutex(g_AdaptersInfoMutex);

	TRACE_EXIT("PacketGetNetType");
	return ret;
}


void* PacketGetAirPcapHandle(LPADAPTER AdapterObject)
{
	TRACE_PRINT("PacketGetAirPcapHandle not supported in this version")
	return NULL;
}
