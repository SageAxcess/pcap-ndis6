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

//
// this should be removed in the long term.  GV 20080807
//
//#define _CRT_SECURE_NO_WARNINGS

#include <StrSafe.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "..\shared\win_bpf.h"
#include "..\shared\CSObject.h"
#include <packet32.h>

#include "Packet32-Int.h"
#include "NdisDriver.h"

#include "debug.h"
#include "Util.h"

#include "Logging.h"

#include "..\shared\MiscUtils.h"
#include "..\shared\SvcUtils.h"
#include "..\shared\StrUtils.h"
#include "..\shared\CommonDefs.h"

#include "..\shared\UmMemoryManager.h"

#include <windows.h>
#include <windowsx.h>
#include <Iphlpapi.h>
#include <netioapi.h>

#include <WpcapNames.h>

#include <string>

static PCAP_NDIS *ndis = nullptr;

#ifdef _DEBUG_TO_FILE
LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName);
CHAR g_LogFileName[1024] = "winpcap_debug.txt";
#endif //_DEBUG_TO_FILE

char PacketLibraryVersion[64];  // Current packet-ndis6.dll Version. It can be retrieved directly or through the PacketGetVersion() function.

#define AEGIS_REGISTRY_KEY_W                L"SOFTWARE\\ChangeDynamix\\AegisPcap"
#define DEBUG_LOGGING_REG_VALUE_NAME_W      L"DebugLoggingLevel"
#define PCAP_NDIS6_DRIVER_SERVICE_NAME_W    L"PcapNdis6"

std::wstring    Packet_DllFileNameW;
std::wstring    Packet_DllFileVersionW;
std::wstring    Packet_DriverNameW;
std::wstring    Packet_DriverVersionW;
std::wstring    Packet_ProcessNameW;
std::wstring    Packet_LogFileNameW;

std::string     Packet_DllFileNameA;
std::string     Packet_DllFileVersionA;
std::string     Packet_DriverNameA;
std::string     Packet_DriverVersionA;

//---------------------------------------------------------------------------

BOOL APIENTRY DllMain(
    __in    HINSTANCE   hinstDLL,
    __in    DWORD       fdwReason,
    __in    LPVOID      lpvReserved)
{
    BOOLEAN Status=TRUE;

    UNREFERENCED_PARAMETER(lpvReserved);

    void* fs;

    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        {
            TRACE_PRINT_DLLMAIN("************Packet32: DllMain************");

            //  Since we do not handle DLL_THREAD_ATTACH/DLL_THREAD_DETACH events
            //  we need to disable them.
            DisableThreadLibraryCalls(hinstDLL);

            UMM_Initialize();

            #ifdef _DEBUG_TO_FILE
            PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" NPF_DRIVER_NAME, "aegis.reg");

            // dump a bunch of registry keys useful for debug to file
            PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
                "adapters.reg");
            PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip",
                "tcpip.reg");
            PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
                "services.reg");

            #endif

            Packet_DllFileNameW = UTILS::MISC::GetModuleName(hinstDLL);
            Packet_DllFileNameA = UTILS::STR::FormatA("%S", Packet_DllFileNameW.c_str());

            Packet_ProcessNameW = UTILS::MISC::GetModuleName(NULL);

            LogMessageToConsole(
                "Packet_ProcessNameW = %S\n",
                Packet_ProcessNameW.c_str());

            Packet_LogFileNameW = UTILS::MISC::ExtractFilePath(Packet_ProcessNameW);
            Packet_LogFileNameW += UTILS::MISC::ExtractFileName(Packet_DllFileNameW);
            Packet_LogFileNameW = UTILS::MISC::ChangeFileExtension(Packet_LogFileNameW, L".log");

            LogMessageToConsole(
                "Packet_LogFileNameW = %S\n",
                Packet_LogFileNameW.c_str());

            LOG::Initialize(
                Packet_LogFileNameW,
                HKEY_LOCAL_MACHINE,
                AEGIS_REGISTRY_KEY_W,
                DEBUG_LOGGING_REG_VALUE_NAME_W);

            LOG::LogMessage(L"Log start\n");

            //
            // Retrieve packet.dll version information from the file
            //

            Packet_DllFileVersionW = UTILS::MISC::GetFileVersion(Packet_DllFileNameW);
            Packet_DllFileVersionA = UTILS::STR::FormatA("%S", Packet_DllFileVersionW.c_str());

            RtlZeroMemory(PacketLibraryVersion, sizeof(PacketLibraryVersion));

            SIZE_T  BytesToCopy =
                Packet_DllFileVersionA.length() > ARRAYSIZE(PacketLibraryVersion) - 1 ?
                ARRAYSIZE(PacketLibraryVersion) - 1 :
                Packet_DllFileVersionA.length();

            RtlCopyMemory(
                PacketLibraryVersion,
                Packet_DllFileVersionA.c_str(),
                BytesToCopy);

            LOG::LogMessageFmt(
                L"DLL version: %S\n",
                Packet_DllFileVersionA.c_str());

            //
            // Retrieve driver version information from the file. 
            //

            std::wstring DriverServiceImagePath = UTILS::SVC::GetServiceImagePath(PCAP_NDIS6_DRIVER_SERVICE_NAME_W);

            Packet_DriverNameW = L"c:\\windows\\system32\\drivers\\pcap-ndis6.sys";
            
            fs = DisableWow64FsRedirection();
            try
            {
                Packet_DriverVersionW = UTILS::MISC::GetFileVersion(Packet_DriverNameW);
            }
            catch(...)
            {
            }
            RestoreWow64FsRedirection(fs);

            Packet_DriverNameA = UTILS::STR::FormatA("%S", Packet_DriverNameW.c_str());
            Packet_DriverVersionA = UTILS::STR::FormatA("%S", Packet_DriverVersionW.c_str());

            LOG::LogMessageFmt(
                L"Driver version: %s\n",
                __FUNCTION__,
                Packet_DriverVersionW.c_str());

            ndis = NdisDriverOpen();

        }break;
        
    case DLL_PROCESS_DETACH:
        {
            if (ndis)
            {
                NdisDriverClose(ndis);
            }

            LOG::Finalize();

            UMM_Finalize();

        }break;
        
    default:
        break;
    }
    
    return Status;
}

/*! 
  \brief Sets the maximum possible lookahead buffer for the driver's Packet_tap() function.
  \param AdapterObject Handle to the service control manager.
  \return If the function succeeds, the return value is nonzero.

  The lookahead buffer is the portion of packet that Packet_tap() can access from the NIC driver's memory
  without performing a copy. This function tries to increase the size of that buffer.

  NOTE: this function is used for NPF adapters, only.
*/

BOOLEAN PacketSetMaxLookaheadsize(LPADAPTER AdapterObject)
{
    BOOLEAN             Result = FALSE;
    ULONG               BufferSize = static_cast<ULONG>(sizeof(PACKET_OID_DATA) + sizeof(ULONG) - 1);
    PPACKET_OID_DATA    OidData = nullptr;

    TRACE_ENTER();

    OidData = reinterpret_cast<PPACKET_OID_DATA>(new UCHAR[BufferSize]);
    if (!Assigned(OidData))
    {
        TRACE_LOG_MESSAGE(
            "%s failed. (insufficient resources)\n",
            __FUNCTION__);
    }
    else
    {
        OidData->Oid = OID_GEN_MAXIMUM_LOOKAHEAD;
        OidData->Length = sizeof(ULONG);

        PacketRequest(
            AdapterObject, 
            FALSE, 
            OidData); // Ignore response

        OidData->Oid = OID_GEN_CURRENT_LOOKAHEAD;

        Result = PacketRequest(
            AdapterObject,
            TRUE,
            OidData);

        delete [] reinterpret_cast<PUCHAR>(OidData);
    }

    TRACE_EXIT();
    
    return Result;
};

BOOLEAN PacketSetReadEvt(LPADAPTER AdapterObject)
{
    BOOLEAN Result = FALSE;
    HANDLE  EventHandle = NULL;

    TRACE_ENTER();

    if (!Assigned(AdapterObject))
    {
        TRACE_LOG_MESSAGE(
            "%s: AdapterObject == NULL\n",
            __FUNCTION__);
        SetLastError(ERROR_INVALID_PARAMETER);
        
        TRACE_EXIT();

        return FALSE;
    }

    if (AdapterObject->ReadEvent != NULL)
    {
        TRACE_LOG_MESSAGE(
            "%s: AdapterObject == NULL\n",
            __FUNCTION__);
        SetLastError(ERROR_INVALID_FUNCTION);

        TRACE_EXIT();

        return FALSE;
    }

    EventHandle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (EventHandle == NULL)
    {
        DWORD   ErrorCode = GetLastError();
        TRACE_LOG_MESSAGE(
            "%s: CreateEventW failed. ErrorCode = %x\n",
            __FUNCTION__,
            ErrorCode);

        SetLastError(ErrorCode);
    }
    else
    {
        AdapterObject->ReadEvent = EventHandle;
        AdapterObject->ReadTimeOut = 0;

        Result = TRUE;
    }

    TRACE_EXIT();

    return Result;
};

/*! 
  \brief Installs the NPF device driver.
  \return If the function succeeds, the return value is nonzero.

  This function installs the driver's service in the system using the CreateService function.
*/

BOOLEAN PacketInstallDriver()
{
    BOOLEAN     Result = FALSE;
    ULONG       ErrorCode = 0;
    SC_HANDLE   ServiceHandle = NULL;
    SC_HANDLE   SCMHandle = NULL;

    TRACE_ENTER();

    SCMHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (SCMHandle != NULL)
    {
        __try
        {
            ServiceHandle = CreateServiceW(
                SCMHandle,
                NPF_DRIVER_NAME_W,
                NPF_SERVICE_DESC_W,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                NPF_DRIVER_COMPLETE_PATH_W,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr);

            if (ServiceHandle == NULL)
            {
                ErrorCode = GetLastError();
                if (ErrorCode == ERROR_SERVICE_EXISTS)
                {
                    ErrorCode = 0;
                    Result = TRUE;
                }
                else
                {
                    TRACE_LOG_MESSAGE(
                        "%s: CreateServiceW failed. ErrorCode = %x\n",
                        __FUNCTION__,
                        ErrorCode);
                }
            }
            else
            {
                Result = TRUE;
                CloseServiceHandle(ServiceHandle);
            }
        }
        __finally
        {
            CloseServiceHandle(SCMHandle);
        }
    }
    else
    {
        ErrorCode = GetLastError();
        TRACE_LOG_MESSAGE(
            "%s: OpenSCManagerW failed. ErrorCode = %x\n",
            __FUNCTION__,
            ErrorCode);
    }

    SetLastError(ErrorCode);
    
    TRACE_EXIT();

    return Result;
};

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

//---------------------------------------------------------------------------
// PUBLIC API
//---------------------------------------------------------------------------

PCHAR PacketGetVersion()
{
    return const_cast<PCHAR>(Packet_DllFileVersionA.c_str());
}

PCHAR PacketGetDriverVersion()
{
    return const_cast<PCHAR>(Packet_DriverVersionA.c_str());
}

PCHAR PacketGetDriverName()
{
    return const_cast<PCHAR>(Packet_DriverNameA.c_str());
}

BOOL PacketStopDriver()
{
    return FALSE; // Not possible to unload ndis 6.x driver
}

LPADAPTER PacketOpenAdapter(PCHAR AdapterNameWA)
{
    if (!Assigned(ndis))
    {
        ndis = NdisDriverOpen();
    }

    RETURN_VALUE_IF_FALSE(
        Assigned(ndis),
        nullptr);

    PPCAP_NDIS_ADAPTER_INFO     AdapterInfo = nullptr;
    LPADAPTER                   Result = nullptr;
    LPPCAP_NDIS_ADAPTER_LIST    AdapterList = NdisDriverGetAdapterList(ndis);

    RETURN_VALUE_IF_FALSE(
        Assigned(AdapterList),
        nullptr);
    try
    {
        std::string AdapterNameStrA;

        for (ULONG k = 0; k < AdapterList->Count; k++)
        {
            if (AdapterList->Items[k].AdapterId.Length > 0)
            {
                std::wstring    AdapterIdStr(
                    AdapterList->Items[k].AdapterId.Buffer,
                    AdapterList->Items[k].AdapterId.Length / sizeof(wchar_t));
                std::wstring    AdapterNameStr = UTILS::STR::FormatW(L"%S", AdapterNameWA);

                if (AdapterNameStr == AdapterIdStr)
                {
                    AdapterInfo = &AdapterList->Items[k];
                    AdapterNameStrA = UTILS::STR::FormatA("%S", AdapterIdStr.c_str());
                    break;
                }
            }
        }

        if (Assigned(AdapterInfo))
        {
            PPCAP_NDIS_ADAPTER  NdisAdapter = NdisDriverOpenAdapter(
                ndis,
                &AdapterInfo->AdapterId);
            if (Assigned(NdisAdapter))
            {
                try
                {
                    Result = UMM_AllocTyped<ADAPTER>();
                    if (Assigned(Result))
                    {
                        RtlZeroMemory(Result, sizeof(ADAPTER));
                        Result->hFile = static_cast<HANDLE>(NdisAdapter);
                        Result->FilterLock = reinterpret_cast<PVOID>(new CCSObject());
                        Result->Flags = INFO_FLAG_NDIS_ADAPTER;

                        RtlCopyMemory(
                            Result->Name,
                            AdapterNameStrA.c_str(),
                            AdapterNameStrA.length() >= ADAPTER_NAME_LENGTH - 1 ?
                            ADAPTER_NAME_LENGTH - 1 :
                            AdapterNameStrA.length());

                        PPCAP_NDIS_ADAPTER  Adapter = reinterpret_cast<PPCAP_NDIS_ADAPTER>(Result->hFile);

                        Result->ReadEvent = Adapter->NewPacketEvent;

                        PacketSetReadTimeout(Result, Result->ReadTimeOut);
                    }
                }
                catch (...)
                {
                }
                if (!Assigned(Result))
                {
                    NdisDriverCloseAdapter(NdisAdapter);
                }
            }
        }
    }
    catch(...)
    {
    }
    NdisDriverFreeAdapterList(AdapterList);

    return Result;
};

/*! 
  \brief Closes an adapter.
  \param lpAdapter the pointer to the adapter to close. 

  PacketCloseAdapter closes the given adapter and frees the associated ADAPTER structure
*/
VOID PacketCloseAdapter(LPADAPTER lpAdapter)
{
    TRACE_ENTER();

    if (!Assigned(lpAdapter))
    {
        TRACE_LOG_MESSAGE(
            "%s: attempt to close a NULL adapter (invalid params)\n",
            __FUNCTION__);
        
        TRACE_EXIT();

        return;
    }

    NdisDriverCloseAdapter(static_cast<LPPCAP_NDIS_ADAPTER>(lpAdapter->hFile));

    if (Assigned(lpAdapter->Filter))
    {
        reinterpret_cast<CCSObject *>(lpAdapter->FilterLock)->Enter();
        __try
        {
            TRACE_LOG_MESSAGE(
                "%s: Releasing filter. ins = %p, filter = %p\n",
                __FUNCTION__,
                lpAdapter->Filter->bf_insns,
                lpAdapter->Filter);

            if (Assigned(lpAdapter->Filter->bf_insns))
            {
                UMM_FreeMem(reinterpret_cast<LPVOID>(lpAdapter->Filter->bf_insns));
            }

            UMM_FreeMem(reinterpret_cast<LPVOID>(lpAdapter->Filter));

            lpAdapter->Filter = nullptr;
        }
        __finally
        {
            reinterpret_cast<CCSObject *>(lpAdapter->FilterLock)->Leave();
        }
    }

    delete reinterpret_cast<CCSObject *>(lpAdapter->FilterLock);

    TRACE_LOG_MESSAGE(
        "%s: Closing event (%p)\n",
        __FUNCTION__,
        lpAdapter->ReadEvent);

    if(lpAdapter->ReadEvent != NULL)
    {
        CloseHandle(lpAdapter->ReadEvent);
    }

    TRACE_LOG_MESSAGE(
        "%s: Releasing adapter\n",
        __FUNCTION__);

    UMM_FreeMem(reinterpret_cast<LPVOID>(lpAdapter));

    TRACE_EXIT();
};

LPPACKET PacketAllocatePacket()
{
    LPPACKET    NewPacket = nullptr;

    TRACE_ENTER();

    try
    {
        NewPacket = new PACKET;
    }
    catch (...)
    {
        TRACE_LOG_MESSAGE(
            "%s: exception during memory allocation",
            __FUNCTION__);
        NewPacket = nullptr;
    }

    TRACE_EXIT();
    
    return NewPacket;
};

VOID PacketFreePacket(LPPACKET lpPacket)
{
    TRACE_ENTER();

    if (Assigned(lpPacket))
    {
        delete lpPacket;
    }

    TRACE_EXIT();
};

VOID PacketInitPacket(
    LPPACKET    lpPacket,
    PVOID       Buffer,
    UINT        Length)
{
    TRACE_ENTER();

    lpPacket->Buffer = Buffer;
    lpPacket->Length = Length;
    lpPacket->ulBytesReceived = 0;
    lpPacket->bIoComplete = FALSE;

    TRACE_EXIT();
};

BOOLEAN CheckFilter(LPADAPTER AdapterObject, LPPACKET lpPacket)
{
    pbpf_hdr    bpf = nullptr;
    PUCHAR      Buffer = nullptr;
    BOOLEAN     Result = TRUE;

    RETURN_VALUE_IF_FALSE(
        (lpPacket->ulBytesReceived > 0) &&
        (Assigned(AdapterObject->Filter)),
        FALSE);

    bpf = reinterpret_cast<pbpf_hdr>(lpPacket->Buffer);

    RETURN_VALUE_IF_FALSE(
        bpf->bh_hdrlen <= lpPacket->ulBytesReceived,
        FALSE);

    Buffer = reinterpret_cast<PUCHAR>(lpPacket->Buffer) + bpf->bh_hdrlen;

    reinterpret_cast<CCSObject *>(AdapterObject->FilterLock)->Enter();
    __try
    {
        UINT f = bpf_filter(
            AdapterObject->Filter->bf_insns, 
            Buffer, 
            bpf->bh_caplen, 
            bpf->bh_caplen);

        Result = (f != 0) ? TRUE : FALSE;
    }
    __finally
    {
        reinterpret_cast<CCSObject *>(AdapterObject->FilterLock)->Leave();
    }

    return Result;
}

BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject, LPPACKET lpPacket, BOOLEAN Sync)
{
    TRACE_ENTER();

    UNREFERENCED_PARAMETER(Sync);

    BOOLEAN res = FALSE;

    LOG::LogMessageFmt(
        L"%S: AdapterObject = %p, lpPacket = %p, Sync = %s\n",
        __FUNCTION__,
        AdapterObject,
        lpPacket,
        Sync ? L"TRUE" : L"FALSE");

    if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
    {
        TRACE_LOG_MESSAGE("   ... NdisDriverNextPacket\n");

        LOG::LogMessageFmt(L"    INFO_FLAG_NDIS_ADAPTER present\n");

        WaitForSingleObject(
            AdapterObject->ReadEvent, 
            (AdapterObject->ReadTimeOut == -1) ? INFINITE : AdapterObject->ReadTimeOut);

        res = (BOOLEAN)NdisDriverNextPacket(
            (PCAP_NDIS_ADAPTER*)AdapterObject->hFile, 
            &lpPacket->Buffer,
            lpPacket->Length, 
            &lpPacket->ulBytesReceived,
            NULL);

        /*
        #ifdef _DEBUG
        NdisDriverLogPacket(lpPacket);
        #endif
        */

        if(!res)
        {
            lpPacket->ulBytesReceived = 0;
            res = FALSE;
        }

        if (!CheckFilter(AdapterObject, lpPacket))
        {
            lpPacket->ulBytesReceived = 0;
            res = FALSE;
        }
    }
    else
    {
        TRACE_LOG_MESSAGE("Request to read on an unknown device type (%u)", AdapterObject->Flags);
    }
    
    TRACE_EXIT();

    return res;
};

BOOLEAN PacketReceivePacketEx(
    __in    LPADAPTER   AdapterObject,
    __out   LPPACKET_EX Packet,
    __in    BOOLEAN     Sync)
{
    BOOLEAN Result = FALSE;

    UNREFERENCED_PARAMETER(Sync);

    RETURN_VALUE_IF_FALSE(
        AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER,
        FALSE);

    WaitForSingleObject(
        AdapterObject->ReadEvent,
        (AdapterObject->ReadTimeOut == -1) ? INFINITE : AdapterObject->ReadTimeOut);

    Result = (BOOLEAN)NdisDriverNextPacket(
        static_cast<LPPCAP_NDIS_ADAPTER>(AdapterObject->hFile),
        &Packet->Packet.Buffer,
        Packet->Packet.Length,
        &Packet->Packet.ulBytesReceived,
        &Packet->ProcessId);

    if (!Result)
    {
        Packet->Packet.ulBytesReceived = 0;
    }

    if (Packet->Packet.ulBytesReceived > 0)
    {
        Sleep(100);
    }

    if (!CheckFilter(AdapterObject, &Packet->Packet))
    {
        Packet->Packet.ulBytesReceived = 0;
        Result = FALSE;
    }

    TRACE_EXIT();

    return Result;
};

BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(lpPacket);
    UNREFERENCED_PARAMETER(Sync);

    TRACE_LOG_MESSAGE(
        "%s not supported in this version",
        __FUNCTION__);

    return FALSE; //TODO: Not supported at the moment
}

INT PacketSendPackets(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(PacketBuff);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Sync);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return 0; //TODO: Not supported at the moment
}

BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(nbytes);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return TRUE;
}

BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode)
{
    UNREFERENCED_PARAMETER(AdapterObject);

    TRACE_FUNCTION_NOT_SUPPORTED();

    if(mode == PACKET_MODE_CAPT)
    {
        return TRUE;
    }

    return FALSE;
};

BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(name);
    UNREFERENCED_PARAMETER(len);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return FALSE;
};

BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(maxfilesize);
    UNREFERENCED_PARAMETER(maxnpacks);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return FALSE;
}

BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(sync);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return FALSE;
}

HANDLE PacketGetReadEvent(LPADAPTER AdapterObject)
{
    TRACE_ENTER();
    TRACE_EXIT();

    return AdapterObject->ReadEvent;
};

BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject, int nwrites)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(nwrites);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return FALSE;
};

BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject, int timeout)
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

BOOLEAN PacketSetBuff(LPADAPTER AdapterObject, int dim)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(dim);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return TRUE;
}

BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, struct bpf_program *fp)
{
    TRACE_ENTER();

    RETURN_VALUE_IF_FALSE(
        Assigned(AdapterObject),
        FALSE);

    struct bpf_program *filter = nullptr;

    if (Assigned(fp))
    {
        filter = UMM_AllocTyped<bpf_program>();
        RETURN_VALUE_IF_FALSE(
            Assigned(filter),
            FALSE);

        filter->bf_len = fp->bf_len;

        size_t size = sizeof(struct bpf_insn) * filter->bf_len;
        if (size > 0)
        {
            filter->bf_insns = UMM_AllocTypedWithSize<bpf_insn>(size);

            RtlCopyMemory(
                filter->bf_insns,
                fp->bf_insns,
                size);
        }
        else
        {
            filter->bf_insns = nullptr;
        }
    }

    reinterpret_cast<CCSObject *>(AdapterObject->FilterLock)->Enter();
    __try
    {
        if (Assigned(AdapterObject->Filter))
        {
            if (Assigned(AdapterObject->Filter->bf_insns))
            {
                UMM_FreeMem(reinterpret_cast<LPVOID>(AdapterObject->Filter->bf_insns));
            }

            UMM_FreeMem(reinterpret_cast<LPVOID>(AdapterObject->Filter));
        }

        AdapterObject->Filter = filter;
    }
    __finally
    {
        reinterpret_cast<CCSObject *>(AdapterObject->FilterLock)->Leave();
    }

    TRACE_EXIT();
        
    return TRUE;
};

BOOLEAN PacketSetLoopbackBehavior(LPADAPTER AdapterObject, UINT LoopbackBehavior)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(LoopbackBehavior);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return FALSE;
}

INT PacketSetSnapLen(LPADAPTER AdapterObject, int snaplen)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(snaplen);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return 0;
}

BOOLEAN PacketGetStats(
    __in    LPADAPTER       AdapterObject,
    __out   struct bpf_stat *s)
{
    PPCAP_NDIS_ADAPTER  Adapter = nullptr;

    RETURN_VALUE_IF_FALSE(
        (Assigned(AdapterObject)) &&
        (Assigned(s)),
        FALSE);

    Adapter = reinterpret_cast<PPCAP_NDIS_ADAPTER>(AdapterObject->hFile);

    s->ps_ifdrop = 0;

    s->bs_capt = Adapter->Stat.Captured;
    s->bs_drop = Adapter->Stat.Dropped;
    s->bs_recv = Adapter->Stat.Received;

    return TRUE;
};

BOOLEAN PacketGetStatsEx(
    __in    LPADAPTER       AdapterObject,
    __out   struct bpf_stat *s)
{
    return PacketGetStats(AdapterObject, s);
};

BOOLEAN PacketGetDriverMemUsage(
    __out   PULONGLONG  TotalAllocations,
    __out   PULONGLONG  TotalBytesAllocated)
{
    return NdisDriverQueryDiagInfo(
        ndis,
        TotalAllocations,
        TotalBytesAllocated) ? TRUE : FALSE;
};

BOOLEAN PacketRequest(LPADAPTER AdapterObject, BOOLEAN Set, PPACKET_OID_DATA OidData)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(Set);
    UNREFERENCED_PARAMETER(OidData);

    TRACE_FUNCTION_NOT_SUPPORTED();

    return FALSE;
}

BOOLEAN PacketSetHwFilter(LPADAPTER AdapterObject, ULONG Filter)
{
    UNREFERENCED_PARAMETER(AdapterObject);
    UNREFERENCED_PARAMETER(Filter);

    TRACE_FUNCTION_NOT_SUPPORTED();

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

BOOLEAN PacketGetAdapterNames(
    __out   PTSTR   pStr,
    __inout PULONG  BufferSize)
{
    RETURN_VALUE_IF_FALSE(
        Assigned(BufferSize),
        FALSE);

    RETURN_VALUE_IF_FALSE(
        Assigned(ndis),
        FALSE);

    BOOLEAN                     Result = FALSE;
    ULONG                       SizeNeeded = 0;
    ULONG                       SizeNames = 0;
    ULONG                       SizeDesc = 0;
    ULONG                       OffDescriptions = 0;
    LPPCAP_NDIS_ADAPTER_LIST    AdapterList = NdisDriverGetAdapterList(ndis);
    RETURN_VALUE_IF_FALSE(
        Assigned(AdapterList),
        FALSE);
    try
    {
        for (ULONG k = 0; k < AdapterList->Count; k++)
        {
            SizeNeeded +=
                (ULONG)AdapterList->Items[k].AdapterId.Length / sizeof(wchar_t) +
                AdapterList->Items[k].DisplayNameLength + 2;

            SizeNames += AdapterList->Items[k].AdapterId.Length / sizeof(wchar_t) + 1;
        }

        if ((SizeNeeded + 2 > *BufferSize) ||
            (!Assigned(pStr)))
        {
            *BufferSize = SizeNeeded + 2;
        }
        else
        {
            RtlZeroMemory(pStr, *BufferSize);

            OffDescriptions = SizeNames + 1;
            SizeNames = 0;
            SizeDesc = 0;

            for (ULONG k = 0; k < AdapterList->Count; k++)
            {
                std::wstring    AdapterId(
                    AdapterList->Items[k].AdapterId.Buffer, 
                    AdapterList->Items[k].AdapterId.Length / sizeof(wchar_t));
                std::string     AdapterName = UTILS::STR::FormatA("%S", AdapterId.c_str());

                StringCchCopyA(
                    ((PCHAR)pStr) + SizeNames,
                    *BufferSize - SizeNames,
                    AdapterName.c_str());

                StringCchCopyA(
                    ((PCHAR)pStr) + OffDescriptions + SizeDesc,
                    *BufferSize - OffDescriptions - SizeDesc,
                    AdapterList->Items[k].DisplayName);

                SizeNames += (ULONG)AdapterName.length() + 1;
                SizeDesc += (ULONG)strlen(AdapterList->Items[k].DisplayName) + 1;
            }

            Result = TRUE;
        }

    }
    catch (...)
    {
    }
    NdisDriverFreeAdapterList(AdapterList);

    if (!Result)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
    }

    return Result;
};

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
    UINT            RetCode;
    PMIB_IF_TABLE2  Table = nullptr;

    RETURN_VALUE_IF_FALSE(
        Assigned(AdapterName),
        FALSE);

    TRACE_LOG_MESSAGE(
        "%s(%s)\n",
        __FUNCTION__,
        AdapterName);

    RetCode = GetIfTable2(&Table);
    if (RetCode != NO_ERROR)
    {
        TRACE_LOG_MESSAGE(
            "%s: GetIfTable2 failed with code %x\n",
            __FUNCTION__,
            RetCode);
        return FALSE;
    }

    if (!Assigned(Table))
    {
        TRACE_LOG_MESSAGE(
            "%s: Table is null\n",
            __FUNCTION__);
        return FALSE;
    }

    int InterfaceIndex = -1;

    try
    {
        for (ULONG k = 0; k < Table->NumEntries; k++)
        {
            PMIB_IF_ROW2    Row = &Table->Table[k];
            std::string     GuidStr = UTILS::STR::GuidToStringA(Row->InterfaceGuid);

            TRACE_LOG_MESSAGE(
                "   adapter guid %s", 
                GuidStr.c_str());

            if (UTILS::STR::SameTextA(GuidStr, AdapterName))
            {
                TRACE_LOG_MESSAGE(
                    "  detected interface index %u", 
                    Row->InterfaceIndex);
                InterfaceIndex = static_cast<int>(Row->InterfaceIndex);
                break;
            }
        }
    }
    catch (...)
    {
        FreeMibTable(Table);
    }

    if (InterfaceIndex >= 0)
    {
        PIP_ADAPTER_INFO    AdapterInfo = UTILS::MISC::GetAdaptersInformation();

        RETURN_VALUE_IF_FALSE(
            Assigned(AdapterInfo),
            FALSE);

        try
        {
            for (PIP_ADAPTER_INFO CurrentInfo = AdapterInfo;
                Assigned(CurrentInfo);
                CurrentInfo = CurrentInfo->Next)
            {
                if (CurrentInfo->Index == static_cast<DWORD>(InterfaceIndex))
                {
                    LONG            Count = 0;

                    for (PIP_ADDR_STRING Addr = &CurrentInfo->IpAddressList;
                        (Assigned(Addr)) && (Count < *NEntries);
                        Addr = Addr->Next)
                    {
                        ULONG   IP4 = 0;

                        TRACE_LOG_MESSAGE(
                            "  resolving address %s", 
                            Addr->IpAddress.String);

                        if (UTILS::MISC::StringToIpAddressV4A(
                            Addr->IpAddress.String,
                            &IP4))
                        {
                            RtlZeroMemory(
                                &buffer[Count].IPAddress,
                                sizeof(sockaddr_storage));
                            RtlCopyMemory(
                                &buffer[Count].IPAddress,
                                &IP4,
                                sizeof(IP4));
                            Count++;
                        }

                    }

                    *NEntries = Count;

                    break;
                }
            }
        }
        catch (...)
        {
        }

        UMM_FreeMem(reinterpret_cast<LPVOID>(AdapterInfo));
        
        return TRUE;
    }

    TRACE_LOG_MESSAGE(
        "%s: adapter not found by guid %s",
        __FUNCTION__,
        AdapterName);
    
    return FALSE;
}

BOOLEAN PacketGetNetType(LPADAPTER AdapterObject, NetType *type)
{
    UNREFERENCED_PARAMETER(AdapterObject);

    type->LinkSpeed = 100 * 1024 * 1024;
    type->LinkType = 0;

    return TRUE;
}


void* PacketGetAirPcapHandle(LPADAPTER AdapterObject)
{
    UNREFERENCED_PARAMETER(AdapterObject);

    TRACE_LOG_MESSAGE("PacketGetAirPcapHandle not supported in this version");

    return NULL;
};
