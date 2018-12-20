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
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef KM_TYPES_H
#define KM_TYPES_H

#include <ndis.h>
#include "KmLock.h"
#include "KmList.h"
#include "KmThreads.h"
#include "NdisMemoryManager.h"
#include "KmTimerThread.h"
#include "..\shared\SharedTypes.h"

#define PACKETS_POOL_INITIAL_SIZE       0x2000
#define DRIVER_CLIENT_POOL_INITIAL_SIZE 0x5000
#define DRIVER_MAX_CLIENTS              0x400
#define DRIVER_SVC_CLIENTS_POOL_SIZE    0x1

typedef struct _ADAPTER     ADAPTER, *PADAPTER;
typedef struct _DEVICE      DEVICE, *PDEVICE;
typedef struct _DRIVER_DATA DRIVER_DATA, *PDRIVER_DATA;

typedef struct _DEVICE
{
    PDRIVER_DATA    DriverData;

    PUNICODE_STRING Name;

    PUNICODE_STRING SymlinkName;

    PDEVICE_OBJECT  Device;

    PADAPTER        Adapter;

    KM_LOCK         OpenCloseLock;

    KM_LIST         ClientList;

    ULONG           Releasing;

} DEVICE, *PDEVICE;

typedef struct _KM_TIME
{
    long    Seconds;
    long    Microseconds;
} KM_TIME, *PKM_TIME;

#define NETWORK_EVENT_INFO_PROCESS_PATH_MAX_SIZE    1024

typedef struct _NETWORK_EVENT_INFO
{
    //  IP protocol (one of IPPROTO_XXX values)
    unsigned short  IpProtocol;

    //  Address family (AF_INET or AF_INET6)
    unsigned short  AddressFamily;

    struct Local
    {
        //  Local address
        IP_ADDRESS      Address;

        //  Local port
        unsigned short  Port;

    } Local;

    struct Remote
    {
        //  Remote address
        IP_ADDRESS      Address;

        //  Remote port
        unsigned short  Port;

    } Remote;

    struct Process
    {
        //  Process id
        unsigned long long  Id;

        //  Process executable path size (in bytes)
        unsigned long       NameSize;

        //  Process executable path buffer
        wchar_t             NameBuffer[NETWORK_EVENT_INFO_PROCESS_PATH_MAX_SIZE];

    } Process;

} NETWORK_EVENT_INFO, *PNETWORK_EVENT_INFO;

typedef struct _ADAPTER_CLOSE_CONTEXT
{
    //  Memory manager for this context
    PKM_MEMORY_MANAGER  MemoryManager;

    //  Completion event
    //  This event should be set to signalled state
    //  once the adapter close operation completes.
    KEVENT              CompletionEvent;

} ADAPTER_CLOSE_CONTEXT, *PADAPTER_CLOSE_CONTEXT;

typedef __declspec(align(1)) struct _ADAPTER
{
    //  List link
    LIST_ENTRY              Link;

    //  Adapter ID
    PCAP_NDIS_ADAPTER_ID    AdapterId;

    //  Size of the data stored in MacAddress field
    ULONG                   MacAddressSize;

    //  Physical adapter address
    UCHAR                   MacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];

    //  MTU size
    ULONG                   MtuSize;

    //  NDIS adapter handle
    NDIS_HANDLE             AdapterHandle;

    //  Adapter lock
    KM_LOCK                 Lock;

    //  Adapter worker thread.
    //  The thread distributes the intercepted packets
    //  to all connected driver clients.
    PKM_THREAD              WorkerThread;

    //  Bind operation timestamp
    KM_TIME                 BindTimestamp;

    // To complete Bind request if necessary
    NDIS_HANDLE             BindContext;

    // To complete Unbind request if necessary
    NDIS_HANDLE             UnbindContext;

    //  Readiness flag
    ULONG                   Ready;

    //  A flag that tells whether the promiscuous mode is enabled or not
    ULONG                   PacketsInterceptionEnabled;

    //  Number of pending OID requests
    volatile ULONG          PendingOidRequests;

    //  Number of pending packet injectio requests
    volatile ULONG          PendingSendPackets;

    //  Number of current connected clients
    LONG                    OpenCount;

    struct Packets
    {
        HANDLE  Pool;
        KM_LIST Allocated;
        KEVENT  NewPacketEvent;
    } Packets;

    //  Pointer to driver data
    PDRIVER_DATA            DriverData;

    //  RESERVED. 
    //  Do not use outside of packet reading routine.
    //  
    //  Current network event info
    //  This field is being used during packet receive.
    NETWORK_EVENT_INFO      CurrentEventInfo;

    //  RESERVED.
    //  Do not use outside of packet reading routine.
    //
    //  Current packet desc info
    //  This field is being use during packet receive.
    PACKET_DESC             CurrentPacketDesc;

    //  Pointer to the adapter close context
    PADAPTER_CLOSE_CONTEXT  CloseContext;

    //  Pointer to a notification event 
    //  that should be set to signalled state in unbind handler right
    //  before freeing the memory allocated for ADAPTER structure.
    PKEVENT                 AdapterUnbindCompletionEvent;

} ADAPTER, *PADAPTER;

typedef struct _PACKET
{
    LIST_ENTRY          Link;

    KM_TIME             Timestamp;

    ULONGLONG           ProcessId;

    ULONG               MaxDataSize;

    ULONG               DataSize;

    UCHAR               Data[1];

} PACKET, *PPACKET;

#define CalcRequiredPacketSize(MTUSize) \
    ((ULONG)(sizeof(PACKET) + MTUSize - sizeof(UCHAR)))

typedef struct _EVENT
{
    char    Name[256];
    PKEVENT Event;
    HANDLE  EventHandle;
} EVENT, *PEVENT;

typedef struct _ADAPTER_CLIENT
{
    PDRIVER_DATA    Data;
    
    PADAPTER        Adapter;

} ADAPTER_CLIENT, *PADAPTER_CLIENT;

typedef struct _DRIVER_CLIENT
{
    //  Process id of connected process
    HANDLE                  OwnerProcessId;

    //  KEVENT object 
    //  This event object is referenced from handle received
    //  during connecting a usermode process to the driver.
    PVOID                   NewPacketEvent;

    //  Handle to packets pool
    HANDLE                  PacketsPool;

    //  Allocated packets list
    KM_LIST                 AllocatedPackets;

    //  ID of associated (opened) adapter
    PCAP_NDIS_ADAPTER_ID    AdapterId;

    HANDLE                  RuleHandle;

} DRIVER_CLIENT, *PDRIVER_CLIENT;

typedef struct _DRIVER_CLIENTS
{
    //  Lock object
    KM_LOCK         Lock;

    //  Handle to a memory pool used for allocating
    //  arrays of DRIVER_CLIENT objects and other service
    //  objects which can be re-used
    //  The entries in this pool should be of 
    //  sizeof(PVOID) * DRIVER_MAX_CLIENTS size
    //  (8192 bytes on x64 systems and 4096 bytes on x86 systems)
    HANDLE          ServicePool;

    //  Handle to a memory pool used for reading packets from
    //  driver client queue
    //  All of entries in this pool are of ADAPTER_READ_BUFFER_SIZE size.
    HANDLE          ReadBuffersPool;

    //  Number of connected clients
    ULONG           Count;

    //  Array of connected clients
    //  Note:
    //      Items in this array are not guaranteed to be located one after another.
    //      The users of this structure must not assume that an item with NULL value
    //      is the last item in the array.
    //      The reason for this is that the indexes in this array are being passed
    //      to usermode code and if a particular client gets closed - the driver
    //      cannot move all the items on the right leftwards by 1 because this'd
    //      render all these moved clients to be unusable.
    PDRIVER_CLIENT  Items[DRIVER_MAX_CLIENTS];

} DRIVER_CLIENTS, *PDRIVER_CLIENTS;

typedef struct _DRIVER_DATA
{
    //  Boolean flag that's set when the driver unload begins
    LONG    DriverUnload;

    struct Ndis
    {
        //  Memory manager for NDIS module
        KM_MEMORY_MANAGER   MemoryManager;

        //  NDIS Protocol Handle
        NDIS_HANDLE         ProtocolHandle;

        PKM_TIMER_THREAD    ReEnumBindingsThread;
    } Ndis;

    struct Wfp
    {
        //  Memory manager for WFP module
        KM_MEMORY_MANAGER   MemoryManager;

        //  WFP module instance handle
        HANDLE              Instance;

    } Wfp;

    struct Other
    {
        //  Driver object received in DriverEntry routine
        PDRIVER_OBJECT  DriverObject;

        //  Handle to Process watcher callback registration.
        HANDLE          ProcessWather;

        //  Handle to KmConnections object instance
        HANDLE          Connections;

        //  Memory pool instance handle.
        //  Contains pre-allocated storage entries for packets (PACKET structure).
        //  The number of pre-allocated entries is defined as PACKETS_POOL_INITIAL_SIZE.
        //  The actual number of entries in the pool depends on the number of packets
        //  received and can possibly be more than PACKETS_POOL_INITIAL_SIZE.
        HANDLE          PacketsPool;

        //  List of received (intercepted) packets
        KM_LIST         ReceivedPackets;

        //  Inter-mode comms instance handle
        HANDLE          IMCInstance;

        //  Rules engine instance handle
        HANDLE          RulesEngineInstance;

    } Other;

    //  Connected clients
    DRIVER_CLIENTS      Clients;

    //  Device used for adapters list retrieval 
    PDEVICE             ListAdaptersDevice;

    //  List of adapters the protocol driver is attached to
    KM_LIST             AdaptersList;

} DRIVER_DATA, *PDRIVER_DATA;

#define FILTER_RE_ENUM_BINDINGS_INTERVAL    30000

#define WFP_FLT_MEMORY_TAG                  'fwDC'
#define NDIS_FLT_MEMORY_TAG                 'nyDC'
#define ADAPTER_PACKET_POOL_MEMORY_TAG      'MPPA'
#define CONNECTIONS_MEMORY_POOL_TAG         'TPMC'
#define CLIENT_PACKET_POOL_MEMORY_TAG       'MPPC'
#define DRIVER_CLIENTS_POOL_MEMORY_TAG      'MPCD'
#define DRIVER_CLIENTS_READ_BUFFER_POOL_TAG 'PBRC'

#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP     17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP    2
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6  58
#endif

#ifndef AF_UNSPEC
#define AF_UNSPEC   0
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6    23
#endif

#endif