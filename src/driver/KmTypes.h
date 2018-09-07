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

#include "KmLock.h"
#include "KmList.h"
#include "KmThreads.h"
#include "..\shared\SharedTypes.h"

#define PACKETS_POOL_INITIAL_SIZE       0x2000
#define DRIVER_MAX_CLIENTS              0x400
#define DRIVER_SVC_CLIENTS_POOL_SIZE    0x1

typedef struct _ADAPTER     ADAPTER, *PADAPTER;
typedef struct _DRIVER_DATA DRIVER_DATA, *PDRIVER_DATA;

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

#define MAX_PHYSICAL_ADDRESS_LENGTH 0x20

typedef struct _ADAPTER
{
    //  List link
    LIST_ENTRY              Link;

    //  Size of the data stored in DisplayName field
    unsigned long           DisplayNameSize;
    
    //  Adapter display name
    char                    DisplayName[256];

    //  Adapter ID
    PCAP_NDIS_ADAPTER_ID    AdapterId;

    //  Size of the data stored in MacAddress field
    unsigned long           MacAddressSize;

    //  Physical adapter address
    unsigned char           MacAddress[MAX_PHYSICAL_ADDRESS_LENGTH];

    //  MTU size
    unsigned long           MtuSize;

    //  Adapter lock
    KM_LOCK                 Lock;

    //  Adapter worker thread.
    //  The thread distributes the intercepted packets
    //  to all connected driver clients.
    PKM_THREAD              WorkerThread;

    //  Bind operation timestamp
    KM_TIME                 BindTimestamp;

    //  Readiness flag
    unsigned long           Ready;

    //  A flag that tells whether the promiscuous mode is enabled or not
    unsigned long           PacketsInterceptionEnabled;

    //  Number of current connected clients
    long                    OpenCount;

    struct Packets
    {
        HANDLE  WorkPool;
        KM_LIST Allocated;
        KEVENT  NewPacketEvent;

        struct ClientPacketPool
        {
            PHANDLE PoolHandle;
        } ClientPacketPool;

    } Packets;

    //  Pointer to driver data
    PDRIVER_DATA            DriverData;

    //  RESERVED. 
    //  Do not use outside of packet reading routine.
    //  
    //  Current network event info
    //  This field is being used during packet receive.
    NETWORK_EVENT_INFO      CurrentEventInfo;

    //  Pointer to the adapter close context
    PADAPTER_CLOSE_CONTEXT  CloseContext;

    //  Pointer to a notification event 
    //  that should be set to signalled state in unbind handler right
    //  before freeing the memory allocated for ADAPTER structure.
    PKEVENT                 AdapterUnbindCompletionEvent;

} ADAPTER, *PADAPTER;

typedef struct _PACKET
{
    //  List link
    LIST_ENTRY          Link;

    //  Object header


    //  Number of current references established to the packet
    //  The structure is being freed when the number of references
    //  goes to zero.
    unsigned long       ReferencesCount;

    //  Packet timestamp.
    //  The time is relative to the system time.
    KM_TIME             Timestamp;

    //  Id of the process of the connection the
    //  packet belongs to.
    unsigned long long  ProcessId;

    //  Size of the packet data
    unsigned long       DataSize;

    //  Packet data
    unsigned char       Data[1];

} PACKET, *PPACKET;

typedef struct _PACKET_REFERENCE
{
    //  List link
    LIST_ENTRY  Link;

    //  Referenced packet
    PPACKET     Packet;

} PACKET_REFERENCE, *PPACKET_REFERENCE;

typedef struct _DRIVER_CLIENT
{
    //  Process id of connected process
    HANDLE                  OwnerProcessId;

    //  KEVENT object 
    //  This event object is referenced from handle received
    //  during connecting a usermode process to the driver.
    PVOID                   NewPacketEvent;

    //  Handle to packets references pool
    HANDLE                  PacketReferencesPool;

    //  Allocated packets references list
    KM_LIST                 AllocatedPacketReferences;

    //  ID of associated (opened) adapter
    PCAP_NDIS_ADAPTER_ID    AdapterId;

} DRIVER_CLIENT, *PDRIVER_CLIENT;

typedef struct _DRIVER_CLIENT_PACKET
{
    //  List link
    LIST_ENTRY  Link;

    //  Pointer to the referenced PACKET structure
    PPACKET     Packet;

} DRIVER_CLIENT_PACKET, *PDRIVER_CLIENT_PACKET;

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

    //  Memory pool instance handle.
    //  Contains pre-allocated storage entries for packets (PACKET structure).
    //  The number of pre-allocated entries is defined as PACKETS_POOL_INITIAL_SIZE.
    //  The actual number of entries in the pool depends on the number of packets
    //  received and can possibly be more than PACKETS_POOL_INITIAL_SIZE.
    HANDLE          PacketsPool;

    //  List of received (intercepted) packets
    KM_LIST         ReceivedPackets;

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

        //  Inter-mode comms instance handle
        HANDLE          IMCInstance;

    } Other;

    //  Connected clients
    DRIVER_CLIENTS      Clients;

    //  List of adapters the protocol driver is attached to
    struct Adapters
    {
        KM_LIST Adapters;

        KM_LIST AdapterPacketPools;

    } Adapters;

} DRIVER_DATA, *PDRIVER_DATA;

#define WFP_FLT_MEMORY_TAG          'fwDC'
#define NDIS_FLT_MEMORY_TAG         'nyDC'

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