//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2019 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#ifndef KM_MEMORY_TAGS_H
#define KM_MEMORY_TAGS_H

/*
    Deprecated values (for referencing purposes only)

    #define WFP_FLT_MEMORY_TAG                  'fwDC'
    #define NDIS_FLT_MEMORY_TAG                 'nyDC'
    #define ADAPTER_PACKET_POOL_MEMORY_TAG      'MPPA'
    #define CONNECTIONS_MEMORY_POOL_TAG         'TPMC'
    #define CLIENT_PACKET_POOL_MEMORY_TAG       'MPPC'
    #define DRIVER_CLIENTS_POOL_MEMORY_TAG      'MPCD'
    #define DRIVER_CLIENTS_READ_BUFFER_POOL_TAG 'PBRC'
    #define KM_RULES_ENGINE_MEM_TAG             'TMER'
    #define KM_RULES_ENGINE_RULE_MEM_TAG        'MRER'
*/

//  Main memory tags
#define WFP_FLT_MEMORY_TAG                  '01DC'
#define NDIS_FLT_MEMORY_TAG                 '02DC'

//  Adapters-related memory tags
#define ADAPTER_PACKET_POOL_MEMORY_TAG      '03DC'
#define ADAPTER_OBJECT_MEMORY_TAG           '04DC'
#define ADAPTER_SVC_MEMORY_TAG              '05DC'

//  Connections-related memory tags
#define KM_CONNECTIONS_MEMORY_POOL_TAG      '06DC'
#define KM_CONNECTIONS_SVC_MEMORY_TAG       '07DC'
#define KM_CONNECTIONS_OBJECT_MEMORY_TAG    '08DC'

//  Clients-related memory tags
#define CLIENT_PACKET_POOL_MEMORY_TAG       '09DC'
#define DRIVER_CLIENTS_POOL_MEMORY_TAG      '0ADC'
#define DRIVER_CLIENTS_READ_BUFFER_POOL_TAG '0BDC'

//  Trees-related memory tags
#define KM_TREE_SVC_MEMORY_TAG              '0CDC'
#define KM_TREE_ITEM_MEMORY_TAG             '0DDC'
#define KM_TREE_OBJECT_MEMORY_TAG           '0EDC'

//  Rules engine-related memory tags
#define KM_RULES_ENGINE_OBJECT_MEMORY_TAG   '0FDC'
#define KM_RULES_ENGINE_SVC_MEMORY_TAG      '10DC'
#define KM_RULES_ENGINE_RULE_MEMORY_TAG     '11DC'

#define KM_TIMER_THREAD_OBJECT_MEMORY_TAG   '12DC'
#define KM_TIMER_THREAD_SVC_MEMORY_TAG      '13DC'
#define KM_TIMER_THREAD_ITEM_MEMORY_TAG     '14DC'

#define KM_MEMORY_POOL_OBJECT_MEMORY_TAG    '15DC'
#define KM_MEMORY_POOL_SVC_MEMORY_TAG       '16DC'

#define KM_TIMER_OBJECT_MEMORY_TAG          '17DC'
#define KM_TIMER_SVC_MEMORY_TAG             '18DC'

#endif