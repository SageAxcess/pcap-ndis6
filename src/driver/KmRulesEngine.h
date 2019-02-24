//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 ChangeDynamix, LLC
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////

#pragma once
#include "KmMemoryManager.h"
#include "KmMemoryPool.h"
#include "..\shared\CommonDefs.h"
#include "..\shared\SharedTypes.h"

#define KM_RULE_RESOLUTION_NONE     0x0
#define KM_RULE_RESOLUTION_ALLOW    0x1
#define KM_RULE_RESOLUTION_BLOCK    0x2
#define KM_RULE_RESOLUTION_SKIP     0x4

#define KM_RULES_ENGINE_MEM_TAG         'TMER'
#define KM_RULES_ENGINE_RULE_MEM_TAG    'MRER'

typedef enum _KM_RULE_RESOLUTION
{
    Rule_None = KM_RULE_RESOLUTION_NONE,
    Rule_Allow = KM_RULE_RESOLUTION_ALLOW,
    Rule_Block = KM_RULE_RESOLUTION_BLOCK,
    Rule_Skip = KM_RULE_RESOLUTION_SKIP
} KM_RULE_RESOLUTION, *PKM_RULE_RESOLUTION;

typedef struct _KM_RULE
{
    LIST_ENTRY          Link;

    KM_RULE_RESOLUTION  Resolution;

    NET_EVENT_INFO      Info;

} KM_RULE, *PKM_RULE;

typedef int(__stdcall _KM_RULES_ENGINE_RULE_MATCHING_ROUTINE)(
    __in    PVOID           Context,
    __in    PNET_EVENT_INFO RuleInfo,
    __in    PNET_EVENT_INFO RuleDesc);
typedef _KM_RULES_ENGINE_RULE_MATCHING_ROUTINE  KM_RULES_ENGINE_RULE_MATCHING_ROUTINE, *PKM_RULES_ENGINE_RULE_MATCHING_ROUTINE;

NTSTATUS __stdcall KmRulesEngine_Initialize(
    __in        PKM_MEMORY_MANAGER                      MemoryManager,
    __in        PKM_RULES_ENGINE_RULE_MATCHING_ROUTINE  MatchingRoutine,
    __in_opt    PVOID                                   MatchingRoutineContext,
    __out       PHANDLE                                 InstanceHandle);

NTSTATUS __stdcall KmRulesEngine_Finalize(
    __in    HANDLE  InstanceHandle);

NTSTATUS __stdcall KmRulesEngine_AddRule(
    __in    HANDLE      InstanceHandle,
    __in    PKM_RULE    RuleDefinition,
    __out   PHANDLE     RuleHandle);

NTSTATUS __stdcall KmRulesEngine_RemoveRuleByHandle(
    __in    HANDLE  InstanceHandle,
    __in    HANDLE  RuleHandle);

NTSTATUS __stdcall KmRulesEngine_CheckRules(
    __in    HANDLE              InstanceHandle,
    __in    PNET_EVENT_INFO     EventInfo,
    __out   PKM_RULE_RESOLUTION Resolution);