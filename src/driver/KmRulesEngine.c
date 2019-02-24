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

#include "KmRulesEngine.h"
#include "KmList.h"
#include "KmLock.h"

typedef struct _KM_RULES_ENGINE
{
    PKM_MEMORY_MANAGER  MemoryManager;

    KM_LOCK             Lock;

    struct _RULES
    {
        LIST_ENTRY                              Rules;

        HANDLE                                  Pool;

        PKM_RULES_ENGINE_RULE_MATCHING_ROUTINE  MatchingRoutine;

        PVOID                                   MatchingRoutineContext;

    } Rules;

} KM_RULES_ENGINE, *PKM_RULES_ENGINE;

NTSTATUS __stdcall KmRulesEngine_Initialize(
    __in        PKM_MEMORY_MANAGER                      MemoryManager,
    __in        PKM_RULES_ENGINE_RULE_MATCHING_ROUTINE  MatchingRoutine,
    __in_opt    PVOID                                   MatchingRoutineContext,
    __out       PHANDLE                                 InstanceHandle)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_RULES_ENGINE    NewEngine = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MatchingRoutine),
        STATUS_INVALID_PARAMETER_2);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(InstanceHandle),
        STATUS_INVALID_PARAMETER_4);

    NewEngine = Km_MM_AllocMemTypedWithTag(
        MemoryManager,
        KM_RULES_ENGINE,
        KM_RULES_ENGINE_MEM_TAG);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(NewEngine),
        STATUS_INSUFFICIENT_RESOURCES);
    __try
    {
        RtlZeroMemory(NewEngine, sizeof(KM_RULES_ENGINE));

        Status = Km_MP_Initialize(
            MemoryManager,
            (ULONG)sizeof(KM_RULE),
            1,
            FALSE,
            KM_RULES_ENGINE_RULE_MEM_TAG,
            &NewEngine->Rules.Pool);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));
        __try
        {
            InitializeListHead(&NewEngine->Rules.Rules);

            NewEngine->Rules.MatchingRoutine = MatchingRoutine;
            NewEngine->Rules.MatchingRoutineContext = MatchingRoutineContext;

            Status = Km_Lock_Initialize(&NewEngine->Lock);
        }
        __finally
        {
            if (!NT_SUCCESS(Status))
            {
                Km_MP_Finalize(&NewEngine->Rules.Pool);
            }
        }
    }
    __finally
    {
        if (!NT_SUCCESS(Status))
        {
            Km_MM_FreeMem(MemoryManager, NewEngine);
        }
        else
        {
            *InstanceHandle = (HANDLE)NewEngine;
        }
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmRulesEngine_Finalize(
    __in    HANDLE  InstanceHandle)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_RULES_ENGINE    Engine = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        InstanceHandle != NULL,
        STATUS_INVALID_PARAMETER_1);

    Engine = (PKM_RULES_ENGINE)InstanceHandle;

    Status = Km_Lock_Acquire(&Engine->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(Engine->MemoryManager),
            STATUS_UNSUCCESSFUL);

        while (!IsListEmpty(&Engine->Rules.Rules))
        {
            PKM_RULE    Rule = CONTAINING_RECORD(
                RemoveHeadList(&Engine->Rules.Rules),
                KM_RULE,
                Link);

            Km_MP_Release(Rule);
        }

        Status = Km_MP_Finalize(Engine->Rules.Pool);

        Engine->Rules.Pool = NULL;
    }
    __finally
    {
        Km_Lock_Release(&Engine->Lock);
    }

    if (NT_SUCCESS(Status))
    {
        Km_MM_FreeMem(Engine->MemoryManager, Engine);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmRulesEngine_AddRule(
    __in        HANDLE      InstanceHandle,
    __in        PKM_RULE    RuleDefinition,
    __out_opt   PHANDLE     RuleHandle)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_RULE            NewRule = NULL;
    PKM_RULES_ENGINE    Engine = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        InstanceHandle != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(RuleDefinition),
        STATUS_INVALID_PARAMETER_2);

    Engine = (PKM_RULES_ENGINE)InstanceHandle;

    Status = Km_Lock_Acquire(&Engine->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        Status = Km_MP_AllocateCheckSize(
            Engine->Rules.Pool,
            sizeof(KM_RULE),
            (PVOID *)&NewRule);
        LEAVE_IF_FALSE(NT_SUCCESS(Status));
        __try
        {
            RtlCopyMemory(
                NewRule,
                RuleDefinition,
                sizeof(KM_RULE));

            InsertTailList(&Engine->Rules.Rules, &NewRule->Link);
        }
        __finally
        {
            if (!NT_SUCCESS(Status))
            {
                Km_MP_Release(NewRule);
            }
            else
            {
                if (Assigned(RuleHandle))
                {
                    *RuleHandle = (HANDLE)NewRule;
                }
            }
        }
    }
    __finally
    {
        Km_Lock_Release(&Engine->Lock);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmRulesEngine_RemoveRuleByHandle(
    __in    HANDLE  InstanceHandle,
    __in    HANDLE  RuleHandle)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_RULES_ENGINE    Engine = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        InstanceHandle != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        RuleHandle != NULL,
        STATUS_INVALID_PARAMETER_2);

    Engine = (PKM_RULES_ENGINE)InstanceHandle;
    
    Status = Km_Lock_Acquire(&Engine->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PLIST_ENTRY Entry;
        PKM_RULE    Rule = NULL;

        for (Entry = Engine->Rules.Rules.Flink;
            Entry != &Engine->Rules.Rules;
            Entry = Entry->Flink)
        {
            if (CONTAINING_RECORD(Entry, KM_RULE, Link) == (PKM_RULE)RuleHandle)
            {
                Rule = CONTAINING_RECORD(Entry, KM_RULE, Link);

                RemoveEntryList(Entry);

                break;
            }
        };

        LEAVE_IF_FALSE_SET_STATUS(
            Assigned(Rule),
            STATUS_UNSUCCESSFUL);

        Km_MP_Release(Rule);
    }
    __finally
    {
        Km_Lock_Release(&Engine->Lock);
    }

cleanup:
    return Status;
};

NTSTATUS __stdcall KmRulesEngine_CheckRules(
    __in    HANDLE              InstanceHandle,
    __in    PNET_EVENT_INFO     EventInfo,
    __out   PKM_RULE_RESOLUTION Resolution)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PKM_RULES_ENGINE    Engine = NULL;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        InstanceHandle != NULL,
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(EventInfo),
        STATUS_INVALID_PARAMETER_2);

    Engine = (PKM_RULES_ENGINE)InstanceHandle;
    
    Status = Km_Lock_Acquire(&Engine->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        PLIST_ENTRY Entry;
        for (Entry = Engine->Rules.Rules.Flink;
            Entry != &Engine->Rules.Rules;
            Entry = Entry->Flink)
        {
            PKM_RULE    Rule = CONTAINING_RECORD(Entry, KM_RULE, Link);
            if (Engine->Rules.MatchingRoutine(
                Engine->Rules.MatchingRoutineContext,
                &Rule->Info,
                EventInfo) == 0)
            {
                if (Assigned(Resolution))
                {
                    *Resolution = Rule->Resolution;
                    __leave;
                }
            }
        }

        Status = STATUS_NO_MATCH;
    }
    __finally
    {
        Km_Lock_Release(&Engine->Lock);
    }

cleanup:
    return Status;
};