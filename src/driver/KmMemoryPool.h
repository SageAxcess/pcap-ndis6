//////////////////////////////////////////////////////////////////////
// Project: pcap-ndis6
// Description: WinPCAP fork with NDIS6.x support 
// License: MIT License, read LICENSE file in project root for details
//
// Copyright (c) 2018 Change Dynamix, Inc.
// All Rights Reserved.
// 
// https://changedynamix.io/
// 
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////
#pragma once

#include "KmMemoryManager.h"

#ifdef KM_MEMORY_MANAGER_EXTENDED_DEBUG_INFO

#define KM_MEMORY_POOL_EXTENDED_DEBUG_INFO  0x1

#else

#define KM_MEMORY_POOL_EXTENDED_DEBUG_INFO  0x0

#endif

#if (KM_MEMORY_POOL_EXTENDED_DEBUG_INFO && !defined(KM_MEMORY_MANAGER_EXTENDED_DEBUG_INFO))

#error("Error: Invalid flags mix. KM_MEMORY_POOL_EXTENDED_DEBUG_INFO flag requires KM_MEMORY_MANAGER_EXTENDED_DEBUG_INFO flag to be defined.")

#endif

#define KM_MEMORY_POOL_FLAG_DEFAULT     0x1
#define KM_MEMORY_POOL_FLAG_DYNAMIC     0x2
#define KM_MEMORY_POOL_FLAG_LOOKASIDE   0x4

#define Km_MP_ValidateFlags(Value) \
    ( \
        ((Value) == KM_MEMORY_POOL_FLAG_DEFAULT) || \
        ((Value) == KM_MEMORY_POOL_FLAG_DYNAMIC) || \
        ((Value) == (KM_MEMORY_POOL_FLAG_DYNAMIC | KM_MEMORY_POOL_FLAG_LOOKASIDE)) \
    )

typedef struct _KM_MEMORY_POOL_BLOCK_DEFINITION
{
    enum _TYPE
    {
        Generic = 0x0,

        //  The pool identifies the size of the blocks at the time of first allocation attempt
        GenericGuessSize = 0x1,

        //  The number of allocations cannot exceed the amount specified in InitialBlockCount field.
        NonGrowable = 0x2,

        //  Acts as a lookaside list (frees the entries which exceed the value specified in BlockCount field upon release)
        LookasideList = 0x3,

    } Type;

    //  Size of each memory block in the list
    SIZE_T  BlockSize;

    //  Number of either initial or initial and maximum block count
    SIZE_T  BlockCount;

    //  Optional field that specifies the memory tag used to allocate this kind of blocks
    ULONG   MemoryTag;

} KM_MEMORY_POOL_BLOCK_DEFINITION, *PKM_MEMORY_POOL_BLOCK_DEFINITION;

/*
    Km_MP_Initialize routine.

    Purpose:
        Initializes a memory pool.

    Parameters:
        MemoryManager       - Pointer to KM_MEMORY_MANAGER structure
                              representing the memory manager to use.
        BlockSize           - Size of each block in the pool in bytes.
        SmartBlockSize      - Boolean value representing whether the pool
                              shoud guess the size of the memory blocks
                              upon first allocation.
        MultipleSizeBlocks  - Boolean value representing whether the pool
                              can contain blocks of different sizes.
        InitialBlockCount   - Number of blocks to allocate in the new pool.
        FixedSize           - Boolean value representing whether the pool
                              can grow in size if there're not enough free
                              entries.

        InstanceHandle      - Pointer to the variable to receive new 
                              pool instance handle.

    Return values:
        STATUS_SUCCESS                  - The routine succeeded.
        STATUS_INVALID_PARAMETER_1      - The MemoryManager parameter is NULL.
        STATUS_INVALID_PARAMETER_2      - The BlockSize is 0.
        STATUS_INVALID_PARAMETER_8      - The InstanceHandle parameter is NULL.
        STATUS_INVALID_PARAMETER_MIX    - The FixedSize parameter is TRUE and the
                                          InitialBlockCount parameter is zero.
*/
NTSTATUS __stdcall Km_MP_Initialize(
    __in                PKM_MEMORY_MANAGER                  MemoryManager,
    __in_opt    const   PKM_MEMORY_POOL_BLOCK_DEFINITION    BlockDefinitions,
    __in        const   ULONG                               NumberOfDefinitions,
    __in        const   ULONG                               Flags,
    __in_opt    const   ULONG                               Tag,
    __out               PHANDLE                             InstanceHandle);

/*
    Km_MP_Finalize routine.

    Purpose:
        Finalizes a memory pool.

    Parameters:
        Instance    - Handle to a memory pool instance to finalize.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER_1  - The Instance parameter is NULL.
        STATUS_UNSUCCESSFUL         - The routine failed to finalize the pool.    
                                      The most possible reason is that there are
                                      blocks allocated from this pool.
                                      Release the allocated blocks using the
                                      Km_MP_Release routine and try again.
*/
NTSTATUS __stdcall Km_MP_Finalize(
    __in    HANDLE  Instance);

/*
    Km_MP_Allocate routine.

    Purpose:
        Allocates a memory block from the memory pool.

    Parameters:
        Instance    - Handle to a memory pool instance.
        Block       - Pointer to the variable to recieve the allocated
                      memory block.

    Return values:
        STATUS_SUCCESS                  - The routine succeeded.
        STATUS_INVALID_PARAMETER_1      - The Instance parameter is NULL.
        STATUS_INVALID_PARAMETER_2      - The Block parameter is NULL.
        STATUS_INSUFFICIENT_RESOURCES   - Low resources situation. 
                                          The pool failed to allocated a new block.
        STATUS_NO_MORE_ENTRIES          - The pool does not have any more available entries.
                                          This can happen if the pool is not growable and
                                          there is no more entries available.
        STATUS_UNSUCCESSFUL             - Pool allocation failed.
*/
#if KM_MEMORY_POOL_EXTENDED_DEBUG_INFO
NTSTATUS __stdcall Km_MP_AllocateEx(
    __in        HANDLE  Instance,
    __in        SIZE_T  Size,
    __out       PVOID   *Block,
    __in_opt    char    *FileName,
    __in_opt    SIZE_T  FileNameLength,
    __in_opt    int     LineNumber,
    __in_opt    char    *FunctionName,
    __in_opt    int     FunctionNameLength);

#define Km_MP_Allocate(Instance, Size, BlockPtr) \
    Km_MP_AllocateEx( \
        (Instance), \
        (Size), \
        (BlockPtr), \
        __FILE__, \
        sizeof(__FILE__), \
        __LINE__, \
        __FUNCTION__, \
        sizeof(__FUNCTION__))

#else
NTSTATUS __stdcall Km_MP_Allocate(
    __in    HANDLE  Instance,
    __in    SIZE_T  Size,
    __out   PVOID   *Block);
#endif

/*
    Km_MP_Release routine.

    Purpose:
        Releases a previously allocated memory block.

    Parameters:
        Block   - Memory block that was allocated from a memory pool.

    Return values:
        STATUS_SUCCESS              - The routine succeeded.
        STATUS_INVALID_PARAMETER_1  - The Block parameter is NULL or 
                                      the memory block header contains invalid data.
        Other status codes          - An error occured.
u*/
NTSTATUS __stdcall Km_MP_Release(
    __in    PVOID   Block);