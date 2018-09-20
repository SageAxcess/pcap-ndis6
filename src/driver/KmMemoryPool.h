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

/*
    Km_MP_Initialize routine.

    Purpose:
        Initializes a memory pool.

    Parameters:
        MemoryManager       - Pointer to KM_MEMORY_MANAGER structure
                              representing the memory manager to use.
        BlockSize           - Size of each block in the pool in bytes.
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
        STATUS_INVALID_PARAMETER_5      - The InstanceHandle parameter is NULL.
        STATUS_INVALID_PARAMETER_MIX    - The FixedSize parameter is TRUE and the
                                          InitialBlockCount parameter is zero.
*/
NTSTATUS __stdcall Km_MP_Initialize(
    __in        PKM_MEMORY_MANAGER  MemoryManager,
    __in        ULONG               BlockSize,
    __in        ULONG               InitialBlockCount,
    __in        BOOLEAN             FixedSize,
    __in_opt    ULONG               Tag,
    __out       PHANDLE             InstanceHandle);

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
NTSTATUS __stdcall Km_MP_Allocate(
    __in    HANDLE  Instance,
    __out   PVOID   *Block);

/*
    Km_MP_AllocateCheckSize routine.

    Purpose:
        Checks whether a block of requested size can
        be allocated from the pool and allocates it.
        
    Parameters:
        Instance    - Handle to a memory pool instance.
        Block       - Pointer to the variable to recieve the allocated
    memory block.

    Return values:
        STATUS_SUCCESS                  - The routine succeeded.
        STATUS_INVALID_PARAMETER_1      - The Instance parameter is NULL.
        STATUS_INVALID_PARAMETER_2      - The Size parameter is 0.
        STATUS_INVALID_PARAMETER_3      - The Block parameter is NULL.
        STATUS_INSUFFICIENT_RESOURCES   - Low resources situation.
                                          The pool failed to allocated a new block.
        STATUS_BUFFER_TOO_SMALL         - The size requested is more than the size
                                          of the elements in the pool.
        STATUS_NO_MORE_ENTRIES          - The pool does not have any more available entries.
                                          This can happen if the pool is not growable and
                                          there is no more entries available.
        STATUS_UNSUCCESSFUL             - Pool allocation failed.
*/
NTSTATUS __stdcall Km_MP_AllocateCheckSize(
    __in    HANDLE  Instance,
    __in    SIZE_T  Size,
    __out   PVOID   *Block); 

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