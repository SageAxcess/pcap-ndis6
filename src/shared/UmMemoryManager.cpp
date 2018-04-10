#include "UmMemoryManager.h"

#include "..\shared\CommonDefs.h"

HANDLE  UMM_HeapHandle = NULL;

void __stdcall UMM_Initialize()
{
    HANDLE  HeapHandle = NULL;

    RETURN_IF_FALSE(UMM_HeapHandle == NULL);

    HeapHandle = HeapCreate(0, 0, 0);

    InterlockedExchangePointer(
        reinterpret_cast<PVOID *>(&UMM_HeapHandle),
        reinterpret_cast<PVOID>(HeapHandle));
};

void __stdcall UMM_Finalize()
{
    HANDLE  HeapHandle = NULL;

    HeapHandle = reinterpret_cast<HANDLE>(InterlockedExchangePointer(
        reinterpret_cast<PVOID *>(&UMM_HeapHandle),
        nullptr));
    RETURN_IF_FALSE(HeapHandle != NULL);

    HeapDestroy(HeapHandle);
};

LPVOID __stdcall UMM_AllocMem(
    __in    SIZE_T  Size)
{
    RETURN_VALUE_IF_FALSE(
        UMM_HeapHandle != NULL,
        nullptr);

    return HeapAlloc(UMM_HeapHandle, HEAP_ZERO_MEMORY, Size);
};

LPVOID __stdcall UMM_ReAllocMem(
    __in    LPVOID  Ptr,
    __in    SIZE_T  NewSize)
{
    RETURN_VALUE_IF_FALSE(
        (UMM_HeapHandle != NULL) &&
        (Assigned(Ptr)),
        nullptr);

    return HeapReAlloc(
        UMM_HeapHandle,
        HEAP_ZERO_MEMORY,
        Ptr,
        NewSize);
};

void __stdcall UMM_FreeMem(
    __in    LPVOID  Ptr)
{
    RETURN_IF_FALSE(
        (UMM_HeapHandle != NULL) &&
        (Assigned(Ptr)));

    HeapFree(UMM_HeapHandle, 0, Ptr);
};