#pragma once

#include <Windows.h>

void __stdcall UMM_Initialize();

void __stdcall UMM_Finalize();

LPVOID __stdcall UMM_AllocMem(
    __in    SIZE_T  Size);

LPVOID __stdcall UMM_ReAllocMem(
    __in    LPVOID  Ptr,
    __in    SIZE_T  NewSize);

void __stdcall UMM_FreeMem(
    __in    LPVOID  Ptr);

template <typename T> T * __stdcall UMM_AllocTypedWithSize(
    __in    SIZE_T  Size)
{
    return reinterpret_cast<T *>(UMM_AllocMem(Size));
};

template <typename T> T * __stdcall UMM_AllocTyped()
{
    return UMM_AllocTypedWithSize<T>(sizeof(T));
};

template <typename T> T * __stdcall UMM_AllocArray(
    __in    SIZE_T  ItemCount)
{
    return UMM_AllocTypedWithSize<T>(sizeof(T) * ItemCount);
};
