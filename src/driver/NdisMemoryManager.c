#include "..\shared\CommonDefs.h"
#include "NdisMemoryManager.h"

typedef struct _NDIS_MM_MEM_BLOCK_HEADER
{
    LIST_ENTRY  Link;

    PNDIS_MM    MemoryManager;

    SIZE_T      Size;

    SIZE_T      MaxSize;

} NDIS_MM_MEM_BLOCK_HEADER, *PNDIS_MM_MEM_BLOCK_HEADER;

NTSTATUS __stdcall Ndis_MM_Initialize(
    __in    PNDIS_MM            MemoryManager,
    __in    NDIS_HANDLE         NdisHandle,
    __in    EX_POOL_PRIORITY    PoolPriority,
    __in    ULONG               Tag)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER_1);
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        NdisHandle != NULL,
        STATUS_INVALID_PARAMETER_2);

    Status = Km_Lock_Initialize(&MemoryManager->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));

    InitializeListHead(&MemoryManager->AllocatedBlocks);

    MemoryManager->NdisObjectHandle = NdisHandle;
    MemoryManager->PoolPriority = PoolPriority;
    MemoryManager->Tag = Tag;

cleanup:
    return Status;
};

NTSTATUS __stdcall Ndis_MM_Finalize(
    __in    PNDIS_MM    MemoryManager)
{
    NTSTATUS    Status = STATUS_SUCCESS;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryManager),
        STATUS_INVALID_PARAMETER);

    Status = Km_Lock_Acquire(&MemoryManager->Lock);
    GOTO_CLEANUP_IF_FALSE(NT_SUCCESS(Status));
    __try
    {
        if (!IsListEmpty(&MemoryManager->AllocatedBlocks))
        {
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    __finally
    {
        Km_Lock_Release(&MemoryManager->Lock);
    }

    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(MemoryManager, sizeof(NDIS_MM));
    }

cleanup:
    return Status;
};

PVOID __stdcall Ndis_MM_AllocMem(
    __in    PNDIS_MM    MemoryManager,
    __in    UINT        Size)
{
    PVOID       Result = NULL;
    UINT        SizeRequired;

    RETURN_VALUE_IF_FALSE(
        (Assigned(MemoryManager)) &&
        (Size > 0),
        NULL);

    SizeRequired = sizeof(NDIS_MM_MEM_BLOCK_HEADER) + Size;

    RETURN_VALUE_IF_FALSE(
        NT_SUCCESS(Km_Lock_Acquire(&MemoryManager->Lock)),
        NULL);
    __try
    {
        PVOID   NewBlock = NdisAllocateMemoryWithTagPriority(
            MemoryManager->NdisObjectHandle,
            SizeRequired,
            MemoryManager->Tag,
            MemoryManager->PoolPriority);

        if (Assigned(NewBlock))
        {
            PNDIS_MM_MEM_BLOCK_HEADER Header = (PNDIS_MM_MEM_BLOCK_HEADER)NewBlock;

            Header->Size = Header->MaxSize = Size;
            Header->MemoryManager = MemoryManager;

            InsertHeadList(
                &MemoryManager->AllocatedBlocks, 
                &Header->Link);

            Result = (PVOID)((PUCHAR)NewBlock + sizeof(NDIS_MM_MEM_BLOCK_HEADER));
        }
    }
    __finally
    {
        Km_Lock_Release(&MemoryManager->Lock);
    }

    return Result;
};

NTSTATUS __stdcall Ndis_MM_FreeMem(
    __in    PVOID   MemoryBlock)
{
    NTSTATUS                    Status = STATUS_SUCCESS;
    PNDIS_MM_MEM_BLOCK_HEADER   Header;

    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(MemoryBlock),
        STATUS_INVALID_PARAMETER);

    Header = (PNDIS_MM_MEM_BLOCK_HEADER)((PUCHAR)MemoryBlock - sizeof(NDIS_MM_MEM_BLOCK_HEADER));
    GOTO_CLEANUP_IF_FALSE_SET_STATUS(
        Assigned(Header->MemoryManager),
        STATUS_INVALID_PARAMETER);



cleanup:
    return Status;
};