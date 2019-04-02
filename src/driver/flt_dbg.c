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
// Author: Mikhail Burilov
// 
// Based on original WinPcap source code - https://www.winpcap.org/
// Copyright(c) 1999 - 2005 NetGroup, Politecnico di Torino(Italy)
// Copyright(c) 2005 - 2007 CACE Technologies, Davis(California)
// Filter driver based on Microsoft examples - https://github.com/Microsoft/Windows-driver-samples
// Copyrithg(C) 2015 Microsoft
// All rights reserved.
//////////////////////////////////////////////////////////////////////

//#include  "precomp.h"

#include <ndis.h>
#include "flt_dbg.h"

#define __FILENUMBER 'GBED'

#if DBG

unsigned long FILTER_DEBUG_LEVEL = DL_EXTRA_LOUD;

#define MAX_HD_LENGTH        128

void DbgPrintHexDump(
    __in    PUCHAR  Buffer,
    __in    ULONG   BufferSize)
/*++

Routine Description:

    Print a hex dump of the given contiguous buffer. If the length
    is too long, we truncate it.

Arguments:

    pBuffer            - Points to start of data to be dumped
    Length            - Length of above.

Return Value:

    None

--*/
{
    ULONG        i;

    if (BufferSize > MAX_HD_LENGTH)
    {
        BufferSize = MAX_HD_LENGTH;
    }

    for (i = 0; i < BufferSize; i++)
    {
        //
        //  Check if we are at the end of a line
        //
        if ((i > 0) && ((i & 0xf) == 0))
        {
            DbgPrint("\n");
        }

        //
        //  Print addr if we are at start of a new line
        //
        if ((i & 0xf) == 0)
        {
            DbgPrint("%08p ", Buffer);
        }

        DbgPrint(" %02x", *Buffer++);
    }

    //
    //  Terminate the last line.
    //
    if (BufferSize > 0)
    {
        DbgPrint("\n");
    }
}
#endif // DBG

