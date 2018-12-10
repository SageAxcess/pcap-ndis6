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
// Author: Mikhail Burilov
// 
// Based on original WinPcap source code - https://www.winpcap.org/
// Copyright(c) 1999 - 2005 NetGroup, Politecnico di Torino(Italy)
// Copyright(c) 2005 - 2007 CACE Technologies, Davis(California)
// Filter driver based on Microsoft examples - https://github.com/Microsoft/Windows-driver-samples
// Copyrithg(C) 2015 Microsoft
// All rights reserved.
//////////////////////////////////////////////////////////////////////

// disable warnings


#ifndef _FILTDEBUG__H
#define _FILTDEBUG__H

//
// Message verbosity: lower values indicate higher urgency
//
#define DL_EXTRA_LOUD       20
#define DL_VERY_LOUD        10
#define DL_LOUD             8
#define DL_INFO             6
#define DL_TRACE            5
#define DL_WARN             4
#define DL_ERROR            2
#define DL_FATAL            0

extern unsigned long FILTER_DEBUG_LEVEL;

#if DBG_PRINT

#define DEBUGP(lev, ...)                                                \
        {                                                               \
            if ((lev) <= FILTER_DEBUG_LEVEL)                              \
            {                                                           \
                DbgPrint("PCAPNDIS6: "); DbgPrint(__VA_ARGS__);           \
            }                                                           \
        }

#define DEBUGPDUMP(lev, pBuf, Len)                                      \
        {                                                               \
            if ((lev) <= FILTER_DEBUG_LEVEL)                            \
            {                                                           \
                DbgPrintHexDump((PUCHAR)(pBuf), (ULONG)(Len));          \
            }                                                           \
        }

#define FILTER_ASSERT(exp)                                              \
        {                                                               \
            if (!(exp))                                                 \
            {                                                           \
                DbgPrint("Filter: assert " #exp " failed in"            \
                    " file %s, line %d\n", __FILE__, __LINE__);         \
                DbgBreakPoint();                                        \
            }                                                           \
        }

#define DEBUGP_FUNC_ENTER(Level)                        DEBUGP((Level), "===> "__FUNCTION__"\n")
#define DEBUGP_FUNC_LEAVE(Level)                        DEBUGP((Level), "<=== "__FUNCTION__"\n")
#define DEBUGP_FUNC_LEAVE_WITH_STATUS(Level, Status)    DEBUGP((Level), "<=== "__FUNCTION__", Status = %x\n", (Status))

#define DEBUGP_PRINT_CHAR_ARRAY_W(Level, ArrayPtr, ArraySize) \
{ \
    unsigned long k; \
    for (k = 0; k < (unsigned long)(ArraySize); k++) \
    { \
        DEBUGP((Level), "%C", (ArrayPtr)[k]); \
    } \
}

void DbgPrintHexDump(
    __in    PUCHAR  Buffer,
    __in    ULONG   BufferSize);

#else

//
// No debug
//
#define DEBUGP(lev, ...)
#define DEBUGPDUMP(lev, pBuf, Len)
#define DEBUGP_FUNC_ENTER(Level)
#define DEBUGP_FUNC_LEAVE(Level)
#define DEBUGP_FUNC_LEAVE_WITH_STATUS(Level, Status)

#define FILTER_ASSERT(exp)

#endif    // DBG


#endif // _FILTDEBUG__H
