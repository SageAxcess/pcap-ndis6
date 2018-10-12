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
// Author: Andrey Fedorinin
//////////////////////////////////////////////////////////////////////
#pragma once

#define Assigned(Expression)            ((Expression) != NULL)

#define SET_BIT_FLAG(Value, Flag)       ((Value) |= (Flag))
#define CLEAR_BIT_FLAG(Value, Flag)     ((Value) &= ~(Flag))
#define IS_BIT_FLAG_SET(Value, Flag)    (((Value) & (Flag)) == (Flag))

#define SetBitFlag		                SET_BIT_FLAG
#define ClearBitFlag	                CLEAR_BIT_FLAG
#define IsBitFlagSet	                IS_BIT_FLAG_SET

#define RETURN_VALUE_IF_TRUE(Condition, Value) \
{ \
    if (Condition) \
    { \
        return (Value); \
    } \
}

#define RETURN_VALUE_IF_FALSE(Condition, Value) RETURN_VALUE_IF_TRUE(!(Condition), (Value))

#define RETURN_IF_TRUE(Condition) \
{ \
    if (Condition) \
    { \
        return; \
    } \
}

#define RETURN_IF_FALSE(Condition)  RETURN_IF_TRUE(!(Condition))

#define RETURN_IF_TRUE_EX(Condition, AdditionalCommand) \
{ \
    if (Condition) \
    { \
        (AdditionalCommand); \
        return; \
    } \
}

#define RETURN_IF_FALSE_EX(Condition, AdditionalCommand)    RETURN_IF_TRUE_EX(!(Condition), (AdditionalCommand))


#define RETURN_VALUE_IF_TRUE_EX(Condition, Value, AdditionalCommand) \
{ \
    if (Condition) \
    { \
        AdditionalCommand; \
        return (Value); \
    } \
}

#define RETURN_VALUE_IF_FALSE_EX(Condition, Value, AdditionalCommand)   RETURN_VALUE_IF_TRUE_EX((Condition), (Value), (AdditionalCommand))

#define GOTO_CLEANUP_IF_TRUE(Condition) \
{ \
    if (Condition) \
    { \
        goto cleanup; \
    } \
}

#define GOTO_CLEANUP_IF_FALSE(Condition)    GOTO_CLEANUP_IF_TRUE(!(Condition))

#define GOTO_CLEANUP_IF_TRUE_SET_STATUS(Condition, StatusValue) \
{ \
    if (Condition) \
    { \
        Status = (StatusValue); \
        goto cleanup; \
    } \
}

#define GOTO_CLEANUP_IF_FALSE_SET_STATUS(Condition, StatusValue) \
    GOTO_CLEANUP_IF_TRUE_SET_STATUS(!(Condition), (StatusValue))

#define LEAVE_IF_TRUE(Condition) \
{ \
    if (Condition) \
    { \
        __leave; \
    } \
}

#define LEAVE_IF_FALSE(Condition)   LEAVE_IF_TRUE(!(Condition))

#define LEAVE_IF_TRUE_SET_STATUS(Condition, StatusValue) \
{ \
    if (Condition) \
    { \
        Status = (StatusValue); \
        __leave; \
    } \
}

#define LEAVE_IF_FALSE_SET_STATUS(Condition, StatusValue)   LEAVE_IF_TRUE_SET_STATUS(!(Condition), (StatusValue))

#define LEAVE_IF_TRUE_EX(Condition, AdditionalCommand) \
{ \
    if (Condition) \
    { \
        (AdditionalCommand); \
        __leave; \
    } \
}

#define LEAVE_IF_FALSE_EX(Condition, AdditionalCommand) LEAVE_IF_TRUE_EX(!(Condition), (AdditionalCommand))

#define LEAVE_IF_TRUE_SET_STATUS_EX(Condition, StatusValue, AdditionalCommand) \
{ \
    if (Condition) \
    { \
        Status = (StatusValue); \
        (AdditionalCommand); \
        __leave; \
    } \
}

#define LEAVE_IF_FALSE_SET_STATUS_EX(Condition, StatusValue, AdditionalCommand) \
    LEAVE_IF_TRUE_SET_STATUS_EX(!(Condition), (StatusValue), (AdditionalCommand))

#define BREAK_IF_TRUE(Condition) \
{ \
    if (Condition) \
    { \
        break; \
    } \
}

#define BREAK_IF_FALSE(Condition)   BREAK_IF_TRUE(!(Condition))

#define BREAK_IF_TRUE_EX(Condition, AdditionalCommand) \
{ \
    if (Condition) \
    { \
        (AdditionalCommand); \
        break; \
    } \
}

#define BREAK_IF_FALSE_EX(Condition, AdditionalCommand) BREAK_IF_TRUE_EX((Condition), (AdditionalCommand))

#define BREAK_IF_TRUE_SET_STATUS(Condition, StatusValue) \
{ \
    if (Condition) \
    { \
        Status = (StatusValue); \
        break; \
    } \
}

#define BREAK_IF_FALSE_SET_STATUS(Condition, StatusValue)   BREAK_IF_TRUE_SET_STATUS(!(Condition), (StatusValue))

#define CONTINUE_IF_TRUE(Condition) \
{ \
    if (Condition) \
    { \
        continue; \
    } \
}

#define CONTINUE_IF_FALSE(Condition)    CONTINUE_IF_TRUE(!(Condition))

#define COMPARE_VALUES(Value1, Value2) \
    ((Value1) > (Value2) ? \
     1 : \
     (Value1) < (Value2) ? \
     -1 : \
     0)

#define SHIFT_R(Value, Bits)    ((Value) >> (Bits))
#define SHIFT_L(Value, Bits)    ((Value) << (Bits))

#define BYTES_SWAP_16(Value16)  (SHIFT_R((Value16) & 0xFF00, 8) | SHIFT_L((Value16) & 0xFF, 8))

#define BYTES_SWAP_32(Value32) \
    (SHIFT_R((Value32) & 0xFF000000, 24) | \
     SHIFT_R((Value32) & 0x00FF0000, 8) | \
     SHIFT_L((Value32) & 0x0000FF00, 8) | \
     SHIFT_L((Value32) & 0x000000FF, 24))

#define BYTES_SWAP_16_2(Value16) \
{ \
    (Value16) = BYTES_SWAP_16(Value16); \
}

#define BYTES_SWAP_32_2(Value32) \
{ \
    (Value32) = BYTES_SWAP_32(Value32); \
}

#define IP6_SWAP_BYTE_ORDER(IPv6Address) \
{ \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[0]); \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[1]); \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[2]); \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[3]); \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[4]); \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[5]); \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[6]); \
    BYTES_SWAP_16_2(((unsigned short *)(IPv6Address))[7]); \
}

#define TicksInASecond              10000000
#define TicksInAMicrosecond         10
#define MicrosecondsInASecond       1000000

#define TicksToSeconds(Value)       ((Value) / TicksInASecond)
#define TicksToMicroseconds(Value)  ((Value) / TicksInAMicrosecond)

#define LogMessageToConsole(Message, ...) \
{ \
    printf("[DBG][%s]: ", __FUNCTION__); \
    printf((Message), __VA_ARGS__); \
}