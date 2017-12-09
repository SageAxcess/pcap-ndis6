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

#define BREAK_IF_TRUE(Condition) \
{ \
    if (Condition) \
    { \
        break; \
    } \
}

#define BREAK_IF_FALSE(Condition)   BREAK_IF_TRUE(!(Condition))

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