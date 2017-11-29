#pragma once

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

#define GOTO_CLEANUP_IF_TRUE(Condition) \
{ \
    if (Condition) \
    { \
        goto cleanup;
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