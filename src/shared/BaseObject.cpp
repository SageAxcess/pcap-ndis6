#include "BaseObject.h"

CBaseObject::CBaseObject(
    __in_opt    LPVOID  Owner) :
    FOwner(Owner)
{
};

CBaseObject::~CBaseObject()
{
};

template <typename T>
T * CBaseObject::GetOwnerAs() const
{
    return reinterpret_cast<T *>(FOwner);
};

LPVOID CBaseObject::GetOwner() const
{
    return FOwner;
};

void CBaseObject::SetOwner(
    __in    LPVOID  Value)
{
    FOwner = Value;
};