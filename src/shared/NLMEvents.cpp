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

#include "NLMEvents.h"

NLM_EVENTS::CEventParams::CEventParams(
    __in        const   EVENT_TYPE         Type,
    __in        const   GUID                &Id,
    __in        const   NLM_CONNECTIVITY    Connectivity,
    __in        const   DWORD               Flags,
    __in_opt            LPVOID              Owner) :
    CBaseObject(Owner),
    FType(Type),
    FId(Id),
    FConnectivity(Connectivity),
    FFlags(Flags)
{

};

NLM_EVENTS::CEventParams::~CEventParams()
{

};

NLM_EVENTS::EVENT_TYPE NLM_EVENTS::CEventParams::GetType() const
{
    return FType;
};

void NLM_EVENTS::CEventParams::SetType(
    __in    const   EVENT_TYPE  Value)
{
    FType = Value;
};

REFIID NLM_EVENTS::CEventParams::GetId() const
{
    return FId;
};

void NLM_EVENTS::CEventParams::SetId(
    __in    REFIID  Value)
{
    FId = Value;
};

NLM_CONNECTIVITY NLM_EVENTS::CEventParams::GetConnectivity() const
{
    return FConnectivity;
};

void NLM_EVENTS::CEventParams::SetConnectivity(
    __in    const   NLM_CONNECTIVITY    Value)
{
    FConnectivity = Value;
};

DWORD NLM_EVENTS::CEventParams::GetFlags() const
{
    return FFlags;
};

void NLM_EVENTS::CEventParams::SetFlags(
    __in    const   DWORD   Value)
{
    FFlags = Value;
};

void NLM_EVENTS::CEventsBase::DoOnChange(
    __in    const   CEventParams    &EventParams)
{
    LPON_CHANGE Callback = FOnChange;

    RETURN_IF_FALSE(Assigned(Callback));

    Callback(*this, EventParams);
};

NLM_EVENTS::CEventsBase::CEventsBase(
    __in_opt    LPVOID  Owner) :
    CBaseObject(Owner)
{
};

NLM_EVENTS::CEventsBase::~CEventsBase()
{
};

NLM_EVENTS::CEventsBase::LPON_CHANGE NLM_EVENTS::CEventsBase::GetOnChange() const
{
    return FOnChange;
};

void NLM_EVENTS::CEventsBase::SetOnChange(
    __in    LPON_CHANGE Value)
{
    FOnChange = Value;
};

REFIID NLM_EVENTS::CNetworkEvents::InternalGetConnectionPointRIID()
{
    return IID_INetworkEvents;
};

NLM_EVENTS::CNetworkEvents::CNetworkEvents(
    __in_opt    LPVOID  Owner):
    CAttachableObject(Owner)
{
};

NLM_EVENTS::CNetworkEvents::~CNetworkEvents()
{
    FDestructorInProgress = TRUE;
    Detach();
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkEvents::NetworkAdded(
    __in    GUID    NetworkId)
{
    DoOnChange(
        CEventParams(
            EVENT_TYPE::ctNetworkAdded,
            NetworkId,
            NLM_CONNECTIVITY_DISCONNECTED,
            0));

    return NOERROR;
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkEvents::NetworkDeleted(
    __in    GUID    NetworkId)
{
    DoOnChange(
        CEventParams(
            EVENT_TYPE::ctNetworkRemoved,
            NetworkId,
            NLM_CONNECTIVITY_DISCONNECTED,
            0));

    return NOERROR;
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkEvents::NetworkConnectivityChanged(
    __in    GUID                NetworkId,
    __in    NLM_CONNECTIVITY    NewConnectivity)
{
    DoOnChange(
        CEventParams(
            EVENT_TYPE::ctNetworkConnectivityChanged,
            NetworkId,
            NewConnectivity,
            0));

    return NOERROR;
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkEvents::NetworkPropertyChanged(
    __in    GUID                        NetworkId,
    __in    NLM_NETWORK_PROPERTY_CHANGE Flags)
{
    DoOnChange(
        CEventParams(
            EVENT_TYPE::ctNetworkPropertyChanged,
            NetworkId,
            NLM_CONNECTIVITY_DISCONNECTED,
            static_cast<DWORD>(Flags)));

    return NOERROR;
};

ULONG STDMETHODCALLTYPE NLM_EVENTS::CNetworkEvents::AddRef()
{
    return __super::AddRef();
};

ULONG STDMETHODCALLTYPE NLM_EVENTS::CNetworkEvents::Release()
{
    return __super::Release();
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkEvents::QueryInterface(
    __in    REFIID  riid,
    __out   void    **ppvObject)
{
    HRESULT Result = __super::QueryInterface(riid, ppvObject);

    RETURN_VALUE_IF_FALSE(
        Result != E_INVALIDARG,
        Result);

    RETURN_VALUE_IF_FALSE(
        Result == E_NOINTERFACE,
        Result);

    if (riid == IID_INetworkEvents)
    {
        *ppvObject = reinterpret_cast<LPVOID>(static_cast<INetworkEvents *>(this));
        AddRef();
        Result = NOERROR;
    }

    return Result;
};

REFIID NLM_EVENTS::CNetworkConnectionEvents::InternalGetConnectionPointRIID()
{
    return IID_INetworkConnectionEvents;
};

NLM_EVENTS::CNetworkConnectionEvents::CNetworkConnectionEvents(
    __in_opt    LPVOID  Owner):
    CEventsBase(Owner),
    CAttachableObject(Owner)
{
};

NLM_EVENTS::CNetworkConnectionEvents::~CNetworkConnectionEvents()
{
    FDestructorInProgress = TRUE;
    Detach();
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkConnectionEvents::NetworkConnectionConnectivityChanged(
    __in    GUID                ConnectionId,
    __in    NLM_CONNECTIVITY    NewConnectivity)
{
    DoOnChange(
        CEventParams(
            EVENT_TYPE::ctNetworkConnectionConnectivityChanged,
            ConnectionId,
            NewConnectivity,
            0));

    return NOERROR;
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkConnectionEvents::NetworkConnectionPropertyChanged(
    __in    GUID                            ConnectionId,
    __in    NLM_CONNECTION_PROPERTY_CHANGE  Flags)
{
    DoOnChange(
        CEventParams(
            EVENT_TYPE::ctNetworkConnectionPropertyChanged,
            ConnectionId,
            NLM_CONNECTIVITY_DISCONNECTED,
            static_cast<DWORD>(Flags)));

    return NOERROR;
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetworkConnectionEvents::QueryInterface(
    __in    REFIID  riid,
    __out   void    **ppvObject)
{
    HRESULT Result = __super::QueryInterface(riid, ppvObject);

    RETURN_VALUE_IF_FALSE(
        Result != E_INVALIDARG,
        Result);

    RETURN_VALUE_IF_FALSE(
        Result == E_NOINTERFACE,
        Result);

    if (riid == IID_INetworkConnectionEvents)
    {
        *ppvObject = static_cast<INetworkConnectionEvents *>(this);
        __super::AddRef();
        Result = NOERROR;
    }

    return Result;
};

ULONG STDMETHODCALLTYPE NLM_EVENTS::CNetworkConnectionEvents::AddRef()
{
    return __super::AddRef();
};

ULONG STDMETHODCALLTYPE NLM_EVENTS::CNetworkConnectionEvents::Release()
{
    return __super::Release();
};

REFIID NLM_EVENTS::CNetListManagerEvents::InternalGetConnectionPointRIID()
{
    return IID_INetworkListManagerEvents;
};

NLM_EVENTS::CNetListManagerEvents::CNetListManagerEvents(
    __in_opt    LPVOID  Owner):
    CEventsBase(Owner),
    CAttachableObject(Owner)
{
};

NLM_EVENTS::CNetListManagerEvents::~CNetListManagerEvents()
{
    FDestructorInProgress = TRUE;
    Detach();
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetListManagerEvents::ConnectivityChanged(
    __in    NLM_CONNECTIVITY    NewConnectivity)
{
    DoOnChange(
        CEventParams(
            EVENT_TYPE::ctConnectivityChanged,
            GUID_NULL,
            NewConnectivity,
            0));

    return NOERROR;
};

ULONG STDMETHODCALLTYPE NLM_EVENTS::CNetListManagerEvents::AddRef()
{
    return __super::AddRef();
};

ULONG STDMETHODCALLTYPE NLM_EVENTS::CNetListManagerEvents::Release()
{
    return __super::Release();
};

HRESULT STDMETHODCALLTYPE NLM_EVENTS::CNetListManagerEvents::QueryInterface(
    __in    REFIID  riid,
    __out   void    **ppvObject)
{
    HRESULT Result = __super::QueryInterface(riid, ppvObject);

    RETURN_VALUE_IF_FALSE(
        Result != E_INVALIDARG,
        Result);

    RETURN_VALUE_IF_FALSE(
        Result == E_NOINTERFACE,
        Result);

    if (riid == IID_INetworkConnectionEvents)
    {
        *ppvObject = static_cast<INetworkListManagerEvents *>(this);
        __super::AddRef();
        Result = NOERROR;
    }

    return Result;
};

void NLM_EVENTS::CNetEventsManager::ThreadRoutine()
{
    HANDLE  WaitArray[] = { InternalGetStopEvent() };
    BOOL    StopThread = !InternalInitialize();
    __try
    {
        while (!StopThread)
        {
            DWORD WaitResult = MsgWaitForMultipleObjects(
                1,
                WaitArray,
                FALSE,
                INFINITE,
                MAXDWORD);

            switch (WaitResult)
            {
            case WAIT_OBJECT_0:
                {
                    StopThread = TRUE;
                }break;

            case WAIT_OBJECT_0 + 1:
                {
                    MSG Message;

                    while (PeekMessageW(&Message, NULL, 0, 0, PM_REMOVE))
                    {
                        TranslateMessage(&Message);
                        DispatchMessageW(&Message);
                    }

                }break;
            }
        }
    }
    __finally
    {
        InternalFinalize();
    }
};

BOOL NLM_EVENTS::CNetEventsManager::InternalInitialize()
{
    BOOL    Result = FALSE;
    HRESULT hResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    RETURN_VALUE_IF_FALSE(
        (hResult == S_OK) ||
        (hResult == S_FALSE),
        FALSE);

    hResult = CoCreateInstance(
        CLSID_NetworkListManager,
        nullptr,
        CLSCTX_ALL,
        IID_INetworkListManager,
        (LPVOID *)&FNetworkListManager);
    RETURN_VALUE_IF_FALSE(
        SUCCEEDED(hResult),
        FALSE);
    __try
    {
        hResult = FNetworkListManager->QueryInterface(
            IID_IConnectionPointContainer,
            (void **)&FConnectionPointContainer);
    }
    __finally
    {
        if (!SUCCEEDED(hResult))
        {
            FNetworkListManager->Release();
            FNetworkListManager = nullptr;
        }
    }

    if (SUCCEEDED(hResult))
    {
        __try
        {
            Result = FNetListManagerEvents->Attach(FConnectionPointContainer);
            LEAVE_IF_FALSE(Result);
            __try
            {
                Result = FNetworkEvents->Attach(FConnectionPointContainer);
                LEAVE_IF_FALSE(Result);
                __try
                {
                    Result = FNetworkConnectionEvents->Attach(FConnectionPointContainer);
                }
                __finally
                {
                    if (!Result)
                    {
                        FNetworkEvents->Detach();
                    }
                }
            }
            __finally
            {
                if (!Result)
                {
                    FNetListManagerEvents->Detach();
                }
            }
        }
        __finally
        {
            if (!Result)
            {
                FConnectionPointContainer->Release();
                FConnectionPointContainer = nullptr;
                FNetworkListManager->Release();
                FNetworkListManager = nullptr;
            }
        }
    }

    return Result;
};

void NLM_EVENTS::CNetEventsManager::InternalFinalize()
{
    if (Assigned(FNetListManagerEvents))
    {
        FNetListManagerEvents->Detach();
    }

    if (Assigned(FNetworkEvents))
    {
        FNetworkEvents->Detach();
    }

    if (Assigned(FNetworkConnectionEvents))
    {
        FNetworkConnectionEvents->Detach();
    }
};

void NLM_EVENTS::CNetEventsManager::InvokeClientCallback(
    __in    const   EVENT_TYPE          EventType,
    __in    const   GUID                &Id,
    __in    const   NLM_CONNECTIVITY    Connectivity,
    __in    const   DWORD               Flags) const
{
    EVENT_CALLBACK  Callback = { nullptr };

    std::unordered_map<int, int> a;

    (const_cast<CNetEventsManager *>(this))->Enter();
    try
    {
        if (FCallbacks.find(EventType) != FCallbacks.end())
        {
            Callback = FCallbacks.at(EventType);
        }
    }
    catch (...)
    {
    }
    (const_cast<CNetEventsManager *>(this))->Leave();

    RETURN_IF_FALSE(Assigned(Callback.Untyped));

    switch (EventType)
    {
    case EVENT_TYPE::ctNetworkAdded:
        {
            Callback.OnNetworkAdd(*this, Id);
        }break;

    case EVENT_TYPE::ctNetworkRemoved:
        {
            Callback.OnNetworkRemove(*this, Id);
        }break;

    case EVENT_TYPE::ctNetworkConnectionAdded:
        {
            Callback.OnNetworkConnectionAdd(*this, Id);
        }break;

    case EVENT_TYPE::ctNetworkConnectionRemoved:
        {
            Callback.OnNetworkConnectionRemove(*this, Id);
        }break;

    case EVENT_TYPE::ctNetworkConnectivityChanged:
        {
            Callback.OnNetworkConnectivityChange(
                *this,
                Id,
                Connectivity);
        }break;

    case EVENT_TYPE::ctNetworkPropertyChanged:
        {
            Callback.OnNetworkPropertyChange(
                *this,
                Id,
                Flags);
        }break;

    case EVENT_TYPE::ctNetworkConnectionConnectivityChanged:
        {
            Callback.OnNetworkConnectionConnectivityChange(
                *this,
                Id,
                Connectivity);
        }break;

    case EVENT_TYPE::ctNetworkConnectionPropertyChanged:
        {
            Callback.OnNetworkConnectionPropertyChange(
                *this,
                Id,
                Flags);
        }break;

    case EVENT_TYPE::ctConnectivityChanged:
        {
            Callback.OnConnectivityChange(*this, Connectivity);
        }break;
    };
};

NLM_EVENTS::CNetEventsManager::EVENT_CALLBACK NLM_EVENTS::CNetEventsManager::GetClientCallbackByType(
    __in    const   EVENT_TYPE  EventType) const
{
    EVENT_CALLBACK  Result = { nullptr };

    (const_cast<CNetEventsManager *>(this))->Enter();
    try
    {
        if (FCallbacks.find(EventType) != FCallbacks.end())
        {
            Result = FCallbacks.at(EventType);
        }
    }
    catch (...)
    {
    }
    (const_cast<CNetEventsManager *>(this))->Leave();

    return Result;
};

void NLM_EVENTS::CNetEventsManager::SetClientCallbackByType(
    __in    const   EVENT_TYPE      EventType,
    __in    const   EVENT_CALLBACK  &Callback)
{
    Enter();
    try
    {
        if (!((FCallbacks.find(EventType) == FCallbacks.end()) && (!Assigned(Callback.Untyped))))
        {
            FCallbacks[EventType] = Callback;
        }
    }
    catch (...)
    {
    }
    Leave();
};

NLM_EVENTS::CNetEventsManager::CNetEventsManager(
    __in_opt    LPVOID  Owner):
    CCSObject(),
    CThread(Owner, TRUE)
{

};

NLM_EVENTS::CNetEventsManager::~CNetEventsManager()
{
    Enter();
    Leave();
    Stop();
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_ADD_REMOVE NLM_EVENTS::CNetEventsManager::GetOnNetworkAdd() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkAdded).OnNetworkAdd;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkAdd(
    __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkAdd = Value;
    SetClientCallbackByType(EVENT_TYPE::ctNetworkAdded, Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_ADD_REMOVE NLM_EVENTS::CNetEventsManager::GetOnNetworkRemove() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkRemoved).OnNetworkRemove;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkRemove(
    __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkRemove = Value;
    SetClientCallbackByType(EVENT_TYPE::ctNetworkRemoved, Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_ADD_REMOVE NLM_EVENTS::CNetEventsManager::GetOnNetworkConnectionAdd() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkConnectionAdded).OnNetworkConnectionAdd;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkConnectionAdd(
    __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkConnectionAdd = Value;
    SetClientCallbackByType(EVENT_TYPE::ctNetworkConnectionAdded, Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_ADD_REMOVE NLM_EVENTS::CNetEventsManager::GetOnNetworkConnectionRemove() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkConnectionRemoved).OnNetworkConnectionRemove;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkConnectionRemove(
    __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkConnectionRemove = Value;

    SetClientCallbackByType(
        EVENT_TYPE::ctNetworkConnectionRemoved,
        Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_CONNECTIVITY_CHANGE NLM_EVENTS::CNetEventsManager::GetOnNetworkConnectivityChange() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkConnectionConnectivityChanged).OnNetworkConnectivityChange;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkConnectivityChange(
    __in    const   LPON_NET_ENTITY_CONNECTIVITY_CHANGE Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkConnectivityChange = Value;
    SetClientCallbackByType(
        EVENT_TYPE::ctNetworkConnectivityChanged,
        Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_CONNECTIVITY_CHANGE NLM_EVENTS::CNetEventsManager::GetOnNetworkConnectionConnectivityChange() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkConnectionConnectivityChanged).OnNetworkConnectionConnectivityChange;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkConnectionConnectivityChange(
    __in    const   LPON_NET_ENTITY_CONNECTIVITY_CHANGE Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkConnectionConnectivityChange = Value;
    SetClientCallbackByType(
        EVENT_TYPE::ctNetworkConnectionConnectivityChanged,
        Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_PROPERTY_CHANGE NLM_EVENTS::CNetEventsManager::GetOnNetworkPropertyChange() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkPropertyChanged).OnNetworkPropertyChange;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkPropertyChange(
    __in    const   LPON_NET_ENTITY_PROPERTY_CHANGE Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkPropertyChange = Value;
    SetClientCallbackByType(
        EVENT_TYPE::ctNetworkPropertyChanged,
        Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_NET_ENTITY_PROPERTY_CHANGE NLM_EVENTS::CNetEventsManager::GetOnNetworkConnectionPropertyChange() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctNetworkConnectionPropertyChanged).OnNetworkConnectionPropertyChange;
};

void NLM_EVENTS::CNetEventsManager::SetOnNetworkConnectionPropertyChange(
    __in    const   LPON_NET_ENTITY_PROPERTY_CHANGE Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnNetworkConnectionPropertyChange = Value;
    SetClientCallbackByType(
        EVENT_TYPE::ctNetworkConnectionPropertyChanged,
        Callback);
};

NLM_EVENTS::CNetEventsManager::LPON_CONNECTIVITY_CHANGE NLM_EVENTS::CNetEventsManager::GetOnConnectivityChange() const
{
    return GetClientCallbackByType(EVENT_TYPE::ctConnectivityChanged).OnConnectivityChange;
};

void NLM_EVENTS::CNetEventsManager::SetOnConnectivityChange(
    __in    const   LPON_CONNECTIVITY_CHANGE    Value)
{
    EVENT_CALLBACK  Callback;
    Callback.OnConnectivityChange = Value;
    SetClientCallbackByType(
        EVENT_TYPE::ctConnectivityChanged,
        Callback);
};