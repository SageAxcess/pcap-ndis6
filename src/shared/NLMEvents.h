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

#include "AttachableObject.h"
#include "CSObject.h"
#include "ThreadObject.h"
#include <netlistmgr.h>
#include <unordered_map>

namespace NLM_EVENTS
{

    typedef enum class _EVENT_TYPE
    {
        ctNone,
        ctNetworkAdded,
        ctNetworkRemoved,
        ctNetworkConnectionAdded,
        ctNetworkConnectionRemoved,
        ctNetworkConnectivityChanged,
        ctNetworkPropertyChanged,
        ctNetworkConnectionConnectivityChanged,
        ctNetworkConnectionPropertyChanged,
        ctConnectivityChanged
    } EVENT_TYPE, *PEVENT_TYPE, *LPEVENT_TYPE;

    class CEventParams :
        virtual public CBaseObject
    {
    private:
        EVENT_TYPE          FType = EVENT_TYPE::ctNone;
        GUID                FId = GUID_NULL;
        NLM_CONNECTIVITY    FConnectivity = NLM_CONNECTIVITY::NLM_CONNECTIVITY_DISCONNECTED;
        DWORD               FFlags = 0;

    public:
        explicit CEventParams(
            __in        const   EVENT_TYPE          Type,
            __in        const   GUID                &Id,
            __in        const   NLM_CONNECTIVITY    Connectivity,
            __in        const   DWORD               Flags,
            __in_opt            LPVOID              Owner = nullptr);
        virtual ~CEventParams();

        virtual EVENT_TYPE GetType() const;
        virtual void SetType(
            __in    const   EVENT_TYPE  Value);

        virtual REFIID GetId() const;
        virtual void SetId(
            __in    REFIID  Value);

        virtual NLM_CONNECTIVITY GetConnectivity() const;
        virtual void SetConnectivity(
            __in    const   NLM_CONNECTIVITY    Value);

        virtual DWORD GetFlags() const;
        virtual void SetFlags(
            __in    const   DWORD   Value);

        CLASS_PROPERTY(EVENT_TYPE, Type);
        CLASS_PROPERTY(REFIID, Id);
        CLASS_PROPERTY(NLM_CONNECTIVITY, Connectivity);
        CLASS_PROPERTY(DWORD, Flags);
    };

    class CEventsBase :
        virtual public CBaseObject
    {
    public:
        typedef void(__stdcall *LPON_CHANGE)(
            __in    const   CEventsBase     &EventsObject,
            __in    const   CEventParams    &ChangeParams);

    private:
        LPON_CHANGE FOnChange = nullptr;

    protected:
        virtual void DoOnChange(
            __in    const   CEventParams &EventParams);

    public:
        CEventsBase(
            __in_opt    LPVOID  Owner = nullptr);
        virtual ~CEventsBase();

        virtual LPON_CHANGE GetOnChange() const;
        virtual void SetOnChange(
            __in    LPON_CHANGE Value);

        CLASS_PROPERTY(LPON_CHANGE, OnChange);
    };

    class CNetworkEvents :
        virtual public CEventsBase,
        virtual public CAttachableObject,
        virtual public INetworkEvents
    {
    protected:
        virtual REFIID InternalGetConnectionPointRIID();

    public:
        CNetworkEvents(
            __in_opt    LPVOID  Owner = nullptr);

        virtual ~CNetworkEvents();

        virtual HRESULT STDMETHODCALLTYPE NetworkAdded(
            __in    GUID    NetworkId);

        virtual HRESULT STDMETHODCALLTYPE NetworkDeleted(
            __in    GUID    NetworkId);

        virtual HRESULT STDMETHODCALLTYPE NetworkConnectivityChanged(
            __in    GUID                NetworkId,
            __in    NLM_CONNECTIVITY    NewConnectivity);

        virtual HRESULT STDMETHODCALLTYPE NetworkPropertyChanged(
            __in    GUID                        NetworkId,
            __in    NLM_NETWORK_PROPERTY_CHANGE Flags);

        virtual ULONG STDMETHODCALLTYPE AddRef();

        virtual ULONG STDMETHODCALLTYPE Release();

        virtual HRESULT STDMETHODCALLTYPE QueryInterface(
            __in    REFIID  riid,
            __out   void    **ppvObject);
    };

    class CNetworkConnectionEvents :
        virtual public CEventsBase,
        virtual public CAttachableObject,
        virtual public INetworkConnectionEvents
    {
    protected:
        virtual REFIID InternalGetConnectionPointRIID();

    public:
        CNetworkConnectionEvents(
            __in_opt    LPVOID  Owner = nullptr);
        virtual ~CNetworkConnectionEvents();

        virtual HRESULT STDMETHODCALLTYPE NetworkConnectionConnectivityChanged(
            __in    GUID                ConnectionId,
            __in    NLM_CONNECTIVITY    NewConnectivity);

        virtual HRESULT STDMETHODCALLTYPE NetworkConnectionPropertyChanged(
            __in    GUID                            ConnectionId,
            __in    NLM_CONNECTION_PROPERTY_CHANGE  Flags);

        virtual HRESULT STDMETHODCALLTYPE QueryInterface(
            __in    REFIID  riid,
            __out   void    **ppvObject);

        virtual ULONG STDMETHODCALLTYPE AddRef();

        virtual ULONG STDMETHODCALLTYPE Release();
    };

    class CNetListManagerEvents :
        virtual public CEventsBase,
        virtual public CAttachableObject,
        virtual public INetworkListManagerEvents
    {
    protected:
        virtual REFIID InternalGetConnectionPointRIID();

    public:
        CNetListManagerEvents(
            __in_opt    LPVOID  Owner = nullptr);

        virtual ~CNetListManagerEvents();

        HRESULT STDMETHODCALLTYPE ConnectivityChanged(
            __in    NLM_CONNECTIVITY    NewConnectivity);

        virtual ULONG STDMETHODCALLTYPE AddRef();

        virtual ULONG STDMETHODCALLTYPE Release();

        virtual HRESULT STDMETHODCALLTYPE QueryInterface(
            __in    REFIID  riid,
            __out   void    **ppvObject);
    };

    class CNetEventsManager :
        virtual public CCSObject,
        virtual public CThread
    {
    public:

        typedef void(__stdcall *LPON_CONNECTIVITY_CHANGE)(
            __in    const   CNetEventsManager   &Manager,
            __in    const   NLM_CONNECTIVITY    NewConnectivity);

        typedef void(__stdcall *LPON_NET_ENTITY_ADD_REMOVE)(
            __in    const   CNetEventsManager   &Manager,
            __in    const   GUID                &EntityId);

        typedef void(__stdcall *LPON_NET_ENTITY_CONNECTIVITY_CHANGE)(
            __in    const   CNetEventsManager   &Manager,
            __in    const   GUID                &EntityId,
            __in    const   NLM_CONNECTIVITY    NewConnectivity);

        typedef void(__stdcall *LPON_NET_ENTITY_PROPERTY_CHANGE)(
            __in    const   CNetEventsManager   &Manager,
            __in    const   GUID                &EntityId,
            __in    const   DWORD               Flags);

    protected:
        typedef union _EVENT_CALLBACK
        {
            LPON_NET_ENTITY_ADD_REMOVE          OnNetworkAdd;
            LPON_NET_ENTITY_ADD_REMOVE          OnNetworkRemove;
            LPON_NET_ENTITY_ADD_REMOVE          OnNetworkConnectionAdd;
            LPON_NET_ENTITY_ADD_REMOVE          OnNetworkConnectionRemove;
            LPON_NET_ENTITY_CONNECTIVITY_CHANGE OnNetworkConnectivityChange;
            LPON_NET_ENTITY_CONNECTIVITY_CHANGE OnNetworkConnectionConnectivityChange;
            LPON_NET_ENTITY_PROPERTY_CHANGE     OnNetworkPropertyChange;
            LPON_NET_ENTITY_PROPERTY_CHANGE     OnNetworkConnectionPropertyChange;
            LPON_CONNECTIVITY_CHANGE            OnConnectivityChange;
            LPVOID                              Untyped;
        } EVENT_CALLBACK, *PEVENT_CALLBACK, *LPEVENT_CALLBACK;

    private:
        std::unordered_map<EVENT_TYPE, EVENT_CALLBACK>  FCallbacks;

        INetworkListManager                 *FNetworkListManager = nullptr;
        IConnectionPointContainer           *FConnectionPointContainer = nullptr;

        CNetListManagerEvents               *FNetListManagerEvents = nullptr;
        CNetworkEvents                      *FNetworkEvents = nullptr;
        CNetworkConnectionEvents            *FNetworkConnectionEvents = nullptr;

    protected:
        virtual void ThreadRoutine();

        virtual BOOL InternalInitialize();
        virtual void InternalFinalize();

        virtual void InvokeClientCallback(
            __in    const   EVENT_TYPE          EventType,
            __in    const   GUID                &Id,
            __in    const   NLM_CONNECTIVITY    Connectivity,
            __in    const   DWORD               Flags) const;

        virtual EVENT_CALLBACK GetClientCallbackByType(
            __in    const   EVENT_TYPE  EventType) const;

        virtual void SetClientCallbackByType(
            __in    const   EVENT_TYPE      EventType,
            __in    const   EVENT_CALLBACK  &Callback);

    public:
        CNetEventsManager(
            __in_opt    LPVOID  Owner = nullptr);

        virtual ~CNetEventsManager();

        virtual LPON_NET_ENTITY_ADD_REMOVE GetOnNetworkAdd() const;
        virtual void SetOnNetworkAdd(
            __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value);

        virtual LPON_NET_ENTITY_ADD_REMOVE GetOnNetworkRemove() const;
        virtual void SetOnNetworkRemove(
            __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value);

        virtual LPON_NET_ENTITY_ADD_REMOVE GetOnNetworkConnectionAdd() const;
        virtual void SetOnNetworkConnectionAdd(
            __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value);

        virtual LPON_NET_ENTITY_ADD_REMOVE GetOnNetworkConnectionRemove() const;
        virtual void SetOnNetworkConnectionRemove(
            __in    const   LPON_NET_ENTITY_ADD_REMOVE  Value);

        virtual LPON_NET_ENTITY_CONNECTIVITY_CHANGE GetOnNetworkConnectivityChange() const;
        virtual void SetOnNetworkConnectivityChange(
            __in    const   LPON_NET_ENTITY_CONNECTIVITY_CHANGE Value);

        virtual LPON_NET_ENTITY_CONNECTIVITY_CHANGE GetOnNetworkConnectionConnectivityChange() const;
        virtual void SetOnNetworkConnectionConnectivityChange(
            __in    const   LPON_NET_ENTITY_CONNECTIVITY_CHANGE Value);

        virtual LPON_NET_ENTITY_PROPERTY_CHANGE GetOnNetworkPropertyChange() const;
        virtual void SetOnNetworkPropertyChange(
            __in    const   LPON_NET_ENTITY_PROPERTY_CHANGE Value);

        virtual LPON_NET_ENTITY_PROPERTY_CHANGE GetOnNetworkConnectionPropertyChange() const;
        virtual void SetOnNetworkConnectionPropertyChange(
            __in    const   LPON_NET_ENTITY_PROPERTY_CHANGE Value);

        virtual LPON_CONNECTIVITY_CHANGE GetOnConnectivityChange() const;
        virtual void SetOnConnectivityChange(
            __in    const   LPON_CONNECTIVITY_CHANGE    Value);

        CLASS_PROPERTY(LPON_NET_ENTITY_ADD_REMOVE, OnNetworkAdd);
        CLASS_PROPERTY(LPON_NET_ENTITY_ADD_REMOVE, OnNetworkRemove);

        CLASS_PROPERTY(LPON_NET_ENTITY_ADD_REMOVE, OnNetworkConnectionAdd);
        CLASS_PROPERTY(LPON_NET_ENTITY_ADD_REMOVE, OnNetworkConnectionRemove);

        CLASS_PROPERTY(LPON_NET_ENTITY_CONNECTIVITY_CHANGE, OnNetworkConnectivityChange);
        CLASS_PROPERTY(LPON_NET_ENTITY_CONNECTIVITY_CHANGE, OnNetworkConnectionConnectivityChange);

        CLASS_PROPERTY(LPON_NET_ENTITY_PROPERTY_CHANGE, OnNetworkPropertyChange);
        CLASS_PROPERTY(LPON_NET_ENTITY_PROPERTY_CHANGE, OnNetworkConnectionPropertyChange);

        CLASS_PROPERTY(LPON_CONNECTIVITY_CHANGE, OnConnectivityChange);
    };
};