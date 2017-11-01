// DriverInstaller.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <Mshtmhst.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <iphlpapi.h>
#include <Natupnp.h>
#include <devguid.h>
#include <regstr.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <objbase.h>
#include <Setupapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#include "netcfgn.h"

bool InstallNdisProtocolDriver(char *inf_path, UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	// Validate arguments
	if (inf_path == NULL)
	{
		return false;
	}
	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		printf("[DEBUG] Created InetCfg\n");
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			printf("[DEBUG] Created InetCfgLock\n");
			LPWSTR locked_by;

			hr = pLock->AcquireWriteLock(lock_timeout, L"SoftEther VPN", &locked_by);

			if (SUCCEEDED(hr))
			{
				printf("[DEBUG] Acquired InetCfgLock\n");
				hr = pNetCfg->Initialize(NULL);

				if (SUCCEEDED(hr))
				{
					char inf_dir[MAX_PATH];
					strcpy_s(inf_dir, MAX_PATH, inf_path);
					char* next = strchr(inf_dir, '\\');
					while(next)
					{
						char* tmp = strchr(next + 1, '\\');
						if(!tmp)
						{
							next[0] = 0;
							break;
						}
						next = tmp;
					}

					printf("[DEBUG] setup inf at %s\n", inf_dir);

					if (SetupCopyOEMInfA(inf_path, inf_dir, SPOST_PATH, 0, NULL, 0, NULL, 0))
					{
						printf("[DEBUG] installed .inf\n");
						INetCfgClassSetup *pSetup;

						hr = pNetCfg->QueryNetCfgClass(&GUID_DEVCLASS_NETSERVICE, IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr))
						{
							printf("[DEBUG] Applying to interface\n");

							OBO_TOKEN token;
							INetCfgComponent *pComponent;

							ZeroMemory(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = pSetup->Install(L"PcapNdis6", &token, 0, 0, NULL, NULL, &pComponent);

							if (SUCCEEDED(hr))
							{
								printf("[DEBUG] Success\n");
								pNetCfg->Apply();

								ret = true;
							} else
							{
								printf("[DEBUG] Install returned 0x%x\n", hr);
							}

							pSetup->Release();
						}

						if (ret == false)
						{
							char dst_inf_name[MAX_PATH];
							DWORD dst_inf_name_size = MAX_PATH;

							if (SetupCopyOEMInfA(inf_path, inf_dir, SPOST_PATH, SP_COPY_REPLACEONLY,
								dst_inf_name, dst_inf_name_size, &dst_inf_name_size, NULL) == false &&
								GetLastError() == ERROR_FILE_EXISTS)
							{
								SetupUninstallOEMInfA(dst_inf_name, 0, NULL);
							}
						}
					} else
					{
						printf("[ERROR] Error in SetupCopyOEMInf: %d\n", GetLastError());
					}
				}

				pLock->ReleaseWriteLock();
			}

			pLock->Release();
		}

		pNetCfg->Release();
	}

	return ret;
}

bool UninstallNdisProtocolDriver(UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	// Validate arguments
	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by;

			hr = pLock->AcquireWriteLock(lock_timeout, L"SoftEther VPN", &locked_by);

			if (SUCCEEDED(hr))
			{
				hr = pNetCfg->Initialize(NULL);

				if (SUCCEEDED(hr))
				{
					INetCfgComponent *pComponent = NULL;
					hr = pNetCfg->FindComponent(L"PcapNdis6", &pComponent);

					if (SUCCEEDED(hr) && pComponent)
					{
						INetCfgClassSetup *pSetup;

						hr = pNetCfg->QueryNetCfgClass(&GUID_DEVCLASS_NETSERVICE, IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr))
						{
							OBO_TOKEN token;

							ZeroMemory(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = pSetup->DeInstall(pComponent, &token, NULL);

							if (SUCCEEDED(hr))
							{
								pNetCfg->Apply();

								ret = true;
							}

							pSetup->Release();
						}
					}
				}

				pLock->ReleaseWriteLock();
			}

			pLock->Release();
		}

		pNetCfg->Release();
	}

	return ret;
}


int main(int argc, char** argv)
{
	if(argc>1)
	{
		CoInitialize(NULL);

		if(!strcmp(argv[1], "/install"))
		{
			HMODULE hModule = GetModuleHandle(NULL);
			char path[MAX_PATH];
			GetModuleFileName(hModule, path, MAX_PATH);
			char* last = strchr(path, '\\');
			while(last)
			{
				char* temp = strchr(last + 1, '\\');
				if(!temp)
				{
					last[1] = 0;
					break;
				}

				last = temp;
			}
			strcat_s(path, MAX_PATH, "pcap-ndis6.inf");

			printf("[DEBUG] Installing .inf at %s\n", path);

			InstallNdisProtocolDriver(path, 60 * 1000);
		} else if (!strcmp(argv[1], "/uninstall"))
		{
			UninstallNdisProtocolDriver(60 * 1000);
		}

		CoUninitialize();
	}

    return 0;
}

