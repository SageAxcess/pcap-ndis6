@echo off

@setlocal

rem
rem Variables declaration
rem

set cmd_path=%~dp0
set SYSWOW64=%WinDir%\SysWOW64
set SYSTEM32=%WinDir%\System32
set DRIVERS=%WinDir%\System32\Drivers
set OS_TYPE=unknown

for /f "tokens=2*" %%a in ('reg query "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE') do (
    set CPU_TYPE=%%b
)

if %CPU_TYPE%==x86 (
	if DEFINED PROCESSOR_ARCHITEW6432 (
		set OS_TYPE=x86
		set CPU_TYPE=AMD64
	)
) else (
	set OS_TYPE=AMD64
)

if %OS_TYPE%==x86 (
	if %CPU_TYPE%==AMD64 (
		set SYSTEM32=%WinDir%\SysNative
		set DRIVERS=%WinDir%%\SysNative\Drivers
	)
)

rem
rem Info block
rem

echo AEGIS PCAP NDIS 6.x driver updater
echo    System directory:  %SystemRoot%
echo    Current directory: %cd%
echo    Script directory:  %cmd_path%
echo    CPU_TYPE:          %CPU_TYPE%
echo    OS_TYPE:           %OS_TYPE%

sc query pcapndis6 > NUL
if ERRORLEVEL 1 (
	echo No driver installed, cannot update.
	goto exit
)

sc stop aegis
if ERRORLEVEL 1 (
	echo Failed to stop aegis service, cannot update.
	goto exit
) else (
	echo AEGIS service stopped.
)
taskkill /F /IM aegis.exe /T

sc stop pcapndis6
if ERRORLEVEL 1 (
	echo Failed to stop pcapndis6 service, cannot update.
	goto exit
) else (
	echo PCAPNDIS6 service stopped.
)

pushd %cmd_path%

	if NOT %OS_TYPE% == x86 (
		copy /y x64\packet-ndis6.dll "%SYSTEM32%\*.*" > NUL
		if ERRORLEVEL 1 (
			echo Failed to copy 64-bit packet-ndis6.dll into %SYSTEM32% folder.			
		)

		copy /y x64\pcap-ndis6.sys "%DRIVERS%\*.*" > NUL
		if ERRORLEVEL 1 (
			echo Failed to copy 64-bit pcap-ndis6.sys into %DRIVERS% folder.			
		)

		copy /Y x64\wpcap.dll "%SYSTEM32%\*.*" > NUL
		if ERRORLEVEL 1 (
			echo Failed to copy 64-bit wpcap.dll into %SYSTEM32% folder.			
		)


		copy /y x86\packet-ndis6.dll "%SYSWOW64%\*.*" > NUL
		if ERRORLEVEL 1 (
			echo Failed to copy 32-bit packet-ndis6.dll into %SYSWOW64% folder.			
		)

		copy /y x86\wpcap.dll "%SYSWOW64%\*.*" > NUL
		if ERRORLEVEL 1 (
			echo Failed to copy 32-bit wpcap.dll into %SYSWOW64% folder.			
		)

	) else (
		copy /y x86\pcap-ndis6.sys "%DRIVERS%\*.*" > NUL
		if ERRORLEVEL 1 (
			echo Failed to copy 32-bit pcap-ndis6.sys into %DRIVERS% folder.			
		)

		copy /y x86\packet-ndis6.dll "%SYSTEM32%\*.*" > NUL
		if ERRORLEVEL 1 (
			echo Failed to copy 32-bit packet-ndis6.dll into %SYSTEM32% folder.			
		)

		copy /y x86\wpcap.dll "%SYSTEM32%\*.*" > NUL		
		if ERRORLEVEL 1 (
			echo Failed to copy 32-bit wpcap.dll into %SYSTEM32% folder.			
		)
	)

popd

sc start pcapndis6
if ERRORLEVEL 1 (
	echo Failed to start pcapndis6 service.
)

sc start aegis
if ERRORLEVEL 1 (
	echo Failed to start aegis service.
)
		
:exit           
popd