@echo off
echo WinPCAP NDIS6.0 driver installer
echo    architecture = %PROCESSOR_ARCHITECTURE% 
echo    system dir = %SystemRoot%

echo Removing files

del /f /q %SystemRoot%\system32\packet-ndis6.dll
del /f /q %SystemRoot%\system32\wpcap.dll
del /f /q %SystemRoot%\SysWOW64\packet-ndis6.dll
del /f /q %SystemRoot%\SysWOW64\wpcap.dll

if %PROCESSOR_ARCHITECTURE%  == x86 goto x86
:x64
echo Uninstalling drivers
x64\DriverInstaller.exe /uninstall

goto exit

:x86
echo Uninstalling drivers
x64\DriverInstaller.exe /uninstall

goto exit
:exit
echo Finished
