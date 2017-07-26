@echo off
echo WinPCAP NDIS6.0 driver installer
echo    architecture = %PROCESSOR_ARCHITECTURE% 
echo    system dir = %SystemRoot%

if %PROCESSOR_ARCHITECTURE%  == x86 goto x86
:x64
echo Uninstalling drivers
x64\DriverInstaller.exe /uninstall

echo Removing files

copy /y x64\packet-ndis6.dll %SystemRoot%\system32
copy /y x64\wpcap.dll %SystemRoot%\system32
copy /y x86\packet-ndis6.dll %SystemRoot%\SysWOW64
copy /y x86\wpcap.dll %SystemRoot%\SysWOW64


copy /y x64\pcap-ndis6.* %SystemRoot%\system32

goto exit
:x86
echo Uninstalling drivers
x64\DriverInstaller.exe /uninstall

goto exit
:exit
echo Finished
