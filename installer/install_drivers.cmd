@echo off
SET mypath=%~dp0
cd %mypath:~0,-1%

for /f "tokens=2*" %%a in ('reg query "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE') do set "PROCESSOR_ARCHITECTURE=%%b"

echo WinPCAP NDIS6.0 driver installer
echo    architecture = %PROCESSOR_ARCHITECTURE% 
echo    system dir = %SystemRoot%
echo    current dir = %mypath:~0,-1%
echo Copying wpcap.dll

if %PROCESSOR_ARCHITECTURE%  == x86 goto x86
:x64
copy /y x64\packet-ndis6.dll %SystemRoot%\system32
copy /y x64\wpcap.dll %SystemRoot%\system32
copy /y x86\packet-ndis6.dll %SystemRoot%\SysWOW64
copy /y x86\wpcap.dll %SystemRoot%\SysWOW64

echo Installing drivers
copy /y x64\pcap-ndis6.* %SystemRoot%\system32
x64\DriverInstaller.exe /install

goto exit
:x86
copy /y x86\packet-ndis6.dll %SystemRoot%\system32
copy /y x86\wpcap.dll %SystemRoot%\system32

echo Installing drivers
copy /y x86\pcap-ndis6.* %SystemRoot%\system32
x86\DriverInstaller.exe /install

goto exit
:exit
net stop aegis
net stop pcapndis6
net start pcapndis6
net start aegis

echo Finished
