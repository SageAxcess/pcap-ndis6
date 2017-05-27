@echo off
echo WinPCAP NDIS6.0 driver installer
echo    architecture = %PROCESSOR_ARCHITECTURE% 
echo    system dir = %SystemRoot%
echo Copying wpcap.dll
if %PROCESSOR_ARCHITECTURE%  == x86 goto x86
:x64
copy /y x64\packet-ndis6.dll %SystemRoot%\system32
copy /y x64\wpcap.dll %SystemRoot%\system32
copy /y x86\packet-ndis6.dll %SystemRoot%\SysWOW64
copy /y x86\wpcap.dll %SystemRoot%\SysWOW64

echo Installing drivers
copy /y x64\pcap-ndis6.* %SystemRoot%\system32
x64\dpinst.exe /q /f /PATH x64\

goto exit
:x86
copy /y x86\packet-ndis6.dll %SystemRoot%\system32
copy /y x86\wpcap.dll %SystemRoot%\system32

echo Installing drivers
copy /y x86\pcap-ndis6.* %SystemRoot%\system32
x86\dpinst.exe /q /f /PATH x86\

goto exit
:exit
echo Finished
