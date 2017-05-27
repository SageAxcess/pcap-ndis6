@echo off
set path=%path%;"C:\Program Files (x86)\WiX toolset v3.9\bin\"
del *.wixobj
del Output\*.wixpdb

candle -ext WixUtilExtension AegisPcap.wxs
light -ext WixUIExtension -ext WixUtilExtension -ext WixNetFxExtension -cultures:en-us AegisPcap.wixobj -out Output/aegis-pcap-1.0.1.msi

del *.wixobj
del Output\*.wixpdb

rem "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Bin\signtool.exe" sign /f "..\cert\codesign.pfx" /t http://timestamp.comodoca.com/authenticode /v -p "SageAxccess#1" Output/aegis-pcap-1.0.2.msi
