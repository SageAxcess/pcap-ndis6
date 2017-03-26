@echo off
set PCAP_VERSION=1.8.1
set ZIP="C:\Program Files (x86)\7-Zip\7z.exe"
set CURL="apps\curl.exe"

Echo Downloading libpcap v %PCAP_VERSION%
%CURL% -OL http://www.tcpdump.org/release/libpcap-%PCAP_VERSION%.tar.gz
Echo Extracting archive...
%ZIP% x libpcap-%PCAP_VERSION%.tar.gz
del /S /Q libpcap-%PCAP_VERSION%.tar.gz
%ZIP% x libpcap-%PCAP_VERSION%.tar
del /S /Q libpcap-%PCAP_VERSION%.tar
