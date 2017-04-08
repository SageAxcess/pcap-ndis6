set Path=%PATH%;"C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\"
makecert -r -pe -n "CN=ChangeDynamix LLC" -sr localmachine -a sha1 -cy authority -sky signature -sv changedynamix.ca.pvk changedynamix.ca.cer 
makecert -pe -n CN="WinPCAP NDIS 6.x Filter Driver" -a sha1 -sky signature -eku 1.3.6.1.5.5.7.3.3 -ic changedynamix.ca.cer -iv changedynamix.ca.pvk -sv pcap-ndis6.pvk pcap-ndis6.cer 
pvk2pfx -pvk pcap-ndis6.pvk -spc pcap-ndis6.cer -pfx pcap-ndis6.pfx 