## Save packets

1. Install `ip_pdcp.lua` plugin in your wireshark to decode packets and add following entities in DLT_USER.
```
DLT=161, Payload Protocol=ip_pdcp
DLT=162, Payload Protocol=ip 
```
2. Make some modifications in either `enb.conf` or `ue.conf` to enable the PDCP packets saving functionality.
3. Run as it as normal srsRAN.