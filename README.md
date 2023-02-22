# zigbee-ota-extractor

Tool to extract Zigbee OTA files from Wireshark packet captures

## Prerequisites

A Zigbee sniffer is required to get the packet capture.
Follow [this guide](https://www.zigbee2mqtt.io/advanced/zigbee/04_sniff_zigbee_traffic.html) to get started.  
**If your device needs an install code, you'll have to derive a link key using AES-MMO first.**

This tool requires an installed [.NET 7 Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/7.0/runtime).

## Usage

* Open your packet capture in Wireshark
* Set `zbee_aps.cluster == 0x0019` as a filter to only show relevant packets
* Go to `File > Export Packet Dissections > As JSON...` and save the file
* Use `./zigbee-ota-extractor <filename>` to extract the OTA file

Due to packet loss, more than one packet capture might be required. You can load multiple captures at once
by specifying multiple filenames for zigbee-ota-extractor.