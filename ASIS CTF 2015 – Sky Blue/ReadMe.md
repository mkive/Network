# ASIS Quals CTF 2015: Sky Blue

**Category:** Forensic
**Points:** 100
**Solves:** 120
**Description:**


## Write-up

This writeup is based on these writeups:

* <http://www.thice.nl/asis-ctf-2015-write-ups/>


We are given a pcap-ng capture file:

```bash
$ binwalk blue.pcap 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
40535         0x9E57          PNG image, 1400 x 74, 8-bit colormap, non-interlaced

```

In Find Packets (Ctrl + F), search for png in packet bytes.
(Find: String, Filter: png, Search In: Packet Bytes, Character Width: Narrow & Wide)

![image](https://github.com/mkive/Network/assets/4083018/3b4bd1b5-f386-424a-883b-54363d9a3605)

If we look at the header of packet 283 as shown above, we can see that it starts with [02 0c 20].

Similarly, if we analyze the data with the header of [02 0c 20] after packet 283 by searching for the hex value, we can see a total of 6 packets. Find additional packets (288, 293, 298, 303, 308, 308, 313).

[02 0C 20 FC 03 F8 03 47 00 63 EF E6 07]

![image](https://github.com/mkive/Network/assets/4083018/6c4ce373-9902-4561-8e21-f3aa8429da29)



Wireshark's [File] - [Export Selected Packet Bytes] function allows you to extract the bytes data of a packet.

The shortcut is [Ctrl + Shift + x].


![image](https://github.com/mkive/Network/assets/4083018/ab28a702-f3e4-4a55-a59e-8dc54da0b140)

If we extract packets 288, 293, 298, 303, 308, 308, and 313 and combine them in order, we get the hidden png file.

We extracted packet 283 as 1.bin, packet 288 as 2.bin, and so on until packet 313 as 7.bin.

![image](https://github.com/mkive/Network/assets/4083018/f58a166f-fba1-48a7-8306-1c3a439c7a55)
[Remove the hex value [02 0C 20 FC 03 F8 03 47 00 63 EF E6 07]]


![image](https://github.com/mkive/Network/assets/4083018/c7f1e4f6-9e9b-4703-b7fe-b1a611366c1a)
[Remove hex value [0E]]

Before assembling files 1.bin through 7.bin with the Hex Editor

Remove the header 13 bytes of the .bin file (02 0C 20 FC 03 F8 03 47 00 63 EF E6 07) and the last 1 byte of the file (0E).

![image](https://github.com/mkive/Network/assets/4083018/02d207dc-c8e5-460b-b6b3-6e83afddda54)


In HxD's [Extra] - [File tools] menu, there is a [Concatenate] function to combine files. 
With this function, we can combine files 1.bin through 7.bin in order to get the out.png file.

![image](https://github.com/mkive/Network/assets/4083018/ce5b0a64-f37b-4ef8-8c6c-09fe82bb28e6)

I extracted the result.png file, but the png file does not open.

The reason is that there is unnecessary data before the png file signature, as shown below.

So, remove the unnecessary data and try to open the file again.

![image](https://github.com/mkive/Network/assets/4083018/99684c90-80c4-4387-affd-a70ae760d2b8)

ASIS{ee9aa3fa92bff0778ab7df7e90a9b6ba}
