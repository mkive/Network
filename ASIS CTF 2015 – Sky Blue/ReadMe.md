# ASIS Quals CTF 2015: Sky Blue

**Category:** Forensic
**Points:** 100
**Solves:** 120
**Description:**


## Write-up

This writeup is based on these writeups:

* <http://www.thice.nl/asis-ctf-2015-write-ups/>
* <https://xmgv.wordpress.com/2015/05/11/asis-ctf-quals-2015-broken-heart/>
* <https://github.com/naijim/blog/blob/master/writeups/asis-quals-ctf-2015_broken_heart_writeup.md>

We are given a pcap-ng capture file:

```bash
$ file myheart_7cb6daec0c45b566b9584f98642a7123 
myheart_7cb6daec0c45b566b9584f98642a7123: XZ compressed data, checksum CRC64
$ mv myheart_7cb6daec0c45b566b9584f98642a7123 myheart_7cb6daec0c45b566b9584f98642a7123.xz 
$ ls
myheart_7cb6daec0c45b566b9584f98642a7123.xz
$ unxz myheart_7cb6daec0c45b566b9584f98642a7123.xz
$ file myheart_7cb6daec0c45b566b9584f98642a7123
myheart_7cb6daec0c45b566b9584f98642a7123: pcap-ng capture file - version 1.0
```
