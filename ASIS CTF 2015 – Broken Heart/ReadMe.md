# ASIS Quals CTF 2015: Broken Heart

**Category:** Forensic
**Points:** 100
**Solves:** 120
**Description:**



## Write-up

This writeup is based on these writeups:

* <https://securitymax.tistory.com/84>
* <http://www.thice.nl/asis-ctf-2015-write-ups/>
* <https://xmgv.wordpress.com/2015/05/11/asis-ctf-quals-2015-broken-heart/>
* <https://github.com/naijim/blog/blob/master/writeups/asis-quals-ctf-2015_broken_heart_writeup.md>
* <https://github.com/ctfs/write-ups-2015/tree/master/asis-quals-ctf-2015/forensic/broken-heart>

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

![image](https://github.com/mkive/Network/assets/4083018/9b4aee01-4fe0-4200-a4ec-49af8439552b)

![image](https://github.com/mkive/Network/assets/4083018/5f60f12f-d014-4be7-b589-c202f51266fd)


![image](https://github.com/mkive/Network/assets/4083018/997087b2-be39-45d3-8515-73c580c0c41c)
The 11th packet shows a request for the LoiRLUoq file.

Click on the packet and select [Right-click]-[Follow TCP Stream] to analyze the header information.

![image](https://github.com/mkive/Network/assets/4083018/6e107b0c-8f3b-415a-8bdf-cf5a46e9f0a3)

* If you look at TCP Stream 0, the client requests the LoiRLUoq file from the server via GET and checks the server's response, the HTTP status code is 206 - Partial Content. 
This code is used when only part of the requested file is sent. 
* When you request a file, it doesn't send all the data at once, it sends it in bits and pieces (fragmentation), and when you carve it, it will be the file you requested.
* A Content-Range entry is present in the header, which indicates the offset range of the requested file. 
Since the fragmented files are requested randomly and not sequentially starting from the first part of the file, the files must be sorted sequentially by offset range before being combined.


Looking at the type of network protocols used in the transmission, we see a bunch of mostly TCP, DNS and HTTP Requests:

```bash
$ tshark -r myheart_7cb6daec0c45b566b9584f98642a7123 | awk '{print $6}' | sort | uniq -c | sort -n
   1 BROWSER
   2 ARP
   7 DHCPv6
  30 HTTP
  92 DNS
3044 TCP
```

Looking at the HTTP requests, we see that a file named `LoiRLUoq` was requested and transmitted in several parts:

```bash
$ tshark -r myheart_7cb6daec0c45b566b9584f98642a7123 'http'
11   0.655025 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
  179   1.655050 87.107.124.13 → 192.168.221.128 HTTP 2237 HTTP/1.1 206 Partial Content 
  192  11.678949 192.168.221.128 → 87.107.124.13 HTTP 225 GET /LoiRLUoq HTTP/1.1 
  334  12.562657 87.107.124.13 → 192.168.221.128 HTTP 1456 HTTP/1.1 206 Partial Content 
  347  19.507011 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
  470  20.518929 87.107.124.13 → 192.168.221.128 HTTP 985 HTTP/1.1 206 Partial Content 
  483  29.239604 192.168.221.128 → 87.107.124.13 HTTP 224 GET /LoiRLUoq HTTP/1.1 
  598  30.268093 87.107.124.13 → 192.168.221.128 HTTP 735 HTTP/1.1 206 Partial Content 
  611  36.167157 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
  780  36.986171 87.107.124.13 → 192.168.221.128 HTTP 98 HTTP/1.1 206 Partial Content 
  793  42.957339 192.168.221.128 → 87.107.124.13 HTTP 224 GET /LoiRLUoq HTTP/1.1 
  933  43.922965 87.107.124.13 → 192.168.221.128 HTTP 629 HTTP/1.1 206 Partial Content 
  946  49.541252 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 1117  50.306791 87.107.124.13 → 192.168.221.128 HTTP 825 HTTP/1.1 206 Partial Content 
 1130  55.682324 192.168.221.128 → 87.107.124.13 HTTP 224 GET /LoiRLUoq HTTP/1.1 
 1312  56.627293 87.107.124.13 → 192.168.221.128 HTTP 1546 HTTP/1.1 206 Partial Content 
 1325  62.346365 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 1452  63.168656 87.107.124.13 → 192.168.221.128 HTTP 461 HTTP/1.1 206 Partial Content 
 1465  69.696295 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 1511  70.040975 87.107.124.13 → 192.168.221.128 HTTP 1221 HTTP/1.1 206 Partial Content 
 1526  75.593022 192.168.221.128 → 87.107.124.13 HTTP 220 GET /LoiRLUoq HTTP/1.1 
 1651  76.783922 87.107.124.13 → 192.168.221.128 HTTP 60 HTTP/1.1 206 Partial Content 
 1665  81.596474 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 1852  82.806389 87.107.124.13 → 192.168.221.128 HTTP 62 HTTP/1.1 206 Partial Content 
 1865  87.618379 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 1947  88.079126 87.107.124.13 → 192.168.221.128 HTTP 20482 HTTP/1.1 206 Partial Content 
 1961  94.205023 192.168.221.128 → 87.107.124.13 HTTP 224 GET /LoiRLUoq HTTP/1.1 
 1995  94.490163 87.107.124.13 → 192.168.221.128 HTTP 10407 HTTP/1.1 206 Partial Content 
 2008 101.674182 192.168.221.128 → 87.107.124.13 HTTP 225 GET /LoiRLUoq HTTP/1.1 
 2116 102.370022 87.107.124.13 → 192.168.221.128 HTTP 2169 HTTP/1.1 206 Partial Content 
 2130 107.310297 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 2167 107.654456 87.107.124.13 → 192.168.221.128 HTTP 755 HTTP/1.1 206 Partial Content 
 2180 113.800224 192.168.221.128 → 87.107.124.13 HTTP 224 GET /LoiRLUoq HTTP/1.1 
 2346 115.092001 87.107.124.13 → 192.168.221.128 HTTP 4150 HTTP/1.1 206 Partial Content 
 2359 122.806044 192.168.221.128 → 87.107.124.13 HTTP 223 GET /LoiRLUoq HTTP/1.1 
 2454 123.310921 87.107.124.13 → 192.168.221.128 HTTP 3034 HTTP/1.1 206 Partial Content 
 2467 128.683312 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 2636 129.480471 87.107.124.13 → 192.168.221.128 HTTP 1551 HTTP/1.1 206 Partial Content 
 2649 135.116803 192.168.221.128 → 87.107.124.13 HTTP 225 GET /LoiRLUoq HTTP/1.1 
 2768 135.711354 87.107.124.13 → 192.168.221.128 HTTP 1960 HTTP/1.1 206 Partial Content 
 2782 141.244285 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 2877 141.868416 87.107.124.13 → 192.168.221.128 HTTP 19741 HTTP/1.1 206 Partial Content 
 2890 148.045887 192.168.221.128 → 87.107.124.13 HTTP 224 GET /LoiRLUoq HTTP/1.1 
 3047 148.748141 87.107.124.13 → 192.168.221.128 HTTP 1311 HTTP/1.1 206 Partial Content 
 3060 153.672244 192.168.221.128 → 87.107.124.13 HTTP 226 GET /LoiRLUoq HTTP/1.1 
 3171 154.569892 87.107.124.13 → 192.168.221.128 HTTP 1522 HTTP/1.1 206 Partial Content 
```

From the `tshark` examination, it seems like the parts were transmitted from the ip `87.107.124.13` to `192.168.221.128`.

We can extract these parts using `tcpflow`:

```bash
# by Ubuntu
sudo apt install tcpflow    
sudo apt install tcpflow-nox
```

```bash
$ tcpflow -r myheart_7cb6daec0c45b566b9584f98642a7123.pcap
reportfilename: ./report.xml
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
tcpflow: TCP PROTOCOL VIOLATION: SYN with data! (length=2)
$ ls -1
087.107.124.013.00080-192.168.221.128.54391
087.107.124.013.00080-192.168.221.128.54392
087.107.124.013.00080-192.168.221.128.54393
087.107.124.013.00080-192.168.221.128.54394
087.107.124.013.00080-192.168.221.128.54397
087.107.124.013.00080-192.168.221.128.54398
087.107.124.013.00080-192.168.221.128.54399
087.107.124.013.00080-192.168.221.128.54400
087.107.124.013.00080-192.168.221.128.54401
087.107.124.013.00080-192.168.221.128.54402
087.107.124.013.00080-192.168.221.128.54403
087.107.124.013.00080-192.168.221.128.54404
087.107.124.013.00080-192.168.221.128.54405
087.107.124.013.00080-192.168.221.128.54406
087.107.124.013.00080-192.168.221.128.54407
087.107.124.013.00080-192.168.221.128.54408
087.107.124.013.00080-192.168.221.128.54409
087.107.124.013.00080-192.168.221.128.54410
087.107.124.013.00080-192.168.221.128.54411
087.107.124.013.00080-192.168.221.128.54412
087.107.124.013.00080-192.168.221.128.54413
087.107.124.013.00080-192.168.221.128.54414
087.107.124.013.00080-192.168.221.128.54415
192.168.221.128.54391-087.107.124.013.00080
192.168.221.128.54392-087.107.124.013.00080
192.168.221.128.54393-087.107.124.013.00080
192.168.221.128.54394-087.107.124.013.00080
192.168.221.128.54397-087.107.124.013.00080
192.168.221.128.54398-087.107.124.013.00080
192.168.221.128.54399-087.107.124.013.00080
192.168.221.128.54400-087.107.124.013.00080
192.168.221.128.54401-087.107.124.013.00080
192.168.221.128.54402-087.107.124.013.00080
192.168.221.128.54403-087.107.124.013.00080
192.168.221.128.54404-087.107.124.013.00080
192.168.221.128.54405-087.107.124.013.00080
192.168.221.128.54406-087.107.124.013.00080
192.168.221.128.54407-087.107.124.013.00080
192.168.221.128.54408-087.107.124.013.00080
192.168.221.128.54409-087.107.124.013.00080
192.168.221.128.54410-087.107.124.013.00080
192.168.221.128.54411-087.107.124.013.00080
192.168.221.128.54412-087.107.124.013.00080
192.168.221.128.54413-087.107.124.013.00080
192.168.221.128.54414-087.107.124.013.00080
192.168.221.128.54415-087.107.124.013.00080
myheart_7cb6daec0c45b566b9584f98642a7123.pcap
report.xml

```

Since we only need data transmitted from `87.107.124.13` to `192.168.221.128`, we only care about the files beginning with `087.107.124.013`.

Content-Range는 각 HTTP Response 의 필드를보고 전송 된 파일의 크기와 전송 된 범위를 확인

We look at the `Content-Range` field of each HTTP Response to see how big the transmitted file is and which ranges have been submitted:

```bash
$ for i in 087.107.124.013.00080-192.168.221.128.54*; do strings -a "$i" | grep "Content-Range"; done | tr '/-' ' ' | sort -nk4
Content Range: bytes 13 179538 2347916
Content Range: bytes 27943 132132 2347916
Content Range: bytes 145550 198027 2347916
Content Range: bytes 188923 359924 2347916
Content Range: bytes 337541 500782 2347916
Content Range: bytes 467298 648929 2347916
Content Range: bytes 552789 781321 2347916
Content Range: bytes 694834 905770 2347916
Content Range: bytes 892465 1067354 2347916
Content Range: bytes 905781 1032111 2347916
Content Range: bytes 986065 1150874 2347916
Content Range: bytes 1080486 1345387 2347916
Content Range: bytes 1276598 1432659 2347916
Content Range: bytes 1397670 1593207 2347916
Content Range: bytes 1507903 1694032 2347916
Content Range: bytes 1540792 1639406 2347916
Content Range: bytes 1672374 1872648 2347916
Content Range: bytes 1774960 1959007 2347916
Content Range: bytes 1888311 1938509 2347916
Content Range: bytes 1904693 2059434 2347916
Content Range: bytes 1987909 2044321 2347916
Content Range: bytes 2001846 2202904 2347916
Content Range: bytes 2106781 2347915 2347916
```

Looks like everything - except the first 13 bytes - is available.

First we create a file of size `2347916` using `dd`:

```bash
$ dd if=/dev/zero of=tcpstream bs=2347916 count=1
1+0 records in
1+0 records out
2347916 bytes (2.3 MB, 2.2 MiB) copied, 0.00619454 s, 379 MB/s
$ ls -alF tcpstream
-rw-r--r-- 1 root root 2347916  7월  8 01:20 tcpstream
```

Then, we write a small [python script] that reassembles the big file from the parts according to their content-ranges:

```python
# reassembler.py
import re, sys
if len(sys.argv) != 3: sys.exit(3)
with open(sys.argv[1], 'r') as f:
	stream = f.read()
results = re.findall(r'Content-Range: bytes (\d+)-(\d+)/\d+', stream)
if len(results) < 1: sys.exit(1)
(begin, end) = results[0]
begin = int(begin)
end = int(end)
print begin, end, len(stream), len(stream)-end+begin
with open(sys.argv[2], 'r+b') as f:
	f.seek(begin)
	f.write(stream[len(stream)-end+begin-1:])
	f.close()
```



```bash
# by Ubuntu
$ for i in 087.107.124.013.00080-192.168.221.128.54*; do python2.7 reassembler.py "$i" tcpstream; done
1080486 1345387 265284 382
986065 1150874 165191 381
1397670 1593207 195920 382
337541 500782 163622 380
2001846 2202904 201441 382
467298 648929 182012 380
1507903 1694032 186512 382
552789 781321 228913 380
1276598 1432659 156444 382
1888311 1938509 50580 381
13 179538 179902 376
2106781 2347915 241517 382
1540792 1639406 98996 381
145550 198027 52857 379
905781 1032111 126712 381
1987909 2044321 56794 381
694834 905770 211317 380
27943 132132 104569 379
1774960 1959007 184430 382
892465 1067354 175271 381
1904693 2059434 155124 382
188923 359924 171382 380
1672374 1872648 200657 382
$ md5sum tcpstream
#657c2f7517a0ef498b25c42e9872d010  tcpstream
61f89707b9c9d2d2da88dfb9259dea56  tcpstream

```

We open the stream using a hexeditor (e.g. `hexedit`) to see that the transmitted file most likely is a PNG, since it contains chunk names such as `[I]HDR`, `pHYs` and `IDAT`:

![image](https://github.com/mkive/Network/assets/4083018/e929947b-499d-49ab-b1fd-84c5c24d3fb6)
![image](https://github.com/mkive/Network/assets/4083018/f0c056af-3274-4252-a054-cf1ff5624776)


All that's left to do is to insert the missing first 13 bytes (also known as part of a `header`) of our PNG.

We can either look up any [PNG specification](http://www.w3.org/TR/PNG/#5DataRep) or open a valid PNG in `hexedit` to know what these first 13 bytes are:

![](png-header.png)

```bash
$ hexedit tcpstream
00000000   00 00 00 00  00 00 00 00  00 00 00 00  00 80 00 00  04 B0 08 06  00 00 00 1A  ........................
00000018   30 57 F6 00  00 00 09 70  48 59 73 00  00 0B 13 00  00 0B 13 01  00 9A 9C 18  0W.....pHYs.............
00000030   00 00 0A 4F  69 43 43 50  50 68 6F 74  6F 73 68 6F  70 20 49 43  43 20 70 72  ...OiCCPPhotoshop ICC pr
00000048   6F 66 69 6C  65 00 00 78  DA 9D 53 67  54 53 E9 16  3D F7 DE F4  42 4B 88 80  ofile..x..SgTS..=...BK..
00000060   94 4B 6F 52  15 08 20 52  42 8B 80 14  91 26 2A 21  09 10 4A 88  21 A1 D9 15  .KoR.. RB....&*!..J.!...
00000078   51 C1 11 45  45 04 1B C8  A0 88 03 8E  8E 80 8C 15  51 2C 0C 8A  0A D8 07 E4  Q..EE...........Q,......
00000090   21 A2 8E 83  A3 88 8A CA  FB E1 7B A3  6B D6 BC F7  E6 CD FE B5  D7 3E E7 AC  !.........{.k........>..
000000A8   F3 9D B3 CF  07 C0 08 0C  96 48 33 51  35 80 0C A9  42 1E 11 E0  83 C7 C4 C6  .........H3Q5...B.......
000000C0   E1 E4 2E 40  81 0A 24 70  00 10 08 B3  64 21 73 FD  23 01 00 F8  7E 3C 3C 2B  ...@..$p....d!s.#...~<<+
000000D8   22 C0 07 BE  00 01 78 D3  0B 08 00 C0  4D 9B C0 30  1C 87 FF 0F  EA 42 99 5C  ".....x.....M..0.....B.\
000000F0   01 80 84 01  C0 74 91 38  4B 08 80 14  00 40 7A 8E  42 A6 00 40  46 01 80 9D  .....t.8K....@z.B..@F...
00000108   98 26 53 00  A0 04 00 60  CB 63 62 E3  00 50 2D 00  60 27 7F E6  D3 00 80 9D  .&S....`.cb..P-.`'......
00000120   F8 99 7B 01  00 5B 94 21  15 01 A0 91  00 20 13 65  88 44 00 68  3B 00 AC CF  ..{..[.!..... .e.D.h;...
00000138   56 8A 45 00  58 30 00 14  66 4B C4 39  00 D8 2D 00  30 49 57 66  48 00 B0 B7  V.E.X0..fK.9..-.0IWfH...
00000150   00 C0 CE 10  0B B2 00 08  0C 00 30 51  88 85 29 00  04 7B 00 60  C8 23 23 78  ..........0Q..)..{.`.##x
00000168   00 84 99 00  14 46 F2 57  3C F1 2B AE  10 E7 2A 00  00 78 99 B2  3C B9 24 39  .....F.W<.+...*..x..<.$9
00000180   45 81 5B 08  2D 71 07 57  57 2E 1E 28  CE 49 17 2B  14 36 61 02  61 9A 40 2E  E.[.-q.WW..(.I.+.6a.a.@.
00000198   C2 79 99 19  32 81 34 0F  E0 F3 CC 00  00 A0 91 15  11 E0 83 F3  FD 78 CE 0E  .y..2.4..............x..
000001B0   AE CE CE 36  8E B6 0E 5F  2D EA BF 06  FF 22 62 62  E3 FE E5 CF  AB 70 40 00  ...6..._-...."bb.....p@.
000001C8   00 E1 74 7E  D1 FE 2C 2F  B3 1A 80 3B  06 80 6D FE  A2 25 EE 04  68 5E 0B A0  ..t~..,/...;..m..%..h^..
000001E0   75 F7 8B 66  B2 0F 40 B5  00 A0 E9 DA  57 F3 70 F8  7E 3C 3C 45  A1 90 B9 D9  u..f..@.....W.p.~<<E....
000001F8   D9 E5 E4 E4  D8 4A C4 42  5B 61 CA 57  7D FE 67 C2  5F C0 57 FD  6C F9 7E 3C  .....J.B[a.W}.g._.W.l.~<
00000210   FC F7 F5 E0  BE E2 24 81  32 5D 81 47  04 F8 E0 C2  CC F4 4C A5  1C CF 92 09  ......$.2].G......L.....
---  tcpstream       --0x0/0x23D38C--0%--------------------------------------------------------------------------

```
After inserting these bytes, we get the following picture containing our flag:

![image](https://github.com/mkive/Network/assets/4083018/d9ec38fa-7793-4550-b31f-16b7160d9f3d)
![image](https://github.com/mkive/Network/assets/4083018/d0e52672-472f-497a-b62e-7dbba32fd1c7)


Now, because we are super-cheeky, we can apply [OCR](https://en.wikipedia.org/wiki/Optical_character_recognition) to extract the flag automatically without writing it down by hand:

![image](https://github.com/mkive/Network/assets/4083018/22789153-ec9e-4e89-a537-fe8937c7aaa5)

```bash
$ tesseract tcpstream.png ./out
[...]
$ cat out.txt
ASIS{8bffe21e084db147b32aa850bc65eb16}
```

The flag is `ASIS{8bffe21e084db147b32aa850bc65eb16}`.

PS: According to [this writeup](https://github.com/naijim/blog/blob/master/writeups/asis-quals-ctf-2015_broken_heart_writeup.md) there exists a program called `dshell` that does the parts reassembling job for us - haven't tried it out yet though.

