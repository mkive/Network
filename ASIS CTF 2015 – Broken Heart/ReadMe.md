# ASIS Quals CTF 2015: Broken Heart

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

Looking at the type of network protocols used in the transmission, we see a bunch of mostly TCP, DNS and HTTP Requests:

```bash
$ tshark -r myheart_7cb6daec0c45b566b9584f98642a7123  | awk '{print $6}' | sort | uniq -c | sort -n
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
sudo apt install tcpflow    
sudo apt install tcpflow-nox


$ tcpflow -r myheart_7cb6daec0c45b566b9584f98642a7123
$ ls -1
087.107.124.013.00080-192.168.221.128.54391
087.107.124.013.00080-192.168.221.128.54392
087.107.124.013.00080-192.168.221.128.54393
[...]
087.107.124.013.00080-192.168.221.128.54414
087.107.124.013.00080-192.168.221.128.54415
192.168.221.128.54391-087.107.124.013.00080
192.168.221.128.54392-087.107.124.013.00080
[...]
192.168.221.128.54414-087.107.124.013.00080
192.168.221.128.54415-087.107.124.013.00080
alerts.txt
myheart_7cb6daec0c45b566b9584f98642a7123
report.xml
```

Since we only need data transmitted from `87.107.124.13` to `192.168.221.128`, we only care about the files beginning with `087.107.124.013`.

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
2347916 bytes transferred in 0.001627 secs (1443123310 bytes/sec)
$ ls -alF tcpstream
-rw-r--r--  1 xxx xxx 2347916 Dec 22 22:13 tcpstream
```

Then, we write a small [python script](./reassembler.py) that reassembles the big file from the parts according to their content-ranges:

```bash
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
$ md5 tcpstream
61f89707b9c9d2d2da88dfb9259dea56  tcpstream
```

We open the stream using a hexeditor (e.g. `hexedit`) to see that the transmitted file most likely is a PNG, since it contains chunk names such as `[I]HDR`, `pHYs` and `IDAT`:

![](./other-chunks.png)

![](./idat-chunk.png)

All that's left to do is to insert the missing first 13 bytes (also known as part of a `header`) of our PNG.

We can either look up any [PNG specification](http://www.w3.org/TR/PNG/#5DataRep) or open a valid PNG in `hexedit` to know what these first 13 bytes are:

![](png-header.png)

After inserting these bytes, we get the following picture containing our flag:

![](tcpstream.png)

Now, because we are super-cheeky, we can apply [OCR](https://en.wikipedia.org/wiki/Optical_character_recognition) to extract the flag automatically without writing it down by hand:

```bash
$ tesseract tcpstream.png ./out
[...]
$ cat out.txt
ASIS{8bffe21e084db147b32aa850bc65eb16}
```

The flag is `ASIS{8bffe21e084db147b32aa850bc65eb16}`.

PS: According to [this writeup](https://github.com/naijim/blog/blob/master/writeups/asis-quals-ctf-2015_broken_heart_writeup.md) there exists a program called `dshell` that does the parts reassembling job for us - haven't tried it out yet though.

## Other write-ups and resources

* <http://lockboxx.blogspot.com/2015/05/asis-ctf-2015-quals-writeup-broken-heart.html>
* <https://xmgv.wordpress.com/2015/05/11/asis-ctf-quals-2015-broken-heart/>
* <https://github.com/naijim/blog/blob/master/writeups/asis-quals-ctf-2015_broken_heart_writeup.md>
* <http://www.thice.nl/asis-ctf-2015-write-ups/>
* [Indonesian](https://github.com/rentjongteam/write-ups-2015/tree/master/asis-quals-2015/broken-heart)
