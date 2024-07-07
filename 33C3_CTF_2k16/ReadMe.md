# 33C3 CTF 2016 : Exfil

**Category:** Forensic **Points:** 100 **Solves:** 137

> We hired somebody to gather intelligence on an enemy party. But apparently they managed to lose the secret document they extracted. They just sent us this and said we should be able to recover everything we need from it.
> Can you help?



## Write-up

For this challenge, we have a PCAP file and a Python server. It's clear that we have to recover a 'secret document' with this. Let see what we have :


### Python Server

We have a Python server which is used to communicate and execute commands over DNS, here are some interesting parts :

```python
...
from dnslib import * # dnslib
...
data = base64.b32encode(data).rstrip(b'=') # BASE32 Encoded
...
    chunk_size = 62
    for i in range(0, len(data), chunk_size): # Chunks every 62 chars
        chunks.append(data[i:i+chunk_size])
    chunks += domain.encode().split(b'.')
...
domain = 'eat-sleep-pwn-repeat.de' # Domain
...
def parse_name(label):
    return decode_b32(b''.join(label.label[:-domain.count('.')-1])) # No domain for the BASE32
...
class RemoteShell: # A little RemoteShell to execute commands and extract the secret document :)
...
```



### PCAP dump

Here is our PCAP :
```bash
$ file dump.pcap 
dump.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

Protocol hierarchy :
```bash
$ tshark -qr dump.pcap -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter: 
eth                                      frames:1804 bytes:306168
  ip                                     frames:1804 bytes:306168
    udp                                  frames:1804 bytes:306168
      dns                                frames:1804 bytes:306168
===================================================================
```

Communication : 
```bash
$ tshark -r dump.pcap -z ip_hosts,tree -q
===============================================================================================================================
IP Statistics/IP Addresses:
Topic / Item    Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start  
-------------------------------------------------------------------------------------------------------------------------------
IP Addresses    1804                                                    0,0177        100%          3,4600        19,865       
 192.168.0.121  1804                                                    0,0177        100,00%       3,4600        19,865       
 192.168.0.1    1804                                                    0,0177        100,00%       3,4600        19,865       
-------------------------------------------------------------------------------------------------------------------------------
```


So, it looks like we have the server '192.168.0.1' and the enemy party '192.168.0.121' from where they extracted the 'secret document'.

From the Python Server code, we may be interested to extract the 'A' query and the CNAME response to anlyses them :

```bash
$ tshark -r dump.pcap -Tfields -e dns.qry.name -e dns.cname
```

First look, we have a lot of duplicate data. Then, I tried to figure out how exactly the server encode de communication. 
After several (hundreds...) test part by part and the domain name 'eat-sleep-pwn-repeat.de' removed, I was able to decode manually some some data with BASE32 :

Original query : `G4JUSBIXCV2G65DBNQQDKNSLBIZDMMRUGE4DIIDEOJ3XQ4RNPBZC26BAGMQGM4.DFORZHSIDGOBSXI4TZEA2C4MCLEBCGKYZAGE3SAMJTHIZTCIBOBIZDMMRRGQ2D.CIDEOJ3XQ4RNPBZC26BAGUQHE33POQQCAIDSN5XXIIBAEA2C4MCLEBCGKYZAGE.3SAMJTHIYDMIBOFYFDENRT.eat-sleep-pwn-repeat.de`

Python 2.x 
```python 2.x
>>> import base64
>>> print(base64.b32decode('G4JUSBIXCV2G65DBNQQDKNSLBIZDMMRUGE4DIIDEOJ3XQ4RNPBZC26BAGMQGM4DFORZHSIDGOBSXI4TZEA2C4MCLEBCGKYZAGE3SAMJTHIZTCIBOBIZDMMRRGQ2DCIDEOJ3XQ4RNPBZC26BAGUQHE33POQQCAIDSN5XXIIBAEA2C4MCLEBCGKYZAGE3SAMJTHIYDMIBOFYFDENRT'))
7Itotal 56K
2624184 drwxr-xr-x 3 fpetry fpetry 4.0K Dec 17 13:31 .
2621441 drwxr-xr-x 5 root   root   4.0K Dec 17 13:06 ..
263
```

Python 3.x
```python 3.x
import base64

encoded_string = 'G4JWIGURCV2G65DBNQQDIMCLBIZDMMRUGE4DIIDEOJ3XQ4RNPBZC26BAGMQGM4.DFORZHSIDGOBSXI4TZEA2C4MCLEBCGKYZAGE3SAMJTHIZTEIBOBIZDMMRRGQ2D.CIDEOJ3XQ4RNPBZC26BAGUQHE33POQQCAIDSN5XXIIBAEA2C4MCLEBCGKYZAGE.3SAMJTHIYDMIBOFYFDENRT'

# Remove dots (.)
encoded_string = encoded_string.replace('.', '')

# Add necessary padding
padding = '=' * ((8 - len(encoded_string) % 8) % 8)
padded_encoded_string = encoded_string + padding

# Decode
decoded_bytes = base64.b32decode(padded_encoded_string)

print(decoded_bytes)

```

```
python decode.py 
b'7\x13d\x1a\x91\x15total 40K\n2624184 drwxr-xr-x 3 fpetry fpetry 4.0K Dec 17 13:32 .\n2621441 drwxr-xr-x 5 root   root   4.0K Dec 17 13:06 ..\n263'
```



We can see that from the server code, each query begins with 6 bytes which contain the the acknowledgement, conversation ID and sequence number. I simply removed it to decode all communication.

So, the idea here is, we need to : 
* Have one query/response per line to decode it easly
* Remove duplicate line
* Remove '.eat-sleep-pwn-repeat.de' and all '.' for each line
* Decode each line from BASE32
* Remove the first 6 bytes for each decoded line

PCAP Extraction, one query/response per line and unique one :
```bash
$ tshark -r dump.pcap -Tfields -e dns.qry.name | awk '!a[$0]++' > extracted.txt && tshark -r dump.pcap -Tfields -e dns.cname | awk '!a[$0]++' >> extracted.txt
```

Got it!
[pcap_extracted.txt](https://github.com/mkive/Network/blob/main/33C3_CTF_2k16/extracted.txt)


Decode
```python
#!/usr/bin/env python2
import base64
with open("extracted.txt") as f:
    pcap_decoded = ""
    for line in f:
        s = ""
        l = line.split('.', line.count('.'))
        for i in range(line.count('.')-1):
            s += str(l[i])
        try:
            pcap_decoded += base64.b32decode(s)[6:]
        except:
            pass
decoded = open('decoded.txt', 'w')
decoded.write(pcap_decoded)
decoded.close()
f.close()
```

```python
#!/usr/bin/env python3
import base64

# File ReadMode
with open("extracted.txt", "r") as f:
    pcap_decoded = ""
    
    for line in f:
        s = ""
        l = line.split('.', line.count('.'))
        
        # Concatenate each part separated by a dot (.)
        for i in range(line.count('.') - 1):
            s += str(l[i])
        
        # Base32 Decoding
        try:
            pcap_decoded += base64.b32decode(s)[6:].decode('utf-8', errors='ignore')
        except Exception as e:
            pass

# Decoding Result File Write
with open('decoded.txt', 'w') as decoded:
    decoded.write(pcap_decoded)
```

Got it!
[pcap_decoded.txt](https://github.com/mkive/Network/blob/main/33C3_CTF_2k16/decoded.txt)

Wait a minute, not done yet, it looks like we have our 'secret document' encrypted... with the file and the key :)
```bash
...
2631216 -rw-r--r-- 1 fpetry fpetry 4.0K Dec 17 13:17 secret.docx
2631222 -rw-rw-r-- 1 fpetry fpetry 4.4K Dec 17 13:31 secret.docx.gpg
2631218 -rw------- 1 fpetry fpetry  908 Dec 17 13:21 .START_OF_FILE�L+�0�j
...
H��0ʟ�=END_OF_FILE
...
-----BEGIN PGP PUBLIC KEY BLOCK-----
lv+fGfdzCZnubp254S3mLsyokuyZ7xjy/i0m2a5fVQ==
=XS5g
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBFhNxEIBCACokqjLjvpwnm/lCdKTnT/vFqnohml2xZo/WiMAr4h3CdTal4yf
...
```

We need to extract our secret.docx.gpg :
```python
#!/usr/bin/env python2
with open("decoded.txt") as f:
    s = f.read().replace('\n', '')
    start = s.index("START_OF_FILE") + len("START_OF_FILE")
    end = s.index("END_OF_FILE", start )
    secret = open('secret.docx.gpg', 'w')
    secret.write(s[start:end])
    secret.close()
    f.close()
```

```python
#!/usr/bin/env python3
# Open decoded.txt file in read mode
with open("decoded.txt", "r") as f:
    s = f.read().replace('\n', '')
    
    # Find the content between START_OF_FILE and END_OF_FILE
    start = s.index("START_OF_FILE") + len("START_OF_FILE")
    end = s.index("END_OF_FILE", start)
    
    # Open secret.docx.gpg file in write mode
    with open('secret.docx.gpg', 'w') as secret:
        secret.write(s[start:end])
```


# DNS Packet Decoder Script

This Python script processes DNS traffic from a pcap file (`dump.pcap`), decodes specific data from DNS packets, and writes the decoded data to an output file (`decode.txt`). The script is designed to filter out duplicates and empty packets, ensuring efficient and accurate data extraction.


```bash
$ pip install dpkt
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: dpkt in /home/kali/.local/lib/python3.11/site-packages (1.9.8)
```


```python
#!/usr/bin/env python3
import base64
import struct
import dpkt

# packet sequence numbers that we will keep track of
sseq = -1
dseq = -1

def decode_b32(s):
    s = s.upper()
    if isinstance(s, str):
        s = s.encode('utf-8')
    for i in range(10):
        try:
            return base64.b32decode(s)
        except base64.binascii.Error:
            s += b'='
    raise ValueError('Invalid base32')

def parse(name):
    if isinstance(name, str):
        name = name.encode('utf-8')
    # split payload data at periods, remove the top 
    # level domain name, and decode the data
    data = decode_b32(b''.join(name.split(b'.')[:-2]))
    (conn_id, seq, ack) = struct.unpack('<HHH', data[:6])
    return (seq, data[6:])

def handle(val, port, output_file):
    global sseq, dseq
    (seq, data) = parse(val)
    # remove empty packets
    if len(data) == 0:
        return
    
    # remove duplicates
    if port == 53:
        if sseq < seq:
            sseq = seq
        else:
            return
    else:
        if dseq < seq:
            dseq = seq
        else:
            return
    
    # Writing data to output file
    with open(output_file, 'ab') as f:
        f.write(data)

# Output file name
output_file = 'decode.txt'

# main execution loop - go through all DNS packets, 
# decode payloads and dump them to the screen
with open('dump.pcap', 'rb') as f:
    for ts, pkt in dpkt.pcap.Reader(f):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                
                dns = dpkt.dns.DNS(udp.data)
                # extract commands from CNAME records and 
                # output from queries
                if udp.sport == 53: 
                    for rr in dns.an:
                        if rr.type == dpkt.dns.DNS_CNAME:
                            handle(rr.cname, udp.sport, output_file)
                else:
                    if dns.opcode == dpkt.dns.DNS_QUERY:
                        handle(dns.qd[0].name, udp.sport, output_file)

print("Data written to", output_file)
```


## Key Components

### Import Statements and Global Variables

```python
import base64
import struct
import dpkt

# Packet sequence numbers that we will keep track of
sseq = -1
dseq = -1
```

Imports:
* base64: For base32 decoding.
* struct: For unpacking binary data.
* dpkt: For parsing pcap files.

Global Variables:
sseq and dseq: These are used to keep track of the last seen sequence numbers for packets from different ports to avoid processing duplicates.
Base32 Decoding Function
python
Copy code
def decode_b32(s):
    s = s.upper()
    if isinstance(s, str):
        s = s.encode('utf-8')
    for i in range(10):
        try:
            return base64.b32decode(s)
        except base64.binascii.Error:
            s += b'='
    raise ValueError('Invalid base32')
decode_b32:
Converts the input string to uppercase.
Ensures the input is a byte string.
Tries to decode the base32 string up to 10 times, adding padding (=) if decoding fails.
Raises a ValueError if it cannot decode after 10 attempts.
Parse Function
python
Copy code
def parse(name):
    if isinstance(name, str):
        name = name.encode('utf-8')
    # Split payload data at periods, remove the top 
    # level domain name, and decode the data
    data = decode_b32(b''.join(name.split(b'.')[:-2]))
    (conn_id, seq, ack) = struct.unpack('<HHH', data[:6])
    return (seq, data[6:])
parse:
Ensures the input name is a byte string.
Removes the top-level domain (TLD) and joins the remaining parts.
Decodes the result using decode_b32.
Unpacks the first 6 bytes of the decoded data into conn_id, seq, and ack.
Returns the sequence number (seq) and the remaining data.
Handle Function
python
Copy code
def handle(val, port, output_file):
    global sseq, dseq
    (seq, data) = parse(val)
    # Remove empty packets
    if len(data) == 0:
        return
    # Remove duplicates
    if port == 53:
        if sseq < seq:
            sseq = seq
        else:
            return
    else:
        if dseq < seq:
            dseq = seq
        else:
            return
    # Writing data to output file
    with open(output_file, 'ab') as f:
        f.write(data)
handle:
Parses the input value to get the sequence number and data.
Filters out empty data packets.
Checks for duplicate packets using sequence numbers and updates sseq or dseq accordingly.
Writes valid data to the output file (decode.txt) in append-binary mode.
Main Execution Loop
python
Copy code
output_file = 'decode.txt'

with open('dump.pcap', 'rb') as f:
    for ts, pkt in dpkt.pcap.Reader(f):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                dns = dpkt.dns.DNS(udp.data)
                # Extract commands from CNAME records and 
                # output from queries
                if udp.sport == 53: 
                    for rr in dns.an:
                        if rr.type == dpkt.dns.DNS_CNAME:
                            handle(rr.cname, udp.sport, output_file)
                else:
                    if dns.opcode == dpkt.dns.DNS_QUERY:
                        handle(dns.qd[0].name, udp.sport, output_file)

print("Data written to", output_file)
Main Execution Loop:
Opens the pcap file (dump.pcap) in binary read mode.
Iterates over each packet in the pcap file using dpkt.pcap.Reader.
Checks if the packet is an IP packet.
Further checks if it is a UDP packet.
If the UDP packet is from port 53 (DNS response), it processes CNAME records.
If it is a DNS query, it processes the query name.
The handle function is called to decode and write valid data to decode.txt.
Summary
The script processes DNS traffic from a pcap file, decodes specific data from DNS packets, and writes the decoded data to an output file while filtering out duplicates and empty packets. The decoding handles potential padding issues with base32 encoding, ensuring robustness in the parsing logic.

Running the Script
Ensure you have the dpkt library installed:

sh
Copy code
pip install dpkt
Run the script using Python 3:

sh
Copy code
python3 script_name.py
Replace script_name.py with the actual name of your script file. Make sure you have the dump.pcap file in the same directory or provide the correct path to it. This should resolve the errors and allow the script to run correctly.












Got it!
[decode.txt](https://github.com/mkive/Network/blob/main/33C3_CTF_2k16/decode.txt)


secret.docx.gpg
```bash
$ file secret.docx.gpg
secret.docx.gpg: PGP RSA encrypted session key - keyid: 1B142B4C 6AA230BF RSA (Encrypt or Sign) 2048b .
```

The output is a treasure trove of information:

- There is a public and private key. We save them to local file key.txt.
- There are commands the user executed to encrypt a document
- And there is the encrypted document itself, written to stdout. The document body is output between tags START_OF_FILE and END_OF_FILE. We use a binary editor (e.g. HxD) to extract its body to secret.docx.gpg.


Now all that is left is to backtrack the user’s steps from the output log and decrypt the document:

```bash
$ gpg --import key.txt                                     
gpg: key D43CC062D0D8161F: "operator from hell <team@kitctf.de>" not changed
gpg: key D43CC062D0D8161F: "operator from hell <team@kitctf.de>" not changed
gpg: key D43CC062D0D8161F: secret key imported
gpg: Total number processed: 2
gpg:              unchanged: 2
gpg:       secret keys read: 1
gpg:  secret keys unchanged: 1

$ gpg --decrypt --recipient team@kitctf.de --trust-model always secret.docx.gpg > secret.docx
gpg: encrypted with 2048-bit RSA key, ID 4C2B141BBF30A26A, created 2016-12-11
      "operator from hell <team@kitctf.de>"
```

Here we go, we have a nice [secret.docx](https://github.com/zbetcheckin/33C3_CTF_2k16/blob/master/secret.docx) with the flag :
```bash
$ file secret.docx
secret.docx: Microsoft Word 2007+
```

**Flag:**
The secret codeword is 
33C3_g00d_d1s3ct1on_sk1llz_h0mie
