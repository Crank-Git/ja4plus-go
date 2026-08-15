# The seven deleted FoxIO text specifications

FoxIO published a text specification for seven JA4+ methods. FoxIO commit `b6f3ff4`
deleted all seven files from `technical_details/`. This page recovers the text of the
seven files, and it reproduces each one without a change.

**This project read the seven files at FoxIO commit
`7ff7b3275a9d084ab6884559a6e58a9cee08f19d`.** That commit is the parent of `b6f3ff4`, and
it is dated 2024-02-22.

**The commit above is not the pin.** `testdata/foxio.pin` holds the pin,
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. The two commits differ on purpose. Five of the
seven files exist at no commit after `b6f3ff4`, so the pin cannot supply them.

Two files carry the same name at the pin, and the content differs from the recovered
content. Read the recovered file as the deleted 2024-02-22 text, and never as the current
file.

| File | At the pin | Recovered here |
|---|---|---|
| `JA4.md` | Present, 6.8 KB | The 2024-02-22 text, 8.9 KB |
| `JA4H.md` | Present, 278 bytes | The 2024-02-22 text, 8.9 KB |
| `JA4L.md` | Absent | The 2024-02-22 text |
| `JA4S.md` | Absent | The 2024-02-22 text |
| `JA4SSH.md` | Absent | The 2024-02-22 text |
| `JA4T.md` | Absent | The 2024-02-22 text |
| `JA4X.md` | Absent | The 2024-02-22 text |

## A deleted text specification corroborates an image, and it never outranks one

`.claude/rules/rulings.md` holds the source ranking. A FoxIO image under
`technical_details/` decides the schema. A FoxIO reference implementation decides the
behaviour that the image leaves silent. **A deleted text specification corroborates an
image, and it never outranks one.**

FoxIO deleted these seven files, and FoxIO kept the images. A rule that this page states
and an image contradicts is not a rule this project follows. Where the two agree, cite
both.

Two of the seven files are the primary source for a rule that no image states: `JA4T.md`
specifies JA4TS part e, and it specifies the JA4TS value for a TCP reset.

## The FoxIO license covers this text

FoxIO wrote the seven files, and FoxIO License 1.1 covers every JA4+ method except JA4.
FoxIO License 1.1 permits non-commercial use only. `NOTICE` at the repository root holds
the full license text, and it states which license covers which material.

Read the license at <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>.

## The ruling that put the copy on this page

**The maintainer ruled on 2026-08-11.** The question was whether a verbatim copy of the
deleted text is a redistribution that the FoxIO license governs.
`docs/specs/features/11-foxio-reference.md` open question 1 held the question, and issue
[#18](https://github.com/Crank-Git/ja4plus-go/issues/18) holds the ruling.

The ruling: **copy the seven files verbatim, and carry the FoxIO License 1.1 notice on the
page.** The maintainer declined the alternative, which quoted each rule and linked to the
historical commit.

The ruling is reversible. Reverse it with a new fact, and record the reversal on issue
#18.

## This page reproduces no FoxIO image

`.claude/rules/ste.md` and FR-reference-16 bar a reproduction of a FoxIO image. Read the
images at <https://github.com/FoxIO-LLC/ja4/tree/main/technical_details>.

Each recovered file below sits in a fenced block. The fence holds the FoxIO text as text,
so the rendered page shows the image links of the FoxIO source and renders no image.

## How to reproduce the recovery

Run the three commands below. The digest of each recovered file matches the table that
follows.

```
git clone https://github.com/FoxIO-LLC/ja4.git
cd ja4
git show 7ff7b3275a9d084ab6884559a6e58a9cee08f19d:technical_details/JA4.md | shasum -a 256
```

| File | SHA-256 at `7ff7b32` |
|---|---|
| `JA4.md` | `a8c2b4c2ecf4f7836a04ad3f2614ca33d0b9f0836805aa3de9e6d0be6fbd20ec` |
| `JA4H.md` | `0587d4180145e7c1f02adde3583fbb2929486e85a05a082f5c139d21d16f918f` |
| `JA4L.md` | `bcf02bc318f7d783da45eff5d00aa32fb5f7b874688eb17e766ba3d6956e8247` |
| `JA4S.md` | `d762c3aadf34ef3999bcbb777ca43c20db0b42923910cb7018430f292e6baf51` |
| `JA4SSH.md` | `843c8f737ec40b4e38300021fcaca7ac8a058ed869ecda5de068fc57cf8af66c` |
| `JA4T.md` | `d8ec985535f5bbf2cf411989f6ab19b17191585137e4ee448041e9ee91191d76` |
| `JA4X.md` | `b094b74a74c541fabb6c3c01150fe10960f41047e6ef5ac8fd15c32259407c8b` |

`foxio_deleted_specs_test.go` holds the same digests, and it fails when an edit changes one
character of a recovered file.

## The recovered files

### JA4.md

Read at FoxIO commit `7ff7b3275a9d084ab6884559a6e58a9cee08f19d`, path
`technical_details/JA4.md`.

<!-- BEGIN VERBATIM JA4.md -->
```````
# JA4: TLS Client Fingerprinting

![JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.png)

JA4 looks at the TLS Client Hello packet and builds a fingerprint of the client based on attributes within the packet.

### JA4 Algorithm:
(QUIC=”q” or TCP=”t”)  
(2 character TLS version)  
(SNI=”d” or no SNI=”i”)  
(2 character count of ciphers)  
(2 character count of extensions)  
(first and last characters of first ALPN extension value)  
_  
(sha256 hash of the list of cipher hex codes sorted in hex order, truncated to 12 characters)  
_  
(sha256 hash of (the list of extension hex codes sorted in hex order)_(the list of signature algorithms), truncated to 12 characters)  
  
The end result is a fingerprint that looks like:  
t13d1516h2_8daaf6152771_b186095e22b6  
  
## Details:
The program needs to ignore GREASE values anywhere it sees them: (https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5)

### QUIC:
https://en.wikipedia.org/wiki/QUIC  
“q” or “t”, which denotes whether the hello packet is for QUIC or TCP. QUIC is the protocol which the new HTTP/3 standard utilizes, encapsulating TLS 1.3 into UDP packets. As QUIC was developed by Google, if an organization heavily utilizes Google products, QUIC could make up half of their network traffic, so this is important to capture.  

If the protocol is QUIC then the first character of the fingerprint is “q” if not, it’s “t”.  

### TLS Version:
TLS version is shown in 3 different places. If extension 0x002b exists (supported_versions), then the version is the highest value in the extension. Remember to ignore GREASE values. If the extension doesn’t exist, then the TLS version is the value of the Protocol Version. Handshake version (located at the top of the packet) should be ignored.

0x0304 = TLS 1.3 = “13”  
0x0303 = TLS 1.2 = “12”  
0x0302 = TLS 1.1 = “11”  
0x0301 = TLS 1.0 = “10”  
0x0300 = SSL 3.0 = “s3”  
0x0200 = SSL 2.0 = “s2”  
0x0100 = SSL 1.0 = “s1”  
  
Unknown = “00”

### SNI:
If the SNI extension (0x0000) exists, then the destination of the connection is a domain, or “d” in the fingerprint. If the SNI does not exist, then the destination is an IP address, or “i”.

### Number of Ciphers:
2 character number of cipher suites, so if there’s 6 cipher suites in the hello packet, then the value should be “06”. If there’s > 99, which there should never be, then output “99”. Remember, ignore GREASE values. They don’t count.

### Number of Extensions:
Same as counting ciphers. Ignore GREASE. Include SNI and ALPN.

### ALPN Extension Value:
The first and last characters of the ALPN (Application-Layer Protocol Negotiation) first value.  
List of possible ALPN Values (scroll down): https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml



In the above example, the first ALPN value is h2 so the first and last characters to use in the fingerprint are “h2”. IF the first ALPN listed was http/1.1 then the first and last characters to use in the fingerprint would be “h1”.

In Wireshark this field is located under tls.handshake.extensions_alpn_str

If there are no ALPN values or no ALPN extension then we print “00” as the value in the fingerprint.

### Cipher hash:
A 12 character truncated sha256 hash of the list of ciphers sorted in hex order, first 12 characters. The list is created using the 4 character hex values of the ciphers, lower case, comma delimited, ignoring GREASE.  
Example:
```
1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035
```
Is sorted to:
```
002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9 = 8daaf6152771
```

### Extension hash:
A 12 character truncated sha256 hash of the list of extensions, sorted by hex value, followed by the list of signature algorithms, in the order that they appear (not sorted).

The extension list is created using the 4 character hex values of the extensions, lower case, comma delimited, sorted (not in the order they appear). Ignore the SNI extension (0000) and the ALPN extension (0010) as we’ve already captured them in the _a_ section of the fingerprint. These values are omitted so that the same application would have the same _b_ section of the fingerprint regardless of if it were going to a domain, IP, or changing ALPNs.

For example:
```
001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015
```
Is sorted to:
```
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01
```
(notice 0000 and 0010 is removed)

The signature algorithm hex values are then added to the end of the list in the order that they appear (not sorted) with an underscore delimiting the two lists.  
For example the signature algorithms:  
```
0403,0804,0401,0503,0805,0501,0806,0601
```
Are added to the end of the previous string to create:
```
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```
Hashed to:
```
e5627efa2ab19723084c1033a96c694a45826ab5a460d2d3fd5ffcfe97161c95
```
Truncated to first 12 characters:
```
e5627efa2ab1
```

If there are no signature algorithms in the hello packet, then the string ends without an underscore and is hashed.   
For example:
```
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01 = 6d807ffa2a79
```

### Example

JA4 fingerprint:  
t (TLS over TCP)  
13 (TLS version 1.3)  
d (SNI exists so it’s going to a domain)  
15 (15 cipher suites ignoring grease)  
16 (16 extensions ignoring grease)  
h2 (first and last characters of the first ALPN extension value)  
_  
8daaf6152771 (truncated sha256 hash of the list of ciphers sorted)
_  
e5627efa2ab1 (truncated sha256 hash of the list of extensions sorted, SNI and ALPN removed, followed by the list of signature algorithms)
```
JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1  
```
### Raw Output  
The program should allow for raw outputs either sorted or original.  
-r (raw fingerprint) -o (original) 

The raw fingerprint for JA4 would look like this:
```
JA4_r = t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```

The "o" option includes the original values in the original order, less GREASE values. This means SNI (0000) and ALPN (0010) are included. 

The raw fingerprint with the original ordering (-o) would look like this:
```
JA4_ro = t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601
```
When ‘-o’ flag is specified, ‘ja4’ field must be renamed to ‘ja4_o’:
```
JA4_o = t13d1516h2_acb858a92679_18f69afefd3d
```

```````
<!-- END VERBATIM JA4.md -->

### JA4H.md

Read at FoxIO commit `7ff7b3275a9d084ab6884559a6e58a9cee08f19d`, path
`technical_details/JA4H.md`.

<!-- BEGIN VERBATIM JA4H.md -->
```````
# JA4H: HTTP Client Fingerprint

![JA4H](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.png)

JA4H fingerprints the HTTP Client. Each client will have multiple fingerprints depending on what it’s doing. Clients will have different fingerprints when doing different HTTP Methods as well as different HTTP versions and will sometimes need to add fields depending on what the server tells it. However, the fingerprint will generally be the same per client per HTTP method and version save for cookie details. 

Each session is likely to have multiple JA4H’s, so each will be logged.

(2 character http method)  
(2 character http version)  
(“c” if cookie exists, “n” if no cookie or new connection)  
(“r” if referer exists, “n” if no referer or new connection)  
(2 character number of headers)  
(4 character first accept-language code)  
_  
(12 character truncated sha256 hash of the http header fields, in the order they are seen)  
_  
(12 character truncated sha256 hash of the cookie fields, sorted)  
_  
(12 character truncated sha256 hash of the cookie fields+values, sorted)  
```
Example JA4H: ge20cr13enus_a82fbf14bc42_457935509480_e97928733c74
```
2 Character HTTP Method:  
These are the HTTP methods available and their 2 character code to start the fingerprint:  
```
ge = GET  
he = HEAD  
op = OPTIONS  
tr = TRACE  
de = DELETE  
pu = PUT  
po = POST  
pa = PATCH  
co = CONNECT
```

2 Character HTTP Version:  
HTTP versions:  
```
10 = HTTP/1.0  
11 = HTTP/1.1  
20 = HTTP/2  
30 = HTTP/3  
```
If there is a Cookie in the HTTP header, the value is “c” for cookie.  
If there is not a Cookie in the HTTP header, the value is “n” for “n”o cookie or “n”ew connection

If there is a Referer in the HTTP header, the value is “r” for referer.  
If there is not a Referer in the HTTP header, the value is “n” for “n”o referer or “n”ew connection

2 character number of header fields. See below on capturing header fields. This ignores the cookie and referer header as that is captured above.  
06 = 6 headers  
99 = anything > than 100 headers

First 4 characters of the primary Accept-Language (ignore “-”):  
See https://www.iana.org/assignments/language-subtag-registry/language-subtag-registry  
This field can look like:  
```
Accept-Language: da, en-GB;q=0.8, en;q=0.7  
Accept-Language: en-US,en;q=0.9
```
The first value prior to the comma is the primary language of the client. JA4H captures this while ignoring the “-” character. Use 0s if less than 4 characters are used or if no accept-language field exists.

Example:  
```
da = da00  
en-US = enus  
en-UK = enuk  
ru-RU = ruru  
None = 0000
```

“_”

12 character truncated sha256 hash of the http headers:  
The http headers come after the http version code and start on new lines ending at a “:” JA4H captures all HTTP header fields, case-sensitive, but does not capture “Cookie” or “Referer” as as we’ve already captured them in the _a_ section of the fingerprint. These values are omitted so that the same application would have the same _b_ section of the fingerprint regardless of if it were a new connection or not. The fields are then concatenated with a “,” delimiter and sha256 hashed using the first 12 characters of the hash. 

So for:   
```
POST /plugins/unassigned.devices/UnassignedDevices.php HTTP/1.1
Host: 192.168.1.1
Content-Length: 664
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.1.1
Referer: http://192.168.1.1/Main
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: example=d7df2dd0937ec27; ud_reload=UD_reload
Connection: close
```
The headers captured are:
```
Host,Content-Length,Accept,X-Requested-With,User-Agent,Content-Type,Origin,Accept-Encoding,Accept-Language,Connection
```
(notice “Cookie” and “Referer” is omitted)
Sha256 hash:
```
47d05ed57293244a9b505865f749705e4e7fcbfee3780254b075f46433e51251
```
Truncated hash:
```
47d05ed57293
```

“_”

12 character truncated sha256 hash of the cookie fields, sorted:  
The cookie fields are the values before “=” and are delimited by “;”. JA4H captures these fields and concatenates them using a “,” delimiter and then performs a truncated sha256 hash of the string.

Example Cookie:
```
Cookie: 1P_JAR=2023-06-07-17; AEC=AUEFqZdaLLwaXJHyxA8-Cu0i0N4klp_vV3XOuyEYeiWlp4QaeIvSv6t4XKM; OGPC=19027681-1:; NID=511=rRELE2o91XNLo6eayqEN7Lf2ue7EcSHVkew3oxf4jzyF8vix2BzxTRvda8MYBFEkLyC1xjTcqSIjbC-wV2r120jr2HFau_dHvMxUm9fk6W2J2mddtlMpGMA8qGuAZWt1DSpCFFwHZSKBryGnvRJUeXkc-jw4sXdWhgCKxeu3f01Na4YsBYGf; DV=A84BtBIPqhgmIDlq9acmfs7ik-duiZjdmUPDG3eW3QIAAAA
```
Fields captured:
```
1P_JAR,AEC,OGPC,NID,DV
```
Sorted in alphabetical order:
```
1P_JAR,AEC,DV,NID,OGPC = 21864220ae3d
```

12 character truncated sha256 hash of the cookie fields+values, sorted:  
The cookie fields+values are now captured and sorted like above, using a “,” delimiter and then performing a truncated hash. This part of the fingerprint will be unique to each user but can allow for tracking of individual users through the application without the need to log SPII like username or session tokens.

Using the example above, we sort the cookie to:  
```
1P_JAR=2023-06-07-17,AEC=AUEFqZdaLLwaXJHyxA8-Cu0i0N4klp_vV3XOuyEYeiWlp4QaeIvSv6t4XKM,DV=A84BtBIPqhgmIDlq9acmfs7ik-duiZjdmUPDG3eW3QIAAAA,NID=511=rRELE2o91XNLo6eayqEN7Lf2ue7EcSHVkew3oxf4jzyF8vix2BzxTRvda8MYBFEkLyC1xjTcqSIjbC-wV2r120jr2HFau_dHvMxUm9fk6W2J2mddtlMpGMA8qGuAZWt1DSpCFFwHZSKBryGnvRJUeXkc-jw4sXdWhgCKxeu3f01Na4YsBYGf,OGPC=19027681-1:

Sha256: e97928733c7408285e0878640b946867e0a8fd0ac02765ad48a375220296a5e3
Truncated: e97928733c74
```

## JA4H Example:

So for:
```
GET /public/api/alerts HTTP/2
Host: www.cnn.com
Cookie: FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726
Sec-Ch-Ua: 
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36
Sec-Ch-Ua-Platform: ""
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.cnn.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```
Headers:
```
Host,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language
```
Cookie:
```
Unsorted: FastAB,sato,countryCode,stateCode,geoData,usprivacy,umto,_dd_s
Sorted: FastAB,_dd_s,countryCode,geoData,sato,stateCode,umto,usprivacy
```
ge (HTTP Method)
20 (HTTP Version)
c (There’s a cookie)
r (There’s a referer)
11 (13 header fields minus Cookie and Referer as those are accounted for above)
enus (Accept-Language)
_
974ebe531c03 (hash of http header fields)
_
b66fa821d02c (hash of sorted cookie fields)
_
e97928733c74 (hash of the sorted cookie fields+values)
```
JA4H=ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74
```

## Raw Output
The program should allow for raw outputs either sorted or original.  
-r (raw fingerprint) -o (original)

The raw fingerprint for JA4H would look like this:
```
JA4H_r = ge20cr13enus_Host,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language_FastAB,_dd_s,countryCode,geoData,sato,stateCode,umto,usprivacy_FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929,_dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726,countryCode=US,geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511,sato=1,stateCode=VA,umto=1,usprivacy=1---
```

The "o" option includes the original values in the original order. This means Cookie and Referer are now included in the _b_ section of the fingerprint if present.

The raw fingerprint with original (-o) would look like this:
```
JA4H_ro = ge20cr13enus_Host,Cookie,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Referer,Accept-Encoding,Accept-Language_FastAB,sato,countryCode,stateCode,geoData,usprivacy,umto,_dd_s_FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929,sato=1,countryCode=US,stateCode=VA,geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511,usprivacy=1—,umto=1,_dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726
```
```````
<!-- END VERBATIM JA4H.md -->

### JA4L.md

Read at FoxIO commit `7ff7b3275a9d084ab6884559a6e58a9cee08f19d`, path
`technical_details/JA4L.md`.

<!-- BEGIN VERBATIM JA4L.md -->
```````
# JA4L: Light Distance

![JA4L](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.png)

JA4L measures the light distance/latency between the first few packets in a connection. We use the first few packets as these are low-level machine generated so there is nearly zero processing delay in creating and sending these packets. This essentially measures the estimated distance between the client and server. Time is measured in microseconds (µs). 1ms = 1000µs. Microseconds are a standard unit of time measurement in packet captures.

If the packet capture/program is running server side, this will measure the distance of the client from the server and if this is running client side, this will measure the distance of the server from the client. If this is running on a network tap, it will measure the distance of each from the network tap location.

JA4L is split up into 2 measurements, client and server. For TCP, these are determined by looking at the TCP 3-way handshake. UDP, we’re looking at the QUIC handshake.

### TCP:

In the TCP 3-way handshake, first the client sends a SYN packet. The timestamp that the syn packet is seen is captured by the program as value “A”. Additionally, the IP TTL from the client is captured.

Then the server responds with a SYN ACK packet. The timestamp of that packet is value “B”. Additionally, the IPv4 TTL or IPv6 Hop Count from the server is captured.

Then the client will respond with an ACK packet, thus completing the TCP 3-way handshake. The timestamp of that packet is value “C”
```
JA4L-C = {(C - B) / 2}_Client TTL
JA4L-S = {(B - A) / 2}_Server TTL
```
Example:  
```
JA4L-C = 11_128  
JA4L-S = 1759_42  
```
### QUIC:
QUIC setup spans several packets.

1. Client sends an Initial QUIC Packet. This timestamp is “A”  
2. Server responds with its Initial QUIC Packet. This timestamp is “B”  
3. Server sends several handshake packets to the client. This could be 1 - 5 packets depending on the server, these are ignored.  
4. The last packet from the server before the client sends a packet is “C”  
5. Client’s 2nd packet, the handshake packet, is “D”  
```
JA4L-C = { (D - C) / 2 }_Client TTL  
JA4L-S = { (B - A) / 2 }_Server TTL
```
## Measuring Distance and Location

With JA4L we can determine the distance between the client and server using this formula:  
_D = jc/p_

D = Distance  
j = JA4L_a  
c = Speed of light per µs in fiber (0.128 miles/µs or 0.206km/µs)
p = Propagation delay factor  

Typical propagation delay depends on terrain and how many networks are involved.  
Poor terrain factor = 2 (around mountains, water)  
Good terrain factor = 1.5 (along highway, under sea cables)  
SpaceX factor = … needs to be tested  

We can use the TTL to calculate the hop count, which can help inform the propagation delay factor. (The table below is a good starting point but more testing needs to be done.)

| Hop Count | Propagation Delay Factor |
|----------|-----------|
| <= 21 | 1.5 |
| 22 | 1.6 |
| 23 | 1.7 |
| 24 | 1.8 |
| 25 | 1.9 |
| >=26 | 2.0 |

To calculate the number of hops a connection went through, subtract the TTL from its estimated initial TTL.

Cisco, F5, most networking devices use a TTL of 255  
Windows uses a TTL of 128  
Mac, Linux, phones, and IoT devices use a TTL of 64

Most routes on the Internet have less than 64 hops. Therefore if the observed TTL, JA4L_b, is <64, the estimated initial TTL is 64. Within 65-128, the estimated initial TTL is 128. And if the TTL is >128 then the estimated initial TTL is 255.

With a JA4L-S of 2449_42, the observed TTL of 42 means the initial TTL was likely 64, a Linux server. 64-42 gives us a hop count of 22.

2449x0.128/1.6=195  
We can conclude that this server is within 195 miles of the client. The server may be closer than this, but it is physically impossible for it to be farther away as the speed of light is constant. If there are multiple JA4Ls for the same host, the lowest value should be taken as the most accurate. 
In this example, the actual distance was 194 miles.

Utilizing multiple locations, one can passively triangulate the physical location of any client or server down to a city area. 

```````
<!-- END VERBATIM JA4L.md -->

### JA4S.md

Read at FoxIO commit `7ff7b3275a9d084ab6884559a6e58a9cee08f19d`, path
`technical_details/JA4S.md`.

<!-- BEGIN VERBATIM JA4S.md -->
```````
# JA4S: TLS Server/Session Fingerprint

![JA4S](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.png)

JA4S Algorithm:  
(q or t)  
(2 character tls version)  
(2 character number of extensions)  
(first and last character of the ALPN chosen)  
_  
(cipher suite chosen in hex)  
_  
(truncated sha256 hash of the extensions in the order that they appear)

In the Server Hello packet, there is always a single cipher, the cipher that the server chose to communicate in. So with JA4S, we don’t need to count the number of ciphers or hash them, instead we can just show the cipher chosen. Also with Server Hellos, the extensions are not being randomized, that means we can hash those in the order they are seen rather than sorting them.

An example where the extensions are: 0005,0017,ff01,0000  
Sha256: 4e8089b08790aebafde4a993a4e554d9ed0fff21124965a9e91beabf80879946  
Truncated to the first 12 characters: 4e8089b08790 

JA4S Example:  
t (TLS over TCP)  
12 (no supported versions extension here so this is x0303, TLS 1.2)  
04 (4 extensions)  
00 (first and last character of the ALPN chosen by the server, 00 here as there’s no ALPN extension)  
_  
c030 (the cipher suite chosen by the server in hex)  
_  
4e8089b08790 (truncated sha256 hash of the extensions in the order they were seen)
```
JA4S = t120400_c030_4e8089b08790 
```
### Raw Output
The program should allow for raw outputs. JA4S doesn’t sort so -o does nothing here.
-r (raw fingerprint)

The raw fingerprint for JA4S would look like this:
```
JA4S_r = t120400_c030_0005,0017,ff01,0000
```
```````
<!-- END VERBATIM JA4S.md -->

### JA4SSH.md

Read at FoxIO commit `7ff7b3275a9d084ab6884559a6e58a9cee08f19d`, path
`technical_details/JA4SSH.md`.

<!-- BEGIN VERBATIM JA4SSH.md -->
```````
# JA4SSH: SSH Traffic Fingerprint

![JA4SSH](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.png)

Runs every n packets per SSH TCP stream. n = 200 by default but is configurable. So by default JA4SSH is running every 200 packets per SSH TCP stream. This means each SSH stream will have multiple JA4SSH results.

### JA4SSH:  
c(mode of client TCP payload length)  
s(mode of server TCP payload length)  
_  
c(total ssh packets sent from client)  
s(total ssh packets sent from server)  
_  
c(ack packets seen from client)  
s(ack packets seen from server)
```
Example JA4SH = c36s36_c55s75_c70s0
```
### How to measure the mode for TCP payload lengths across 200 packets in the session:

Reminder: We’re looking at the TCP payload lengths, not the packet length. In wireshark this is under “tcp.len”. And this is only for SSH (layer 7) packets. This does not include TCP ACK packets or other layer 4 packets.

We’re looking for the mode, or the value that appears the most number of times in the data set, not the mean or median.

So if 36 bytes appear 20 times, and 128 bytes appear 10 times and 200 bytes appear 15 times, the mode is 36. If there is a collision, the program choses the smaller byte value.

JA4SSH calculates this for both the client and server separately.

### Counting the SSH packets:

JA4SSH counts the number of SSH (layer 7) packets sent from the client and server separately. This does not include ACK packets, TCP replays or any other layer 4 packets. 

### Counting the ACK packets:

JA4SSH counts the number of bare TCP ACK packets sent from the client and server separately.

### Example JA4SSH:
c36 (36 bytes was the mode for ssh packet lengths sent from client)
s36 (36 bytes was the mode for ssh packet lengths sent from server)
_
c55 (55 SSH packets were sent from the client)
s75 (75 SSH packets were sent from the server)
_
c70 (70 ack packets were sent from the client)
s0 (0 ack packets were sent from the server)
```
JA4SSH = c36s36_c55s75_c70s0
```

Forward SSH shell (notice the ACKs come from the client):
```
JA4SSH = c36s36_c51s80_c69s0
```
Reverse SSH shell (notice the ACKs come from the server):
```
JA4SSH = c76s76_c71s59_c0s70
```
SCP file transfer (always c112s1460):
```
JA4SSH = c112s1460_c0s179_c21s0
```
```````
<!-- END VERBATIM JA4SSH.md -->

### JA4T.md

Read at FoxIO commit `7ff7b3275a9d084ab6884559a6e58a9cee08f19d`, path
`technical_details/JA4T.md`.

<!-- BEGIN VERBATIM JA4T.md -->
```````
# JA4T: TCP Fingerprint

![JA4T](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.png)

| Full Name | Short Name | Decription |
|-------|-------|------|
JA4TCP | JA4T | TCP Client Fingerprint |
JA4TCPServer | JA4TS | TCP Server Response Fingerprint |
JA4TCPScan | JA4TScan | Active TCP Server Fingerprint Scanner |

JA4T fingerprints the TCP SYN packet sent from the client.  
JA4TS fingerprints the TCP SYN ACK response packet(s) sent from the server.  
JA4TScan fingerprints servers by envoking TCP retransmissions.

These methods are inspired by:  
p0f - Michał Zalewski - last update 2014  
hershel+ - Zain Shamsi & Dmitri Loguinov - last update 2018  
gait - Charles Smutz & Brandon A. Thomas - active zeek scipts

The goal of JA4T/S/Scan was to make a small and extemely useful TCP fingerprint that does not require a database, that is easy to eyeball and pivot on in hunting and log analysis. Each OS, device, and some applications have their own TCP fingerprint, their own way of using the TCP stack. And differences in Window Size and Maximum Segment Size can provide clues as to the network characteristics.

JA4T Examples:

| OS/Device/Application | JA4T |
|----|----|
| Windows 10 | 64240_2-1-3-1-1-4_1460_8 |
| WSL Ubuntu on Windows 10 | 64240_2-4-8-1-3_1460_7 |
| Ubuntu 22.04 | 65535_2-4-8-1-3_1460_8 |
| Amazon AWS Linux 2 | 62727_2-4-8-1-3_8961_7 |
| Mac OSX / iPhone | 65535_2-1-3-1-1-8-4-0-0_1460_6 |
| Nmap | 1024_2_1460_00 |
| Zmap | 65535_00_00_00 |
| Web Scanner | 1024_00_00_00 |

JA4TScan Examples:

| OS/Device/Application | JA4TScan |
|-----|-----|
| Windows 10 | 64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6 |
| Windows 2003 | 16384_2-1-3-1-1-8-1-1-4_1460_00_2-7 |
| Amazon AWS Linux 2 | 62727_2-4-8-1-3_8961_7_1-2-4-8-16 |
| Mac OSX / iPhone | 65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12 |
| F5 Big IP | 4380_2-1-3-1-1-8-1-1-4_1460_1_3-6 |
| HP ILO | 5840_2_1460_00_3-6-12-24-48-60-60-60-60-60 |
| Epson Printer | 28960_2-4-8-1-3_1460_3_1-4-8-16 |

![exampleja4t1](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/exampleja4t1.PNG)

__JA4T Fingerprint format:__

WindowSize_TCPOptions_MSSValue_WindowScale

The TCP Window Size is captured in decimal, 64240 in the example screenshot.

TCP options are limited to 1 byte. List to TCP options (kinds): https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml Most modern operating systems use TCP options 2,3,4, and 8. Some specific devices will use options up to 255. Option 1 is used to pad the options to be divisible by 4 and option 0 is sometimes used to denote the end of the options list.

In the above screenshot example, we have options 2,1,3,1,1,4. These would be captured as their decimal values, hyphen delimited:  
2-1-3-1-1-4

The MSS value is captured in Decimal. In the above example, the MSS value is 1460.

The Window scale is captured in Decimal as well. In the above example, the Window scale is 8.

If any field does not exist, then the output is 00. For example, a packet with a Window of 1024 and no TCP options, and therefore no Window scale would be:
JA4T = 1024_00_00_00

Using the above screenshot example:

JA4T = 64240_2-1-3-1-1-4_1460_8

__JA4TS and JA4TScan Fingerprint formats:__

WindowSize_TCPOptions_MSSValue_WindowScale_TimeSinceLastSYNACK  
a_b_c_d_e

JA4TS takes into account the number of SYNACK TCP Retransmissions, or RST, as well as the time delay between each retransmission or RST. Different OS/Devices will retransmit a different amount of times and at different intervals.

If no retransmissions are seen, as there shouldn't be in normal network communications, the fingerprint will omit section e. If retransmissions are seen, the fingerprint will fill out section e.

Note that the JA4TS is dependant on the JA4T that was sent to it. If, for example, a client sent a SYN packet with no TCP options, the server will respond with a SYN ACK with no TCP options. That is NOT the TCP fingerprint of the server, but is a fingerprint of the server's response.

JA4TScan is a tool that sends a very specific SYN packet and then listens to all SYN ACK responses. This DOES build out a TCP fingerprint of the server, similar to how JARM works for TLS servers.

![exampleja4t2](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/exampleja4t2.PNG)

In the above example, there are 5 TCP retransmissions with different delays between them. To find the delay between them we start with the timestamp of the first SYNACK and subtract it from the next SYNACK, rounding the result to the nearest whole number in seconds. In the above example:

1. 15.621983  
2. 16.626151 - 15.621983 = 1.004 = 1  
3. 18.642179 - 16.626151 = 2.016 = 2  
4. 22.738154 - 18.642179 = 4.096 = 4  
5. 30.930163 - 22.738154 = 8.192 = 8  
6. 47.058146 - 30.930163 = 16.128 = 16  

Thereby JA4TS builds out the fingerprint as follows:

1. 62727_2_8961_00  
2. 62727_2_8961_00_1  
3. 62727_2_8961_00_1-2  
4. 62727_2_8961_00_1-2-4  
5. 62727_2_8961_00_1-2-4-8  
6. 62727_2_8961_00_1-2-4-8-16  

With 62727_2_8961_00_1-2-4-8-16 being the final fingerprint in this example.

Because it is not known when the last retransmission will come in, a timeout is requred as to not fill up state tables. The max is 10 retransmissions counted and the timeout is 2 minutes after the last SYNACK.

Some systems will send several SYNACK retransmissions and just stop while others will send a RST (reset) after a few retransmissions. For example:

![exampleja4t3](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/exampleja4t3.PNG)

In this case, the final TCP packet, a RST packet, should be appended to the last JA4TS denoted with “R” and its delay. In the above example:

1. 16.681435  
2. 17.683799 - 16.681435 = 1.002 = 1  
3. 19.691548 - 17.683799 = 2.008 = 2  
4. 23.703045 - 19.691548 = 4.011 = 4  
5. 31.714762 - 23.703045 = 8.012 = 8  
6. RST 37.723966 - 31.714762 = RST 6.009 = R6

Thereby the JA4TS fingerprints for each SYN ACK in order would be:

1. 65535_2-1-3-1-1-4_65495_8  
2. 65535_2-1-3-1-1-4_65495_8_1  
3. 65535_2-1-3-1-1-4_65495_8_1-2  
4. 65535_2-1-3-1-1-4_65495_8_1-2-4  
5. 65535_2-1-3-1-1-4_65495_8_1-2-4-8  
6. 65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6

With 65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6 being the final fingerprint of the server.

Note that RST packets do not contain TCP options or window sizes, as such the program will need to be aware of the previous JA4TS. 

```````
<!-- END VERBATIM JA4T.md -->

### JA4X.md

Read at FoxIO commit `7ff7b3275a9d084ab6884559a6e58a9cee08f19d`, path
`technical_details/JA4X.md`.

<!-- BEGIN VERBATIM JA4X.md -->
```````
# JA4X: X509 TLS Certificate Fingerprint
Credit: W.

![JA4X](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.png)

JA4X looks at the TLS certificate (X500/X509/X520). These certificates are encrypted in TLS 1.3 but are sent in clear text in TLS 1.2. This fingerprint can identify the application that was used to generate the certificate. This fingerprint may be used best in scanning and identifying connections to certain self signed certs as well as a pivot point in hunting.

(12 character truncated sha256 of the Issuer RDNs in the order they are seen)
_
(12 character truncated sha256 of the Subject RDNs in the order they are seen)
_
(12 character truncated sha256 of the extensions in the order they are seen)
```
Example JA4X = 96a6439c8f5c_96a6439c8f5c_aae71e8db6d7
```

When truncating SHA256 we are using the first 12 characters.

We use only the hex values for the RDNs, comma separated, to build out the fingerprint string. As an example: 
```
Issuer = 550403,550406,550408,55040a = 96a6439c8f5c
Subject = 550403,550406,550408,55040a = 96a6439c8f5c
Extensions = 551d0f,551d25,551d11 = aae71e8db6d7

JA4X = 96a6439c8f5c_96a6439c8f5c _aae71e8db6d7
```
## Raw Output
The program should allow for raw outputs. JA4X doesn’t sort so -o does nothing here.
-r (raw fingerprint)

The raw fingerprint for JA4 would look like this:
```
JA4X_r = 550403,550406,550408,55040a_550403,550406,550408,55040a_551d0f,551d25,551d11
```
```````
<!-- END VERBATIM JA4X.md -->
