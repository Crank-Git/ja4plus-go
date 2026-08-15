# seed-fuzz-reduce.awk builds one protocol record from the identifiers of a captured
# record. `scripts/seed-fuzz.sh` states the reduction and states why the output carries no
# FoxIO license obligation.
#
# The program reads the hexadecimal bytes of one classic pcap file, one byte per field.
# `kind` selects the record: `clienthello`, `serverhello` or `http`. The program writes the
# bytes of the new record as `\xNN` escapes, and it exits 1 when the file holds no such
# record.
#
# The program copies no byte of the capture. It reads the version, the cipher suite
# identifiers, the extension identifiers, the HTTP method and the HTTP header names. Every
# other field of the output holds a fixed filler.

function hv(s,   c, v, i) {
	v = 0
	for (i = 1; i <= length(s); i++) {
		c = index("0123456789abcdef", substr(s, i, 1))
		v = v * 16 + (c - 1)
	}
	return v
}

function le32(o) { return b[o] + b[o+1] * 256 + b[o+2] * 65536 + b[o+3] * 16777216 }
function be16(o) { return b[o] * 256 + b[o+1] }

function ob(v) { out[m++] = v % 256 }
function ob16(v) { ob(int(v / 256)); ob(v) }
function ob24(v) { ob(int(v / 65536)); ob(int(v / 256)); ob(v) }
function obs(s,   i) { for (i = 1; i <= length(s); i++) ob(index(ASCII, substr(s, i, 1)) + 31) }

BEGIN { n = 0 }

{ for (i = 1; i <= NF; i++) { b[n] = hv($i); n++ } }

END {
	ASCII = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	if (n < 24 || b[0] != 212 || b[1] != 195) { exit 1 }

	linktype = le32(20)
	if (linktype != 1 && linktype != 0) { exit 1 }
	off = 24
	while (off + 16 <= n) {
		incl = le32(off + 8)
		p = off + 16
		off = p + incl
		if (off > n) { break }

		if (linktype == 1) {
			if (be16(p + 12) != 2048) { continue }
			ip = p + 14
		} else {
			if (b[p] != 2) { continue }
			ip = p + 4
		}
		if (int(b[ip] / 16) != 4) { continue }
		if (b[ip + 9] != 6) { continue }

		iplen = be16(ip + 2)
		ihl = (b[ip] % 16) * 4
		tcp = ip + ihl
		pay = tcp + int(b[tcp + 12] / 16) * 4
		end = ip + iplen
		if (end > p + incl) { end = p + incl }
		if (pay >= end) { continue }

		if (kind == "clienthello" && b[pay] == 22 && b[pay + 5] == 1) { if (tls(pay, end, 1)) { emit(); exit 0 } }
		if (kind == "serverhello" && b[pay] == 22 && b[pay + 5] == 2) { if (tls(pay, end, 2)) { emit(); exit 0 } }
		if (kind == "http" && http(pay, end)) { emit(); exit 0 }
	}
	exit 1
}

# tls reads the version, the cipher suites and the extension identifiers of one
# handshake record, then it builds a new record from those numbers alone.
function tls(pay, end, want,   body, o, sl, cl, i, cnt, ids, el, et, extend, ext, ec, ver) {
	body = pay + 9
	o = body + 34
	if (o >= end) { return 0 }
	ver = be16(body)
	sl = b[o]
	o = o + 1 + sl
	if (o + 2 > end) { return 0 }

	cnt = 0
	if (want == 1) {
		cl = be16(o)
		o = o + 2
		if (o + cl > end) { return 0 }
		for (i = 0; i < cl; i = i + 2) { cipher[cnt] = be16(o + i); cnt++ }
		o = o + cl
		if (o >= end) { return 0 }
		o = o + 1 + b[o]
	} else {
		cipher[0] = be16(o)
		cnt = 1
		o = o + 3
	}
	ncipher = cnt

	next_ext = 0
	if (o + 2 <= end) {
		el = be16(o)
		o = o + 2
		extend = o + el
		if (extend > end) { extend = end }
		while (o + 4 <= extend) {
			extid[next_ext] = be16(o)
			next_ext++
			o = o + 4 + be16(o + 2)
		}
	}
	# Build the extension block.
	ec = 0
	for (i = 0; i < next_ext; i++) {
		et = extid[i]
		if (et == 0) { ext[ec++] = 0; ext[ec++] = 0; ext[ec++] = 0; ext[ec++] = 20
			ext[ec++] = 0; ext[ec++] = 18; ext[ec++] = 0; ext[ec++] = 0; ext[ec++] = 15
			ec = adds(ext, ec, "example.invalid")
		} else if (et == 16) { ext[ec++] = 0; ext[ec++] = 16; ext[ec++] = 0; ext[ec++] = 5
			ext[ec++] = 0; ext[ec++] = 3; ext[ec++] = 2
			ec = adds(ext, ec, "h2")
		} else if (et == 43 && want == 1) { ext[ec++] = 0; ext[ec++] = 43; ext[ec++] = 0; ext[ec++] = 5
			ext[ec++] = 4; ext[ec++] = 3; ext[ec++] = 4; ext[ec++] = 3; ext[ec++] = 3
		} else if (et == 43) { ext[ec++] = 0; ext[ec++] = 43; ext[ec++] = 0; ext[ec++] = 2
			ext[ec++] = 3; ext[ec++] = 4
		} else if (et == 13 && want == 1) { ext[ec++] = 0; ext[ec++] = 13; ext[ec++] = 0; ext[ec++] = 6
			ext[ec++] = 0; ext[ec++] = 4; ext[ec++] = 4; ext[ec++] = 3; ext[ec++] = 8; ext[ec++] = 4
		} else { ext[ec++] = int(et / 256); ext[ec++] = et % 256; ext[ec++] = 0; ext[ec++] = 0 }
	}
	nextb = ec

	# Build the handshake body.
	m = 0
	ob16(ver)
	for (i = 0; i < 32; i++) { ob(0) }
	ob(0)
	if (want == 1) { ob16(ncipher * 2) }
	for (i = 0; i < ncipher; i++) { ob16(cipher[i]) }
	if (want == 1) { ob(1); ob(0) } else { ob(0) }
	ob16(nextb)
	for (i = 0; i < nextb; i++) { ob(ext[i]) }

	for (i = 0; i < m; i++) { hs[i] = out[i] }
	hslen = m

	m = 0
	ob(22); ob(3); ob(1); ob16(hslen + 4)
	ob(want); ob24(hslen)
	for (i = 0; i < hslen; i++) { ob(hs[i]) }
	return 1
}

function adds(a, c, s,   i) {
	for (i = 1; i <= length(s); i++) { a[c] = index(ASCII, substr(s, i, 1)) + 31; c++ }
	return c
}

# http reads the method and the header names of one request, then it builds a new
# request from those names alone.
function http(pay, end,   i, line, ch, method, names, cnt, j, c) {
	line = ""
	for (i = pay; i < end && i < pay + 2048; i++) {
		c = b[i]
		if (c == 13) { continue }
		if (c < 9 || c > 126) { return 0 }
		line = line sprintf("%c", c)
	}
	if (line !~ /^(GET|POST|HEAD|PUT|OPTIONS|DELETE) [^ ]+ HTTP\/1\.[01]\n/) { return 0 }
	cnt = split(line, L, "\n")
	sub(/ .*/, "", L[1])
	method = L[1]
	names = ""
	for (j = 2; j <= cnt; j++) {
		if (L[j] == "") { break }
		if (L[j] !~ /^[A-Za-z0-9-]+:/) { continue }
		sub(/:.*/, "", L[j])
		names = names L[j] "\n"
	}
	if (names == "") { return 0 }

	m = 0
	obs(method); obs(" /a HTTP/1.1"); ob(13); ob(10)
	cnt = split(names, N, "\n")
	for (j = 1; j <= cnt; j++) {
		if (N[j] == "") { continue }
		obs(N[j]); obs(": x"); ob(13); ob(10)
	}
	ob(13); ob(10)
	return 1
}

function emit(   i) {
	for (i = 0; i < m; i++) { printf "\\x%02x", out[i] }
	printf "\n"
}
