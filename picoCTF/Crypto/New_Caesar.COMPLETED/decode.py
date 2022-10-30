#!/usr/bin/env python3

import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

# We saw the key is length 1, among the first 16 letters of the lowercase alphabet (easy to bruteforce)
#   ALPHABET = string.ascii_lowercase[:16]
#   assert all([k in ALPHABET for k in key])
#   assert len(key) == 1

def b16_decode(encoded):
	dec = ""
	for i in range(0,len(encoded), 2):
		p1 = ALPHABET.index(encoded[i])
		p2 = ALPHABET.index(encoded[i+1])

		dec += chr((p1 << 4) + p2)
	return dec

def unshift(c, k):
	return ALPHABET[(int(c)-int(k))%len(ALPHABET)]

encoded_flag = 'apbopjbobpnjpjnmnnnmnlnbamnpnononpnaaaamnlnkapndnkncamnpapncnbannaapncndnlnpna'

for k in ALPHABET:
	flag_unshifted = ""
	for c in encoded_flag:
		flag_unshifted += unshift(ALPHABET.index(c),ALPHABET.index(k))
	
	flag = b16_decode(flag_unshifted)
	if flag.isprintable():
		print(f"key: {k}: {flag}")