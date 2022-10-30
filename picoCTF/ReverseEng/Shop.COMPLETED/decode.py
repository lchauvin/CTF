#!/usr/bin/env python3

encoded_flag = [112,105,99,111,67,84,70,123,98,52,100,95,98,114,111,103,114,97,109,109,101,114,95,53,51,50,98,99,100,57,56,125]

decoded_flag = []

for e in encoded_flag:
	decoded_flag.append(chr(e))

print(''.join(decoded_flag))
