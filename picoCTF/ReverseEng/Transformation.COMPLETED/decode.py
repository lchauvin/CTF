#!/usr/bin/env python3

import os

with open('enc') as f:
	encoded_flag = f.read()

# Original encoding
#''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

# Decode
decoded_flag = []
for char in encoded_flag:
	decoded_flag.append(chr(ord(char) >> 8))
	decoded_flag.append(chr(ord(char) - ((ord(char) >> 8) << 8)))

print(''.join(decoded_flag))
