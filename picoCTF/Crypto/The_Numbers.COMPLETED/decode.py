#!/usr/bin/env python3

import string

sequence = [16,9,3,15,3,20,6,20,8,5,14,21,13,2,5,18,19,13,1,19,15,14]
alphabet = string.ascii_lowercase

flag = []
for s in sequence:
	flag.append(alphabet[s-1])

print(''.join(flag))