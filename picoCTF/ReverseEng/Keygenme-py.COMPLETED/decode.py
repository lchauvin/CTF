#!/usr/bin/env python3

import hashlib

username_trial = b"ANDERSON"

key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial


key_static_decode = []
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[4])
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[5])
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[3])
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[6])
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[2])
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[7])
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[1])
key_static_decode.append(hashlib.sha256(username_trial).hexdigest()[8])

print(key_part_static1_trial + ''.join(key_static_decode) + key_part_static2_trial)
