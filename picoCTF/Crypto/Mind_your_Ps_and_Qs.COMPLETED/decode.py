#!/usr/bin/env python3

import requests
#import beautifulsoup4

url = "https://www.dcode.fr/api/"

rsa_data = {'tool':'rsa-cipher'}
with open('values') as file:
	data = file.readlines()
	for d in data:
		s = d.strip().split(':')
		s = list(filter(None,s))
		if len(s) > 1:
			rsa_data[s[0]] = s[1]


# Doesn't work because of captcha
r = requests.post(url, data=rsa_data)

print(r.text)