#!/usr/bin/env python3

import requests

url = 'http://10.10.16.71/xmlrpc.php'

xml="""
<?xml version="1.0" encoding="utf-8"?>
<methodCall>
	<methodName>system.listMethods</methodName>
	<params></params>
</methodCall>"""

headers = {'Content-Type': 'application/xml'} 

s = requests.post(url, data=xml)

print(s)
