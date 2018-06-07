#!/usr/bin/env python3
import sys
import pyshark

if len(sys.argv) == 1:
	print('Add meg a fájlnevet!')
else:
	cap = pyshark.FileCapture(sys.argv[1], display_filter='http && http.request.method == "POST"')
	tokens = ['password', 'pw', 'pass']

	for i in cap:
		try:
			uri = i.http.get_field_value('request_full_uri')
			data = i.http.get_field_value('file_data')
			if any(token in data for token in tokens):
				print('URL:', uri, '\nData:', data, '\n')
		except:
			pass

