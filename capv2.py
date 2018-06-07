import sys
import pyshark
import socket

tokens = ['password', 'pw', 'pass']

pwdict = {} #will store occurrences of passwords

dict={} #will store the number occurrences of hosts
ipdict={} #will store the IPs of the hosts

#checks if there is a password in a string
def containsPassword(string):
	for i in tokens:
		if string.find(i) >= 0:
			return True
	return False

#analyses the packet
def host_statistic(pkt):
	try:
		dst_addr=pkt.ip.dst
		
		#getting and storing the password, if any
		data = pkt.http.get_field_value('file_data')
		if containsPassword(data):
			variables = data.split("&")
			for pair in variables:
				varpair = pair.split("=")
				if containsPassword(varpair[0]):
					if varpair[1] in pwdict.keys():
						pwdict[varpair[1]] += 1
					else:
						pwdict[varpair[1]] = 1
		
		
		#getting the hostname; if can't use the IP address instead
		try:
			hostname = pkt.http.get_field_value('host')
		except socket.herror:
			hostname = dst_addr
		
		#a new occurrence found; logging
		if hostname in dict.keys():
			dict[hostname] += 1 
		else:
			dict[hostname] = 1
		
		#log the IP for the hostname
		if hostname not in ipdict.keys():
			ipdict[hostname] = dst_addr
	except AttributeError as e:
		print(e)
		pass
      
        


if len(sys.argv) == 1:
	print('Add meg a fájlnevet!')
else:
	cap = pyshark.FileCapture(sys.argv[1], display_filter = 'http') #loading all http packets from file
	cap.apply_on_packets(host_statistic,timeout=100) #analyzing every packet
	
	#sorting and printing hosts
	print("Top hosts connected to:")
	while True:
		maxnumber = -1
		maxhost = ""
		for i in dict.keys():
			if maxnumber < dict[i]:
				maxnumber = dict[i]
				maxhost = i
		if maxnumber > -1:
			print(str(maxnumber) + "\t" + str(ipdict[maxhost]) + "\t" + maxhost)
		else:
			break
		dict[maxhost] = -1
	
	#separating outputs
	print("\nPasswords used:")
	
	#printing password statistics
	for pw in pwdict.keys():
		print(str(pwdict[pw]) + "\t" + pw)
