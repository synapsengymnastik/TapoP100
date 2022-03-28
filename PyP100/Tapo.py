

import requests
from requests import Session

from base64 import b64encode, b64decode
import hashlib
from Crypto.PublicKey import RSA
import time
import json
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5

import ast
import pkgutil
import uuid

import logging

import pkcs7
import base64

import socket



class Tapo():
    
	ERROR_CODES = {
	"0": "Success",
	"3": "Invalid IP",
	"4": "Decryption failed",
	"5": "Wrong Command !",
	"6": "ConnectionRoutine Error",
	"200": "Response OK",
	"-1010": "Invalid Public Key Length",
	"-1012": "Invalid terminalUUID",
	"-1501": "Invalid Request or Credentials",
	"1002": "Incorrect Request",
	"-1003": "JSON formatting error",
	"-1008": "ERR_PARAMS"
	}   
 
	def __init__ (self, ipAddress, email, password):
		self.ipAddress = ipAddress
		self.terminalUUID = str(uuid.uuid4())
		self.email = email
		self.password = password
		self.session = Session()
		self.errorCodes = self.ERROR_CODES
  
# translate Errorcode into Message
	def ErrorCheck(self, decryptedResponse):

		errorCode = decryptedResponse["error_code"]

		errorMessage = self.errorCodes[str(errorCode)]
		return (f"Error Code: {errorCode} : {errorMessage}")


# check if IP is valide
	def IPCheck(self):
		try:
			socket.inet_aton(self.ipAddress)
			return {'error_code': 0}
		except socket.error:
			return {'error_code': 3}		
    
    
# Helper
	@staticmethod
	def mime_encoder(to_encode: bytes):
		encoded_list = list(base64.b64encode(to_encode).decode("UTF-8"))

		count = 0
		for i in range(76, len(encoded_list), 76):
			encoded_list.insert(i + count, '\r\n')
			count += 1
		return ''.join(encoded_list)

	def encrypt(self, data):
		data = pkcs7.PKCS7Encoder().encode(data)
		data: str
		cipher = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
		encrypted = cipher.encrypt(data.encode("UTF-8"))
		return self.mime_encoder(encrypted).replace("\r\n","")

	def decrypt(self, data: str):
		aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
		pad_text = aes.decrypt(base64.b64decode(data.encode("UTF-8"))).decode("UTF-8")
		return pkcs7.PKCS7Encoder().decode(pad_text)		

	def sha_digest_username(self, data):
		b_arr = data.encode("UTF-8")
		digest = hashlib.sha1(b_arr).digest()

		sb = ""
		for i in range(0, len(digest)):
			b = digest[i]
			hex_string = hex(b & 255).replace("0x", "")
			if len(hex_string) == 1:
				sb += "0"
				sb += hex_string
			else:
				sb += hex_string

		return sb


# Token, Keys, Cookies........
	def handshake(self):
    
		self.keys = RSA.generate(1024)
		self.privateKey = self.keys.exportKey("PEM")
		self.publicKey = self.keys.publickey().exportKey("PEM")
  
		URL = f"http://{self.ipAddress}/app"
		Payload = {"method":"handshake", "params":{"key": self.publicKey.decode("utf-8"), "requestTimeMils": int(round(time.time() * 1000))}}

		r = self.session.post(URL, json=Payload, timeout=2)
		# <Response [200]>
  
		if r.status_code != 200:
			#return '{"error_code": %s}' % r.status_code
			return {'error_code': r.status_code}

		#r = <Response [200]>	
		# r.json(): {'error_code': 0, 'result': {'key': 'XXXX}}
		encryptedKey = r.json()["result"]["key"]
		
		decode: bytes = b64decode(encryptedKey.encode("UTF-8"))
		decode2: bytes = self.privateKey

		cipher = PKCS1_v1_5.new(RSA.importKey(decode2))
		do_final = cipher.decrypt(decode, None)
		if do_final is None:
			#return '{"error_code": 4}'
			return {'error_code': 4}

		b_arr:bytearray = bytearray()
		b_arr2:bytearray = bytearray()

		for i in range(0, 16):
			b_arr.insert(i, do_final[i])
		for i in range(0, 16):
			b_arr2.insert(i, do_final[i + 16])

		self.iv = b_arr2
		self.key = b_arr

		try:
			# r.header: {'Content-Type': 'application/json;charset=UTF-8', 'Set-Cookie': 'TP_SESSIONID=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;TIMEOUT=1440', 'Server': 'SHIP 2.0', 'Content-Length': '208', 'Connection': 'keep-alive'}
			self.cookie = r.headers["Set-Cookie"][:-13]
			#return '{"error_code": %s}' % r.json()["error_code"]
			return {'error_code': r.json()["error_code"]}
	
		except:
			#return '{"error_code": %s}' % r.json()["error_code"]
			return {'error_code': r.json()["error_code"]}

	def login(self):
    
   		#Email Encoding
		self.encodedEmail = self.sha_digest_username(self.email)
		self.encodedEmail = self.mime_encoder(self.encodedEmail.encode("utf-8"))
  
		#Password Encoding
		self.encodedPassword = self.mime_encoder(self.password.encode("utf-8"))
  
		URL = f"http://{self.ipAddress}/app"
		
		Payload = {"method":"login_device", "params":{"username": self.encodedEmail, "password": self.encodedPassword},	"requestTimeMils": int(round(time.time() * 1000)),}
		
		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method":"securePassthrough", "params":{"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)
	
		if r.status_code != 200:
			#return '{"error_code": %s}' % r.status_code
			return {'error_code': r.status_code}

		decryptedResponse = self.decrypt(r.json()["result"]["response"])

		try:
			self.token = json.loads(decryptedResponse)["result"]["token"]
			return json.loads(self.decrypt(r.json()["result"]["response"]))

		except:
			return json.loads(self.decrypt(r.json()["result"]["response"]))

# IP-Check, Handshake, Login
	def ConnectionRoutine(self):  

		Chk = self.IPCheck()
		if Chk["error_code"] == 0:
			Chk = self.handshake()
			if Chk["error_code"] == 0:
				Chk = self.login()
		return Chk
			
   
# Nickname
	def setNickname(self, Name):
     
		URL = f"http://{self.ipAddress}/app?token={self.token}"
  
		headers = {"Cookie": self.cookie}
 
		Payload = {"method": "set_device_info", "params": {"nickname": Name,}, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}
 
		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough","params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])

		return json.loads(decryptedResponse)

# Dont work !!!!
	def setLogin(self, NewEmail, NewPassword):
     
		URL = f"http://{self.ipAddress}/app?token={self.token}"
  
		headers = {"Cookie": self.cookie}
  
   		#Email Encoding
		encodedNewEmail = self.sha_digest_username(NewEmail)
		encodedNewEmail = self.mime_encoder(encodedNewEmail.encode("utf-8"))
  
		#Password Encoding
		encodedNewPassword = self.mime_encoder(NewPassword.encode("utf-8"))
  
		print(encodedNewEmail)
		print(encodedNewPassword)
 
		Payload = {"method": "set_qs_info", "params": {'account': {'username': encodedNewEmail, 'password': encodedNewPassword}}, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}
 
		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough","params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])

		return json.loads(decryptedResponse)


# Settings 
	def getDeviceInfo(self, command):
       
		URL = f"http://{self.ipAddress}/app?token={self.token}"
       
		Payload = {"method": "get_device_info",	"requestTimeMils": int(round(time.time() * 1000)),}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method":"securePassthrough", "params":{"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)
		
		decryptedResponse = json.loads(self.decrypt(r.json()["result"]["response"]))
    
		commands = {'response': decryptedResponse,
      				'result': decryptedResponse["result"],
					'device_id': decryptedResponse["result"]["device_id"],
					'fw_ver': decryptedResponse["result"]["fw_ver"],
					'model': decryptedResponse["result"]["model"],
					'mac': decryptedResponse["result"]["mac"],
					'overheated': decryptedResponse["result"]["overheated"],
					'ip': decryptedResponse["result"]["ip"],
					'time_diff': decryptedResponse["result"]["time_diff"],
					'ssid': decryptedResponse["result"]["ssid"],
					'signal_level': decryptedResponse["result"]["signal_level"],
					'nickname': decryptedResponse["result"]["nickname"],
					'device_on': decryptedResponse["result"]["device_on"],
					'on_time': decryptedResponse["result"]["on_time"],
					'error_code': decryptedResponse["error_code"]
					}
		
		if command == "nickname":
			encodedName = decryptedResponse["result"]["nickname"]
			name = b64decode(encodedName)
			return name.decode("utf-8")
		elif command == "ssid":
			encodedSSID = decryptedResponse["result"]["ssid"]
			SSID = b64decode(encodedSSID)
			return SSID.decode("utf-8")
		elif command != "nickname" and command != "ssid":
			return commands[command]


# Relay

# turn Relay On
	def turnOn(self):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
		Payload = {"method": "set_device_info",	"params":{"device_on": True}, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough", "params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])

# turn Relay Off
	def turnOff(self):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
		Payload = {"method": "set_device_info",	"params":{"device_on": False}, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough", "params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])
  
# turn Relay Off
	def turnOnWithDelay(self, delay):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
  
		Payload = {"method": "add_countdown_rule", "params": {"delay": int(delay), "desired_states": {"on": True}, "enable": True, "remain": int(delay)}, "terminalUUID": self.terminalUUID}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough", "params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])
    
# turn Relay Off
	def turnOffWithDelay(self, delay):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
  
		Payload = {"method": "add_countdown_rule", "params": {"delay": int(delay), "desired_states": {"on": False}, "enable": True, "remain": int(delay)}, "terminalUUID": self.terminalUUID}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough", "params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])
  
    
# Toggle On or Off with or without delay
	def toggle(self, command, delay=0):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
  
		headers = {"Cookie": self.cookie}
  
		if command == "on":
				state = True
		elif command == "off":
				state = False
		elif command != "on" & command != "off":
			return {'error_code': 5}
  
		#overwrite countdownrule
		Payload = {"method": "add_countdown_rule", "params": {"delay": 0, "desired_states": {"on": state}, "enable": False,	"remain": 0},"terminalUUID": self.terminalUUID}
  
		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough","params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)
		# r = <Response [200]> 

		# r.json(): {'error_code': 0, 'result': {'response': 'ENCRYPTED'}}
		decryptedResponse = self.decrypt(r.json()["result"]["response"])
		# decryptedResponse: {"result":{"id":"C1"},"error_code":0}
  
		errorCode = ast.literal_eval(decryptedResponse)["error_code"]
  
		#turn On or Off - with or without CountdownRule
		if errorCode == 0:

			if delay <= 0:
				Payload = {"method": "set_device_info",	"params": {"device_on": state}, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}
  
			if delay > 0:
				Payload = {"method": "add_countdown_rule", "params": {"delay": int(delay), "desired_states": {"on": state}, "enable": True, "remain": int(delay)}, "terminalUUID": self.terminalUUID}
   		
		
			EncryptedPayload = self.encrypt(json.dumps(Payload))

			SecurePassthroughPayload = {"method": "securePassthrough","params": {"request": EncryptedPayload}}

			r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)

			decryptedResponse = self.decrypt(r.json()["result"]["response"])
			# {'error_code': 0}   
   
		return json.loads(decryptedResponse)


# LED		
	def getLEDInfo(self, command):
    
		URL = f"http://{self.ipAddress}/app?token={self.token}"

		Payload = {"method": "get_led_info", "requestTimeMils": int(round(time.time() * 1000)),}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method":"securePassthrough", "params":{"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)
		
		decryptedResponse = json.loads(self.decrypt(r.json()["result"]["response"]))
  
		commands = {'response': decryptedResponse,
      				'result': decryptedResponse["result"],
					'night_mode_type': decryptedResponse["result"]["night_mode"]["night_mode_type"],
					'start_time': decryptedResponse["result"]["night_mode"]["start_time"],
					'end_time': decryptedResponse["result"]["night_mode"]["end_time"],		
					'sunrise_offset': decryptedResponse["result"]["night_mode"]["sunrise_offset"],
     				'sunset_offset': decryptedResponse["result"]["night_mode"]["sunset_offset"],
         			'led_status': decryptedResponse["result"]["led_status"],
            		'led_rule': decryptedResponse["result"]["led_rule"],
               		'error_code': decryptedResponse["error_code"],
					}
		return commands[command]

	def toggleLED(self, command):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
  
		headers = {"Cookie": self.cookie}
  
		if command == "on":
			Payload = {"method": "set_led_info", "params": {"led_status": True, "led_rule": "always", "night_mode": {"night_mode_type": "unknown", "sunrise_offset": 0, "sunset_offset": 0, "start_time": 0, "end_time": 0}}, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}
   
		elif command == "off":
			Payload = {"method": "set_led_info", "params": {"led_status": False, "led_rule": "never", "night_mode": {"night_mode_type": "unknown", "sunrise_offset": 0, "sunset_offset": 0, "start_time": 0, "end_time": 0}}, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}
  
		elif command != "on" & command != "off":
			return {'error_code': 5}
		
		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method": "securePassthrough","params": {"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])

		return json.loads(decryptedResponse)


# Energyusage
	def getEnergyUsage(self, command):
        
		URL = f"http://{self.ipAddress}/app?token={self.token}"

		Payload = {"method": "get_energy_usage", "requestTimeMils": int(round(time.time() * 1000)),}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method":"securePassthrough", "params":{ "request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = json.loads(self.decrypt(r.json()["result"]["response"]))
  
		commands = {'response': decryptedResponse,
      				'result': decryptedResponse["result"],
					'today_runtime': decryptedResponse["result"]["today_runtime"],
					'month_runtime': decryptedResponse["result"]["month_runtime"],
					'today_energy': decryptedResponse["result"]["today_energy"],
					'month_energy': decryptedResponse["result"]["month_energy"],
					'local_time': decryptedResponse["result"]["local_time"],
					'past24h': decryptedResponse["result"]["past24h"],
					'past30d': decryptedResponse["result"]["past30d"],
					'past1y': decryptedResponse["result"]["past1y"],
					'past7d': decryptedResponse["result"]["past7d"],
					'current_power': decryptedResponse["result"]["current_power"],
					'error_code': decryptedResponse["error_code"]
					}
		return commands[command]



# generally function for using different "get" functions, like:
# get_device_running_info
# get_device_usage
# get_wireless_scan_info
# qs_component_nego
# component_nego
# get_device_time
# get_countdown_rules
# get_antitheft_rules
# get_inherit_info
# get_ffs_info
# get_connect_cloud_state
# getWifiBasic

	def sendGet(self, cmd):
		URL = f"http://{self.ipAddress}/app?token={self.token}"

		Payload = {"method": cmd, "requestTimeMils": int(round(time.time() * 1000)), "terminalUUID": self.terminalUUID}

		headers = {"Cookie": self.cookie}

		EncryptedPayload = self.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {"method":"securePassthrough", "params":{"request": EncryptedPayload}}

		r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.decrypt(r.json()["result"]["response"])

		return (json.loads(decryptedResponse))




