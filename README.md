#If you like my work, you can please buy me a coffee:
https://www.paypal.me/synapsengymnastik

# Tapo P100
Tapo P100 is a Python library for controlling the Tp-link Tapo P100/P110 plugs.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install PyP100.

```bash
pip3 install PyP100
```

## Usage
Plugs - P100 & P110 
```
from . import Tapo

p = Tapo("192.168.X.X", "email@gmail.com", "Password123") #Creating a P100 plug object

p.handshake() #Creates the cookies required for further methods

p.login() #Sends credentials to the plug and creates AES Key and IV for further methods


p.turnOn() #Sends the turn on request

p.turnOff() #Sends the turn off request

p.turnOnWithDelay(10) # Sends the turn on request with 10 seconds delay

p.turnOffWithDelay(10) # Sends the turn off request with 10 seconds delay


p.toggle("on", 0) # Sends the turn on request

p.toggle("off", 0) # Sends the turn off request

p.toggle("on", 10) # Sends the turn on request with 10 seconds delay

p.toggle("off", 10) # Sends the turn off request with 10 seconds delay


p.getDeviceInfo() # Returns dict with all the device info
you can use this commands:
decryptedResponse,
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
          

p.getEnergyUsage("result") # Returns dict with all the energy usage
you can use this commands:
'response': decryptedResponse,
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
          

p.getLEDInfo("response") # Infos for the LED
you can use this commands:
'response': decryptedResponse,
'result': decryptedResponse["result"],
'night_mode_type': decryptedResponse["result"]["night_mode"]["night_mode_type"],
'start_time': decryptedResponse["result"]["night_mode"]["start_time"],
'end_time': decryptedResponse["result"]["night_mode"]["end_time"],		
'sunrise_offset': decryptedResponse["result"]["night_mode"]["sunrise_offset"],
'sunset_offset': decryptedResponse["result"]["night_mode"]["sunset_offset"],
'led_status': decryptedResponse["result"]["led_status"],
'led_rule': decryptedResponse["result"]["led_rule"],
'error_code': decryptedResponse["error_code"],


p.toggleLED("on") # turns the LED On - the LED is On if the Relay is On and Off if the Relay is Off

p.toggleLED("off") # turns the LED Off - the LED is alwys Off


p.setNickname(Name) # sets a new name for the device


p.IPCheck() # Is checking, if the IP is valide.

p.ConnectionRoutine() # Is a function that combines IPCheck, Handshake and Login.


p.ErrorCeck() # All functions are returning a ErrorCode or a Value (get functions). 
              # The ErrorCheck function is searching for a ErrorMessage for the Errornumber.
              
p.sendGet("get_device_running_info") # sen different get commands              
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
              


Example for using the ConnectionRoutine and a function with ErrorCheck:

p = Tapo("192.168.1.99", "magictrips@hotmail.com", "1234octo&&&")

Chk =p.ConnectionRoutine()
print("ConnectionRoutin: ", p.ErrorCheck(Chk))
if Chk["error_code"] == 0:
	print(p.sendGet("getDeviceList"))
