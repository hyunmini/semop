#!/usr/bin/python
#-*- coding: utf-8 -*-
import sys
import frida
import codecs
from util import shell
from pwn import *

class Util:
	@staticmethod
	def randstr(length):
		randomString=""
		for i in range(length):
		    randomString += (str(unichr(random.randint(97,122)))) 
		return randomString  

class Logger(object):
	INFO = '\033[10m' 	# white
	SUCC = '\033[92m' 	# green
	WARN = '\033[93m' # yellow
	END  = '\033[0m'	 	# normal(white)

	@staticmethod
	def info(msg):		# print console
		print Logger.INFO + msg + Logger.END

	@staticmethod
	def succ(msg):		# print console
		print Logger.SUCC + msg + Logger.END

	@staticmethod
	def warn(msg):		# print console
		print Logger.WARN + msg + Logger.END

	@staticmethod
	def log(msg):			# log file
		pass

def on_message(message, data):
	if message['type'] == 'error':
		Logger.warn("[Error] : %s" % message['description'])
	elif message['type'] == 'send':
		if message['payload'].startswith('[+]'):
			Logger.succ(" %s" % message['payload'])
		elif message['payload'].startswith('[-]'):
			Logger.warn(" %s" % message['payload'])
		else:
			Logger.info("[*] %s" % message['payload'])
	else:
		print "[%s] -> %s" % (message, data)

class IOS:
	def __init__(self):
		self.scheme = "http"
		self.host = ""

def get_procinfo(identifier):
	os = frida.get_usb_device().name
	if os == 'iPhone':
		apps = frida.get_usb_device().enumerate_applications()		
		for app in apps:
			if app.identifier == identifier:
				print "yes", app
			else:
				print "no",app

#(identifier="com.shinhan.smartcaremgr", name="S알리미")

def main(target_process):
	pid = frida.get_usb_device().spawn([target_process])
	session = frida.get_usb_device().attach(pid)
	#frida.get_usb_device().resume(pid)
	#for module in session.enumerate_modules():
	#		print "[+] ",module
	with codecs.open('./dbi.js','r',encoding='utf8') as f:
		dbi_js = f.read()
	script = session.create_script(dbi_js) 
 
	script.on('message', on_message)
	script.load()
	frida.get_usb_device().resume(pid)
	sys.stdin.read()
 
if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "Usage : %s [Identifier]" %  sys.argv[0]
		print "ex) %s com.shinhan.sbank" %  sys.argv[0]
		sys.exit()
	target_process = sys.argv[1]
	#get_procinfo(target_process)
	main(target_process)
