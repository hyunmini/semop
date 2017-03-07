#!/usr/bin/python
#-*- coding: utf-8 -*-
import sys
import frida
import codecs
from util import shell
from pwn import *

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
