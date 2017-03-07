'''

	Logger Class

'''
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