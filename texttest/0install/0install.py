import sys
args = sys.vargs[1:]

try:
	index = args.index('--debug')
	del args[index]
	server_files = args[index].split(';')
	del args[index]
	import server
	server.handle_requests(server_files)
except ValueError:
	pass

from subprocess import check_call
check_call(['python2', '../../0install'] + args)
