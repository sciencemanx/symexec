
from Executor import Executor
import sys

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Usage: {} <file> [func]'.format(sys.argv[0])
		sys.exit()

	file = sys.argv[1]
	if len(sys.argv) == 2:
		func = 'main'
	else:
		func = sys.argv[2]

	ex = Executor(file, func)
	ex.run()

