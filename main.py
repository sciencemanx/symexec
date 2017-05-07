
from Executor import Executor
import sys

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print 'Usage: {} <file>'.format(sys.argv[0])
		sys.exit()

	file = sys.argv[1]

	ex = Executor(file)
	ex.run()

