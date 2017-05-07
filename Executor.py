
from Ops import op_map
from CFG import CFG, op_str
from pwnlib.elf import ELF
from SymState import SymState

class Executor(object):
	def __init__(self, filename):
		self.elf = ELF(filename)
		self.cfg = CFG(self.elf, self.elf.sym['main'])
		self.paths = [SymState(self.cfg, self.elf)]
		self.errors = []

	def step(self, path):
		insn = self.cfg[path.pc]
		print op_str(insn)
		return op_map[insn.id](path, insn)

	def run(self):
		while len(self.paths) > 0:
			path = self.paths.pop(0)
			print path
			new_paths = self.step(path)

			self.paths.extend(new_paths)
			# if len(self.paths) == 0:
			# 	print path
			# self.errors.extend(errors)