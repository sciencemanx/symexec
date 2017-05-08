
from Ops import ops
from CFG import CFG, op_str
from pwnlib.elf import ELF
from SymState import SymState

class Executor(object):
	def __init__(self, filename, func='main'):
		elf = ELF(filename)
		addr = elf.sym[func]
		self.cfg = CFG(elf, addr)
		self.paths = [SymState(self.cfg, elf)]

	def step(self, path):
		insn = self.cfg[path.pc]
		return ops[insn.id](path, insn)

	def run(self):
		while len(self.paths) > 0:
			path = self.paths.pop()
			new_paths = self.step(path)
			self.paths.extend(new_paths)
