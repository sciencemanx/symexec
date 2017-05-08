
from capstone.x86 import *
from collections import defaultdict
from copy import deepcopy

reg_dict = {globals()[d]:d.split('_')[-1] for d in dir() if 'X86_REG_' in d}
def reg_str(reg):
	return reg_dict[reg]

class Unknown(object):
	def __eq__(self, other):
		return isinstance(other, type(self))
	def __hash__(self): return 0
	def __repr__(self): return 'Unknown()'
	def __add__(self, other): return Unknown()
	def __sub__(self, other): return Unknown()
	def __mul__(self, other): return Unknown()
	def __div__(self, other): return Unknown()


class StackPointer(object):
	def __init__(self, offset=0):
		self.offset = offset
	def __add__(self, other):
		if isinstance(other, (int, long)):
			return StackPointer(self.offset + other)
		elif isinstance(other, Unknown):
			return Unknown()
		else:
			raise TypeError
	def __sub__(self, other):
		return self + (-other)
	def __eq__(self, other):
		if isinstance(other, type(self)):
			return self.offset == other.offset
		return False
	def __hash__(self):
		return hash(self.offset)
	def __repr__(self):
		return 'SP({})'.format(hex(self.offset))


class SymState(object):
	def __init__(self, cfg, elf):
		self.cfg = cfg
		self.elf = elf

		self.pc = cfg.start_addr
		self.regs = defaultdict(lambda: Unknown())
		self.mem = defaultdict(lambda: Unknown())

		self.vars = ()
		self.path_constraints = ()

		self.OF = False
		self.SF = False
		self.ZF = False

		self.regs[X86_REG_RSP] = StackPointer(0)

	def __eq__(self, other):
		if isinstance(other, type(self)):
			return self.regs == other.regs and self.mem == other.mem
		return False

	def __ne__(self, other):
		return not (self == other)

	def __repr__(self):
		return "SymState(regs:{}, mem:{})".format(
			{reg_str(r):v for r,v in dict(self.regs).items()}, dict(self.mem))

	def is_call(self, target, fun_name):
		if fun_name not in self.elf.sym:
			return False
		return self.elf.sym[fun_name] == target.imm

	def is_get_int(self, target):
		return self.is_call(target, 'get_int')

	def is_error(self, target):
		return self.is_call(target, 'error')

	def calc_ptr(self, mem):
		base_addr = self.regs[mem.base]
		if mem.index != 0:
			return base_addr + mem.disp + (self.read_reg(mem.index) * mem.scale)
		else:
			return base_addr + mem.disp

	def store_reg(self, reg, value):
		self.regs[reg] = value

	def store_mem(self, mem, value):
		self.mem[self.calc_ptr(mem)] = value

	def store_value(self, operand, value):
		if operand.type == X86_OP_REG:
			self.store_reg(operand.reg, value)
		if operand.type == X86_OP_MEM:
			self.store_mem(operand.mem, value)
	
	def read_imm(self, imm):
		return imm
	
	def read_reg(self, reg):
		return self.regs.get(reg, Unknown())

	def read_mem(self, mem):
		return self.mem.get(self.calc_ptr(mem), Unknown())

	def read_value(self, operand):
		if operand.type == X86_OP_IMM:
			return self.read_imm(operand.imm)
		if operand.type == X86_OP_REG:
			return self.read_reg(operand.reg)
		if operand.type == X86_OP_MEM:
			return self.read_mem(operand.mem)
