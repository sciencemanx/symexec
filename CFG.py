
from capstone import *
from capstone.x86 import *

MAX_INST_LEN = 15

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def op_str(op):
	return '0x{:x}: {} {}'.format(op.address, op.mnemonic, op.op_str)


def get_jmp_target(op):
	target = op.operands[0]
	if target.type == X86_OP_IMM:
		return target.imm
	else:
		raise Exception


def succ(op):
	addrs = []
	if op.id not in [X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ, X86_INS_JMP]:
		addrs.append(op.address + op.size)
	if X86_GRP_JUMP in op.groups:
		addrs.append(get_jmp_target(op))
	return addrs


def construct_cfg(elf, start_addr):
		cfg = {}
		work_queue = [start_addr]

		while len(work_queue) > 0:
			addr = work_queue.pop()
			if addr in cfg:
				continue
			code = elf.read(addr, MAX_INST_LEN)
			op = next(md.disasm(code, addr))
			op.succs = succ(op)
			cfg[addr] = op
			work_queue += op.succs

		return cfg


class CFG(object):
	def __init__(self, elf, start_addr):
		self.start_addr = start_addr
		self.ops = construct_cfg(elf, start_addr)
		self.end_addr = max(self.ops)

	def __getitem__(self, key):
		if isinstance(key, (int, long)):
			return self.ops[key]

	@property
	def start(self):
		return self[self.start_addr]

	@property
	def end(self):
		return self[self.end_addr]

	def __repr__(self):
		return '{}(0x{:x})'.format(self.__class__.__name__, self.start_addr)
