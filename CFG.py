
from capstone import *
from capstone.x86 import *
from pwnlib.elf import ELF
from BasicBlock import BasicBlock

MAX_INST_LEN = 15
NUM_REGS = 234

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def get_jmp_target(op):
	target = op.operands[0]
	if target.type == X86_OP_IMM:
		return target.imm

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

def build_basic_blocks(opgraph):
	ops = [opgraph[addr] for addr in sorted(opgraph.keys())]

	splits = []
	for op in ops:
		if len(op.succs) >= 2 or op.id == X86_INS_JMP: #make this not suck
			splits += op.succs

	basic_blocks = {}
	block = BasicBlock()
	for op in ops:
		if op.address in splits:
			basic_blocks[block.start.address] = block
			block = BasicBlock()
		block.insn.append(op)
	basic_blocks[block.start.address] = block

	for start_addr, block in basic_blocks.items():
		succs = block.insn[-1].succs
		for s in succs:
			if s not in basic_blocks:
				continue
			basic_blocks[s].in_blocks.append(block)
			block.out_blocks.append(basic_blocks[s])

	return basic_blocks

def op_str(op):
	return '0x{:x}: {} {}'.format(op.address, op.mnemonic, op.op_str)

class CFG(object):
	def __init__(self, elf, start_addr):
		self.start_addr = start_addr
		self.ops = construct_cfg(elf, start_addr)
		self.end_addr = max(self.ops)
		self.blocks = build_basic_blocks(self.ops)

	def __getitem__(self, key):
		if isinstance(key, (int, long)):
			return self.ops[key]

	@property
	def start(self):
		return self[self.start_addr]

	@property
	def end(self):
		return self[self.end_addr]

	@property
	def start_block(self):
		return self.blocks[self.start_addr]

	def show(self):
		visited = set()
		work_list = [self.start_block]
		while len(work_list) > 0:
			block = work_list.pop()
			visited.add(block)
			
			print('block {:x}'.format(block.start.address))
			for i in block.insn:
				print(op_str(i))

			for out_block in block.out_blocks:
				if out_block not in visited:
					work_list.append(out_block)

	def __repr__(self):
		return '{}(0x{:x})'.format(self.__class__.__name__, self.start_addr)


if __name__ == '__main__':
	import sys

	if len(sys.argv) != 2:
		print('Usage: {} <file>'.format(sys.argv[0]))
		sys.exit()

	e = ELF(sys.argv[1])
	main_addr = e.symbols['main']

	cfg = CFG(e, main_addr)
	cfg.show()
