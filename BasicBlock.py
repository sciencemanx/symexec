
class BasicBlock(object):
	def __init__(self, insn=None):
		self.in_blocks = []
		self.out_blocks = []
		self.insn = insn if insn else []

	@property
	def start(self):
		return self.insn[0]

	@property
	def end(self):
		return self.insn[-1]

	def __repr__(self):
		return 'BasicBlock({}, {}, {})'.format(self.insn, self.in_blocks, self.out_blocks)
		