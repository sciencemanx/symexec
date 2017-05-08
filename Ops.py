
import copy
from capstone.x86 import *
from z3 import *
from SymState import StackPointer


def msb(x):
	return x & 0x80000000


def do_and(state, store, val1, val2):
	res = val1 & val2

	if store is not None:
		state.store_value(store, res)

	state.ZF = res == 0
	state.SF = msb(res) != 0
	state.OF = False


def do_sub(state, store, val1, val2):
	res = val1 - val2

	if store is not None:
		state.store_value(store, res)

	# assume stack pointer comparisons aren't used for jmps
	if isinstance(res, StackPointer):
		return

	state.ZF = res == 0
	state.SF = msb(res) != 0
	state.OF = And(msb(val1) == msb(-val2), msb(val1) != msb(res))


def show_vars(consts, vs):
	s = Solver()
	s.add(*consts)
	s.check()
	for v in vs:
		print '{} = {}'.format(v, s.model()[v])


# OF, SF, ZF, AF, CF, and PF flags are set
def ADD(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	sum = val1 + val2
	newstate.store_value(op1, sum)

	newstate.ZF = sum == 0
	newstate.SF = msb(sum) != 0
	newstate.OF = And(msb(val1) == msb(val2), msb(val1) != msb(sum))

	newstate.pc += insn.size

	return (newstate,)


# OF and CF flags are cleared; the SF, ZF, and PF flags are set
def AND(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	do_and(newstate, op1, val1, val2)

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def CALL(symstate, insn):
	target, = insn.operands
	newstate = copy.copy(symstate)

	global v_num

	if symstate.is_error(target):
		print 'error at pc: 0x{:x}'.format(insn.address)
		show_vars(symstate.path_constraints, symstate.vars)
		return ()
	elif symstate.is_get_int(target):
		# print 'get_int at pc: 0x{:x}'.format(insn.address)
		var = BitVec('v{}'.format(len(symstate.vars)), 32)
		newstate.regs[X86_REG_EAX] = var
		newstate.vars += (var,)
	else:
		print 'call[0x{:x}] unsupported'.format(target.imm)
		return ()

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def CDQE(symstate, insn):
	newstate = copy.copy(symstate)

	newstate.regs[X86_REG_RAX] = symstate.regs[X86_REG_EAX]

	newstate.pc += insn.size

	return (newstate,)


# The CF, OF, SF, ZF, AF, and PF flags are set according to the result
def CMP(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	do_sub(newstate, None, val1, val2)

	newstate.pc += insn.size

	return (newstate,)


# CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
def DEC(symstate, insn):
	op, = insn.operands
	val = symstate.read_value(op)
	newstate = copy.copy(symstate)

	res = val - 1
	newstate.store_value(op, res)

	newstate.ZF = res == 0
	newstate.SF = msb(res) != 0 
	newstate.OF = Or(res == 0x7fffffff, res == 0xffffffff)

	newstate.pc += insn.size

	return (newstate,)


# not handled
def IMUL(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	res = val1 * val2
	newstate.store_value(op1, res)

	newstate.pc += insn.size

	return (newstate,)


# CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
def INC(symstate, insn):
	op, = insn.operands
	val = symstate.read_value(op)
	newstate = copy.copy(symstate)

	res = val + 1
	newstate.store_value(op, res)

	newstate.ZF = res == 0
	newstate.SF = msb(res) != 0 
	newstate.OF = Or(res == 0x80000000, res == 0)

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def Jcc(symstate, insn, jmp_const):
	target, = insn.operands

	def check_const(*const):
		s = Solver()
		s.append(*const)
		return s.check()

	can_jmp = check_const(jmp_const, *symstate.path_constraints) == sat
	can_not_jmp = check_const(Not(jmp_const), *symstate.path_constraints) == sat

	states = ()

	if can_jmp:
		newstate = copy.copy(symstate)
		newstate.pc = symstate.read_value(target)
		newstate.path_constraints += (jmp_const,)
		states += (newstate,)
	if can_not_jmp:
		newstate = copy.copy(symstate)
		newstate.pc += insn.size
		newstate.path_constraints += (Not(jmp_const),)
		states += (newstate,)

	return states


# ZF=1
def JE(symstate, insn):
	jmp_const = symstate.ZF
	return Jcc(symstate, insn, jmp_const)


# ZF=0 and SF=OF
def JG(symstate, insn):
	jmp_const = And(Not(symstate.ZF), symstate.SF == symstate.OF)
	return Jcc(symstate, insn, jmp_const)


# SF=OF
def JGE(symstate, insn):
	jmp_const = symstate.SF == symstate.OF
	return Jcc(symstate, insn, jmp_const)


# SF<>OF
def JL(symstate, insn):
	jmp_const = symstate.SF != symstate.OF
	return Jcc(symstate, insn, jmp_const)


# ZF=1 or SF<>OF
def JLE(symstate, insn):
	jmp_const = Or(symstate.ZF, symstate.SF != symstate.OF)
	return Jcc(symstate, insn, jmp_const)


# ZF=0
def JNE(symstate, insn):
	jmp_const = Not(symstate.ZF)
	return Jcc(symstate, insn, jmp_const)


# OF=0
def JNO(symstate, insn):
	jmp_const = Not(symstate.OF)
	return Jcc(symstate, insn, jmp_const)


# SF=0
def JNS(symstate, insn):
	jmp_const = Not(symstate.SF)
	return Jcc(symstate, insn, jmp_const)


# OF=1
def JO(symstate, insn):
	jmp_const = symstate.OF
	return Jcc(symstate, insn, jmp_const)


# SF=1
def JS(symstate, insn):
	jmp_const = symstate.SF
	return Jcc(symstate, insn, jmp_const)


# no eflags
def JMP(symstate, insn):
	target, = insn.operands
	newstate = copy.copy(symstate)

	newstate.pc = symstate.read_value(target)

	return (newstate,)


# no eflags
def LEA(symstate, insn, dst, src):
	dst, src = insn.operands
	newstate = copy.copy(symstate)

	src_val = symstate.calc_ptr(src)
	newstate.store_value(dst, src_val)

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def LEAVE(symstate, insn):
	newstate = copy.copy(symstate)

	# todo

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def MOV(symstate, insn):
	dst, src = insn.operands
	newstate = copy.copy(symstate)

	src_val = symstate.read_value(src)
	newstate.store_value(dst, src_val)

	newstate.pc += insn.size

	return (newstate,)


# CF flag set to 0 if the source operand is 0; otherwise it is set to 1. 
# The OF, SF, ZF, AF, and PF flags are set according to the result.
def NEG(symstate, insn):
	op, = insn.operands
	val = symstate.read_value(op)
	newstate = copy.copy(symstate)

	res = -val
	newstate.store_value(op, res)

	state.ZF = res == 0
	state.SF = msb(res) != 0
	state.OF = res == 0x80000000

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def NOP(symstate, insn):
	newstate = copy.copy(symstate)

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def NOT(symstate, insn):
	op, = insn.operands
	newstate = copy.copy(symstate)

	newstate.store_value(op, ~symstate.read_value(op))

	newstate.pc += insn.size

	return (newstate,)


# The OF and CF flags are cleared; the SF, ZF, and PF flags are set
def OR(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	res = val1 | val2
	newstate.store_value(op1, res)

	state.ZF = res == 0
	state.SF = msb(res) != 0
	state.OF = False

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def POP(symstate, insn):
	op, = insn.operands
	newstate = copy.copy(symstate)

	new_rsp = symstate.regs[X86_REG_RSP] + 4
	newstate.mem[new_rsp] = symstate.regs[op.reg]
	newstate.regs[X86_REG_RSP] = new_rsp

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def PUSH(symstate, insn):
	op, = insn.operands
	newstate = copy.copy(symstate)

	rsp = symstate.regs[X86_REG_RSP]
	newstate.mem[rsp] = symstate.regs[op.reg]
	newstate.regs[X86_REG_RSP] = symstate.regs[X86_REG_RSP] - 4

	newstate.pc += insn.size

	return (newstate,)


# no eflags
def RET(symstate, insn):
	return ()


# OF, SF, ZF, AF, PF, and CF flags are set according to the result.
def SUB(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	do_sub(newstate, op1, val1, val2)

	newstate.pc += insn.size

	return (newstate,)


# OF and CF flags are set to 0. The SF, ZF, and PF flags are set according to 
# the result
def TEST(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	do_and(newstate, None, val1, val2)

	newstate.pc += insn.size

	return (newstate,)


# The OF and CF flags are cleared; the SF, ZF, and PF flags are set according 
# to the result.
def XOR(symstate, insn):
	op1, op2 = insn.operands
	val1, val2 = symstate.read_value(op1), symstate.read_value(op2)
	newstate = copy.copy(symstate)

	res = val1 ^ val2
	newstate.store_value(op1, res)

	newstate.ZF = res == 0
	newstate.SF = msb(res) != 0 
	newstate.OF = False

	newstate.pc += insn.size

	return (newstate,)


ops = {
	X86_INS_ADD:   ADD,
	X86_INS_AND:   AND,
	X86_INS_CALL:  CALL,
	X86_INS_CDQE:  CDQE,
	X86_INS_CMP:   CMP,
	X86_INS_DEC:   DEC,
	X86_INS_IMUL:  IMUL,
	X86_INS_INC:   INC,
	X86_INS_JE:    JE,
	X86_INS_JG:    JG,
	X86_INS_JGE:   JGE,
	X86_INS_JL:    JL,
	X86_INS_JLE:   JLE,
	X86_INS_JNE:   JNE,
	X86_INS_JNO:   JNO,
	X86_INS_JNS:   JNS,
	X86_INS_JO:    JO,
	X86_INS_JS:    JS,
	X86_INS_JMP:   JMP,
	X86_INS_LEA:   LEA,
	X86_INS_LEAVE: LEAVE,
	X86_INS_MOV:   MOV,
	X86_INS_NEG:   NEG,
	X86_INS_NOP:   NOP,
	X86_INS_NOT:   NOT,
	X86_INS_OR:    OR,
	X86_INS_POP:   POP,
	X86_INS_PUSH:  PUSH,
	X86_INS_RET:   RET,
	X86_INS_SUB:   SUB,
	X86_INS_TEST:  TEST,
	X86_INS_XOR:   XOR
}
