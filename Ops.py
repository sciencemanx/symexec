
import copy
from capstone.x86 import *
from z3 import *

# OF, SF, ZF, AF, CF, and PF flags are set
def ADD(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	newstate.pc += insn.size

	sum = symstate.read_value(op1) + symstate.read_value(op2)
	newstate.store_value(op1, sum)

	newstate.ZF = sum == 0
	newstate.SF = (sum & 0x80000000) != 0
	# newstate.CF = 
	# newstate.OF = 

	return (newstate,)

# OF and CF flags are cleared; the SF, ZF, and PF flags are set
def AND(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

v_num = 0

# no eflags
def CALL(symstate, insn):
	target, = insn.operands
	newstate = copy.copy(symstate)

	global v_num

	if symstate.is_error(target):
		print 'error at pc: 0x{:x}'.format(insn.address)
		s = Solver()
		s.append(symstate.path_constraints)
		s.check()
		print s.model()
		print symstate.path_constraints
		return ()
	elif symstate.is_get_int(target):
		print 'get_int at pc: 0x{:x}'.format(insn.address)
		var = BitVec('v{}'.format(v_num), 32)
		newstate.regs[X86_REG_EAX] = var
		newstate.vars += (var,)
		v_num += 1
	elif symstate.is_get_char(target):
		print 'get_char at pc: 0x{:x}'.format(insn.address)
	else:
		print 'call[0x{:x}] unsupported'.format(target.imm)
		return ()

	newstate.pc += insn.size

	return (newstate,)

# no eflags
def CBW(symstate, insn):
	op, = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

def CMP(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	tmp = symstate.read_value(op1) - symstate.read_value(op2)

	newstate.ZF = tmp == 0
	newstate.SF = (tmp & 0x80000000) != 0

	newstate.pc += insn.size

	return (newstate,)

# no eflags
def CWDE(symstate, insn):
	op, = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

# CF, OF, SF, ZF, AF, and PF flags are undefined
def DIV(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

# CF, OF, SF, ZF, AF, and PF flags are undefined
def IDIV(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)


def IMUL(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

# CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
def INC(symstate, insn):
	op, = insn.operands
	newstate = copy.copy(symstate)

	op_val = symstate.read_value(op)
	newstate.store_value(op, op_val + 1)

	newstate.pc += insn.size

	return (newstate,)

def check_const(*const):
	s = Solver()
	s.append(*const)
	return s.check()

def Jcc(symstate, insn, jmp_const):
	target, = insn.operands

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

	print('can jmp to {} different states'.format(len(states)))

	return states


# CF=0 and ZF=0
def JA(symstate, insn):
	jmp_const = And(symstate.CF, symstate.ZF)

	return Jcc(symstate, insn, jmp_const)


# CF=0
def JAE(symstate, insn):
	jmp_const = symstate.CF
  
	return Jcc(symstate, insn, jmp_const)


# CF=1
def JB(symstate, insn):
	jmp_const = symstate.CF

	return Jcc(symstate, insn, jmp_const)


# CF=1 or ZF=1
def JBE(symstate, insn):
	jmp_const = Or(symstate.CF, symstate.ZF)

	return Jcc(symstate, insn, jmp_const)


# ZF=1
def JE(symstate, insn):
	jmp_const = symstate.ZF

	return Jcc(symstate, insn, jmp_const)


# ZF=0 and SF=OF
def JG(symstate, insn):
	print (symstate.ZF, symstate.SF, symstate.OF)
	x = symstate.SF == symstate.OF
	y = symstate.ZF
	jmp_const = And(symstate.ZF, symstate.SF == symstate.OF)

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
	jmp_const = And(symstate.ZF, symstate.SF != symstate.OF)

	return Jcc(symstate, insn, jmp_const)


# ZF=0
def JNE(symstate, insn):
	jmp_const = symstate.ZF

	return Jcc(symstate, insn, jmp_const)


# OF=0
def JNO(symstate, insn):
	jmp_const = symstate.OF

	return Jcc(symstate, insn, jmp_const)


# PF=0
def JNP(symstate, insn):
	jmp_const = symstate.PF

	return Jcc(symstate, insn, jmp_const)


# SF=0
def JNS(symstate, insn):
	jmp_const = symstate.SF

	return Jcc(symstate, insn, jmp_const)


# OF=1
def JO(symstate, insn):
	jmp_const = symstate.OF

	return Jcc(symstate, insn, jmp_const)


# PF=1
def JP(symstate, insn):
	jmp_const = symstate.PF

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

# OF and CF flags are set to 0 if the upper half of the result is 0
# otherwise, they are set to 1
def MUL(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

# CF flag set to 0 if the source operand is 0; otherwise it is set to 1. 
# The OF, SF, ZF, AF, and PF flags are set according to the result.
def NEG(symstate, insn):
	op, = insn.operands
	newstate = copy.copy(symstate)

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

	return (newstate,)

# The OF and CF flags are cleared; the SF, ZF, and PF flags are set
def OR(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

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


# CF flag contains the value of the last bit shifted out of the destination operand; 
# it is undefined for SHL and SHR instructions where the count is greater than 
# or equal to the size (in bits) of the destination operand. The OF flag is 
# affected only for 1-bit shifts (see "Description" above); otherwise, it is 
# undefined. The SF, ZF, and PF flags are set according to the result. If the 
# count is 0, the flags are not affected. For a non-zero count, the AF flag is 
# undefined.
def SAL(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)


def SAR(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)


def SHL(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)


def SHR(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

# OF, SF, ZF, AF, PF, and CF flags are set according to the result.
def SUB(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	newstate.store_value(op1, symstate.read_value(op1) - symstate.read_value(op2))
	newstate.pc += insn.size

	return (newstate,)

# OF and CF flags are set to 0. The SF, ZF, and PF flags are set according to the result
def TEST(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

def XOR(symstate, insn):
	op1, op2 = insn.operands
	newstate = copy.copy(symstate)

	return (newstate,)

op_map = {
	X86_INS_ADD:   ADD,

	X86_INS_AND:   AND,

	X86_INS_CALL:  CALL,

	X86_INS_CBW:   CBW,

	X86_INS_CDQ:   None,
	X86_INS_CDQE:  None,

	X86_INS_CMP:   CMP,

	X86_INS_CWD:   None,
	X86_INS_CWDE:  CWDE,

	X86_INS_DEC:   None,
	X86_INS_DIV:   DIV,

	X86_INS_IDIV:  IDIV,
	X86_INS_IMUL:  IMUL,

	X86_INS_INC:   INC,

	X86_INS_JA:    JA,
	X86_INS_JAE:   JAE,
	X86_INS_JB:    JB,
	X86_INS_JBE:   JBE,
	X86_INS_JE:    JE,
	X86_INS_JG:    JG,
	X86_INS_JGE:   JGE,
	X86_INS_JL:    JL,
	X86_INS_JLE:   JLE,
	X86_INS_JNE:   JNE,
	X86_INS_JNO:   JNO,
	X86_INS_JNP:   JNP,
	X86_INS_JNS:   JNS,
	X86_INS_JO:    JO,
	X86_INS_JP:    JP,
	X86_INS_JS:    JS,

	X86_INS_JMP:   JMP,

	X86_INS_LEA:   LEA,

	X86_INS_LEAVE: LEAVE,

	X86_INS_MOV:   MOV,
	X86_INS_MOVZX: None,

	X86_INS_MUL:   MUL,


	X86_INS_NEG:   NEG,

	X86_INS_NOP:   NOP,

	X86_INS_NOT:   NOT,

	X86_INS_OR:    OR,
	
	X86_INS_POP:   POP,
	X86_INS_PUSH:  PUSH,

	X86_INS_RET:   RET,

	X86_INS_SAL:   SAL,
	X86_INS_SAR:   SAR,
	X86_INS_SHL:   SHL,
	X86_INS_SHR:   SHR,

	X86_INS_SUB:   SUB,

	X86_INS_TEST:  TEST,

	X86_INS_XOR:   XOR
}
