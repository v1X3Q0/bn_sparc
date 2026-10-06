#include <binaryninjaapi.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>

#include "disassembler.h"

using namespace BinaryNinja;

#include "il.h"
#include "util.h"

#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug

#define OTI_SEXT32_REGS 1
#define OTI_SEXT64_REGS 2
#define OTI_ZEXT32_REGS 4
#define OTI_ZEXT64_REGS 8
#define OTI_SEXT32_IMMS 16
#define OTI_SEXT64_IMMS 32
#define OTI_ZEXT32_IMMS 64
#define OTI_ZEXT64_IMMS 128
#define OTI_IMM_CPTR 256
#define OTI_IMM_REL_CPTR 512
#define OTI_IMM_BIAS 1024
#define OTI_GPR0_ZERO 2048

/* ---------------------------------------------------------------------------
 * operand -> IL conversion
 * ------------------------------------------------------------------------- */

/* %g0 always reads as zero; memory operands are (base|0) + (index|0) + disp */
static ExprId operToIL_sz(LowLevelILFunction &il, struct cs_sparc_op *op,
	int archsz, int options=0, uint64_t extra=0)
{
	ExprId res;

	if(!op) {
		MYLOG("ERROR: operToIL() got NULL operand\n");
		return il.Unimplemented();
	}

	switch(op->type) {
		case SPARC_OP_REG:
			if(op->reg == SPARC_REG_G0)
				res = il.Const(archsz, 0);
			else
				res = il.Register(archsz, op->reg);
			break;

		case SPARC_OP_IMM:
			/* the immediate is a constant pointer (eg: absolute address) */
			if(options & OTI_IMM_CPTR) {
				res = il.ConstPointer(archsz, op->imm);
			}
			/* the immediate is a displacement (eg: relative addressing) */
			else if(options & OTI_IMM_REL_CPTR) {
				res = il.ConstPointer(archsz, op->imm + extra);
			}
			/* the immediate should be biased with given value */
			else if(options & OTI_IMM_BIAS) {
				res = il.Const(archsz, op->imm + extra);
			}
			else {
				res = il.Const(archsz, op->imm);
			}
			break;

		case SPARC_OP_MEM:
			if(op->mem.base == SPARC_REG_G0 || op->mem.base == SPARC_REG_INVALID)
				res = il.Const(archsz, 0);
			else
				res = il.Register(archsz, op->mem.base);

			if(op->mem.index && op->mem.index != SPARC_REG_G0)
				res = il.Add(archsz, res, il.Register(archsz, op->mem.index));

			res = il.Add(archsz, res, il.Const(archsz, (uint64_t)op->mem.disp + extra));
			break;

		case SPARC_OP_INVALID:
		default:
			MYLOG("ERROR: don't know how to convert operand to IL\n");
			res = il.Unimplemented();
	}

	return res;
}

#define operToIL(il, op)	operToIL_sz(il, op, arch->GetAddressSize())

/* ---------------------------------------------------------------------------
 * floating point
 *
 * Every FP register is modelled as 8 bytes wide (see GetRegisterInfo): double
 * precision values live in aligned pairs, single precision values are the low
 * 4 bytes, and the upper bits of a single precision result are architecturally
 * undefined (zero extended here).  Quad precision (the Q forms) are not
 * modelled.
 *
 * %fcc holds the 2 bit result of a floating point compare:
 * 0 = equal, 1 = less, 2 = greater, 3 = unordered (V9 manual table 8).
 * ------------------------------------------------------------------------- */

static bool IsFReg(uint32_t r)
{
	return r >= SPARC_REG_F0 && r <= SPARC_REG_F62;
}

static ExprId FRead(LowLevelILFunction &il, cs_sparc_op *op, size_t fs)
{
	if(!op || op->type != SPARC_OP_REG)
		return il.Unimplemented();
	if(fs == 8)
		return il.Register(8, op->reg);
	return il.LowPart(4, il.Register(8, op->reg));
}

static void FWrite(LowLevelILFunction &il, cs_sparc_op *op, size_t fs, ExprId v)
{
	if(!op || op->type != SPARC_OP_REG) {
		il.AddInstruction(il.Unimplemented());
		return;
	}
	il.AddInstruction(il.SetRegister(8, op->reg,
			fs == 8 ? v : il.ZeroExtend(8, v)));
}

/* which %fcc field an instruction writes or tests (defaults to %fcc0) */
static uint32_t FccRegOf(struct cs_sparc *sparc)
{
	int i;
	for(i = 0; i < (int)sparc->op_count; i++)
		if(sparc->operands[i].type == SPARC_OP_REG &&
				sparc->operands[i].reg >= SPARC_REG_FCC0 &&
				sparc->operands[i].reg <= SPARC_REG_FCC3)
			return sparc->operands[i].reg;
	return SPARC_REG_FCC0;
}

/* translate a capstone SPARC_CC_FCC_* float branch condition into a test of
 * the 2 bit %fcc value */
static ExprId FloatCondExpr(LowLevelILFunction &il, int cc, uint32_t fccReg)
{
	ExprId f  = il.Register(1, fccReg);
	ExprId c0 = il.Const(1, 0), c1 = il.Const(1, 1);
	ExprId c2 = il.Const(1, 2), c3 = il.Const(1, 3);

	switch(cc) {
		case SPARC_CC_FCC_A:   return il.Const(1, 1);
		case SPARC_CC_FCC_N:   return il.Const(1, 0);
		case SPARC_CC_FCC_E:   return il.CompareEqual(0, f, c0);
		case SPARC_CC_FCC_NE:  return il.CompareNotEqual(0, f, c0);
		case SPARC_CC_FCC_L:   return il.CompareEqual(0, f, c1);
		case SPARC_CC_FCC_G:   return il.CompareEqual(0, f, c2);
		case SPARC_CC_FCC_LE:  return il.Or(1, il.CompareEqual(0, f, c0),
					il.CompareEqual(0, f, c1));
		case SPARC_CC_FCC_GE:  return il.Or(1, il.CompareEqual(0, f, c0),
					il.CompareEqual(0, f, c2));
		case SPARC_CC_FCC_LG:  return il.Or(1, il.CompareEqual(0, f, c1),
					il.CompareEqual(0, f, c2));
		case SPARC_CC_FCC_O:   return il.CompareNotEqual(0, f, c3);
		case SPARC_CC_FCC_U:   return il.CompareEqual(0, f, c3);
		case SPARC_CC_FCC_UE:  return il.Or(1, il.CompareEqual(0, f, c0),
					il.CompareEqual(0, f, c3));
		case SPARC_CC_FCC_UL:  return il.Or(1, il.CompareEqual(0, f, c1),
					il.CompareEqual(0, f, c3));
		case SPARC_CC_FCC_UG:  return il.Or(1, il.CompareEqual(0, f, c2),
					il.CompareEqual(0, f, c3));
		case SPARC_CC_FCC_ULE: return il.CompareNotEqual(0, f, c2);
		case SPARC_CC_FCC_UGE: return il.CompareNotEqual(0, f, c1);
		default:               return il.Unimplemented();
	}
}

/* ---------------------------------------------------------------------------
 * %icc computation
 *
 * writers compute the icc value with bit layout N:8 Z:4 C:2 V:1.
 * kind selects how C and V are computed.
 * ------------------------------------------------------------------------- */

#define ICC_KIND_ADD   0
#define ICC_KIND_SUB   1
#define ICC_KIND_LOGIC 2

static void EmitIcc(LowLevelILFunction &il, size_t sz, ExprId res,
	ExprId a, ExprId b, int kind)
{
	ExprId n, z, c, v, icc;
	ExprId zeroS = il.Const(sz, 0);

	/* N = MSB(result) */
	n = il.CompareNotEqual(0,
			il.LogicalShiftRight(sz, res, il.Const(sz, sz * 8 - 1)), zeroS);
	n = il.ShiftLeft(1, n, il.Const(1, 3));

	/* Z = result == 0 */
	z = il.CompareEqual(0, res, zeroS);
	z = il.ShiftLeft(1, z, il.Const(1, 2));

	if(kind == ICC_KIND_ADD)
		/* carry out */
		c = il.CompareUnsignedLessThan(0, res, a);
	else if(kind == ICC_KIND_SUB)
		/* borrow: C = 1 when a <u b */
		c = il.CompareUnsignedLessThan(0, a, b);
	else
		c = il.Const(1, 0);
	if(kind != ICC_KIND_LOGIC)
		c = il.ShiftLeft(1, c, il.Const(1, 1));

	if(kind == ICC_KIND_ADD)
		/* signed overflow: ((a^r) & (b^r)) msb */
		v = il.And(sz,
				il.Xor(sz, a, res),
				il.Xor(sz, b, res));
	else if(kind == ICC_KIND_SUB)
		/* signed overflow: ((a^b) & (a^r)) msb */
		v = il.And(sz,
				il.Xor(sz, a, b),
				il.Xor(sz, a, res));
	else
		v = il.Const(1, 0);
	if(kind != ICC_KIND_LOGIC)
		v = il.CompareNotEqual(0,
				il.LogicalShiftRight(sz, v, il.Const(sz, sz * 8 - 1)),
				il.Const(sz, 0));

	icc = il.Or(1, il.Or(1, il.Or(1, n, z), c), v);
	il.AddInstruction(il.SetRegister(1, SPARC_REG_ICC, icc));
}

/* icc is the *32 bit* view of an operation result, xcc the 64 bit view (not
 * modelled); all icc conditional branches test the 32 bit view, so on a 64 bit
 * architecture the condition codes must be taken from the low word only. */
static void EmitIccView(LowLevelILFunction &il, size_t sz, ExprId res,
	ExprId a, ExprId b, int kind)
{
	if(sz == 4)
		EmitIcc(il, 4, res, a, b, kind);
	else
		EmitIcc(il, 4, il.LowPart(4, res), il.LowPart(4, a), il.LowPart(4, b), kind);
}

/* CCR.icc.c as a 0/1 value of width sz: the add/subtract with carry forms read
 * the 32 bit carry bit, never a 64 bit one */
static ExprId IccCarry(LowLevelILFunction &il, size_t sz)
{
	ExprId c = il.And(1, il.Register(1, SPARC_REG_ICC), il.Const(1, IL_ICC_C));
	c = il.LogicalShiftRight(1, c, il.Const(1, 1));
	return il.ZeroExtend(sz, c);
}

/* ---------------------------------------------------------------------------
 * branch condition determination
 * ------------------------------------------------------------------------- */

/* the condition carried in a branch mnemonic (first token; tokens after the
 * first comma are prediction/annul hints and are ignored) */
typedef enum {
	BC_NONE = 0,	/* no condition token: consult detail->sparc.cc */
	BC_A, BC_N, BC_E, BC_NE, BC_VS, BC_VC, BC_NEG, BC_POS,
	BC_LE, BC_L, BC_LEU, BC_CS, BC_GE, BC_G, BC_GU, BC_CC,
	BC_FLOAT
} branch_cond_t;

static const struct { const char *tok; branch_cond_t bc; } branchCondTable[] = {
	{ "a",   BC_A   },
	{ "n",   BC_N   },
	{ "e",   BC_E   },
	{ "ez",  BC_E   },
	{ "ne",  BC_NE  },
	{ "nz",  BC_NE  },
	{ "vs",  BC_VS  },
	{ "vc",  BC_VC  },
	{ "neg", BC_NEG },
	{ "nv",  BC_NEG },
	{ "pos", BC_POS },
	{ "pv",  BC_POS },
	{ "le",  BC_LE  },
	{ "lez", BC_LE  },
	{ "l",   BC_L   },
	{ "lz",  BC_L   },
	{ "leu", BC_LEU },
	{ "cs",  BC_CS  },
	{ "ge",  BC_GE  },
	{ "gez", BC_GE  },
	{ "g",   BC_G   },
	{ "gz",  BC_G   },
	{ "gu",  BC_GU  },
	{ "cc",  BC_CC  },
	{ "nc",  BC_CC  },
	/* float condition tokens; only a and n are special, the rest are opaque */
	{ "ue",  BC_FLOAT },
	{ "uge", BC_FLOAT },
	{ "ul",  BC_FLOAT },
	{ "ule", BC_FLOAT },
	{ "lg",  BC_FLOAT },
	{ "o",   BC_FLOAT },
	{ "u",   BC_FLOAT },
};

/* extract the condition token from a branch mnemonic ("bne,pn" -> "ne") */
static branch_cond_t BranchCondFromMnemonic(const char *mnemonic)
{
	const char *p = mnemonic;
	char tok[16];
	size_t i = 0;

	if(tolower(*p) == 'f')
		p++;
	if(tolower(*p) == 'b')
		p++;

	while(*p && *p != ',' && i < sizeof(tok) - 1) {
		tok[i++] = (char)tolower(*p);
		p++;
	}
	tok[i] = 0;

	if(i == 0)
		return BC_NONE;

	for(size_t j = 0; j < sizeof(branchCondTable)/sizeof(branchCondTable[0]); j++)
		if(strcmp(branchCondTable[j].tok, tok) == 0)
			return branchCondTable[j].bc;

	/* unknown token (float, etc) */
	return BC_NONE;
}

static branch_cond_t ccToCond(sparc_cc cc)
{
	switch(cc) {
		case SPARC_CC_ICC_N:   return BC_N;
		case SPARC_CC_ICC_E:   return BC_E;
		case SPARC_CC_ICC_LE:  return BC_LE;
		case SPARC_CC_ICC_L:   return BC_L;
		case SPARC_CC_ICC_LEU: return BC_LEU;
		case SPARC_CC_ICC_CS:  return BC_CS;
		case SPARC_CC_ICC_NEG: return BC_NEG;
		case SPARC_CC_ICC_VS:  return BC_VS;
		case SPARC_CC_ICC_A:   return BC_A;
		case SPARC_CC_ICC_NE:  return BC_NE;
		case SPARC_CC_ICC_G:   return BC_G;
		case SPARC_CC_ICC_GE:  return BC_GE;
		case SPARC_CC_ICC_GU:  return BC_GU;
		case SPARC_CC_ICC_CC:  return BC_CC;
		case SPARC_CC_ICC_POS: return BC_POS;
		case SPARC_CC_ICC_VC:  return BC_VC;
		default:               return BC_NONE;
	}
}

/* classify a branch instruction's disposition (public: arch_sparc.cpp) */
sparc_branch_disp_t SparcClassifyBranch(uint32_t insnId, const char *mnemonic, sparc_cc cc)
{
	branch_cond_t bc;

	switch(insnId) {
		/* all branch-register forms are conditional */
		case SPARC_INS_BRZ:
		case SPARC_INS_BRNZ:
		case SPARC_INS_BRLZ:
		case SPARC_INS_BRLEZ:
		case SPARC_INS_BRGZ:
		case SPARC_INS_BRGEZ:
			return SPARC_BRANCH_CONDITIONAL;
		default:
			break;
	}

	bc = BranchCondFromMnemonic(mnemonic);
	if(bc == BC_NONE && cc != SPARC_CC_INVALID)
		bc = ccToCond(cc);

	/* default: an unadorned "b"/"ba" is unconditional; unknown tokens on
	 * float branches are conditional, on icc branches treated as taken */
	if(bc == BC_N)
		return SPARC_BRANCH_NEVER;
	if(bc == BC_A || bc == BC_NONE)
		return SPARC_BRANCH_UNCOND;
	return SPARC_BRANCH_CONDITIONAL;
}

/* branches are reported by capstone with the target resolved to an absolute
 * address in the last immediate operand */
bool SparcBranchTarget(decomp_result *res, uint64_t *target)
{
	struct cs_sparc *sparc = &(res->detail.sparc);

	for(int i = (int)sparc->op_count - 1; i >= 0; i--) {
		if(sparc->operands[i].type == SPARC_OP_IMM) {
			*target = (uint64_t)sparc->operands[i].imm;
			return true;
		}
	}
	return false;
}

/* jmpl/jmp with destination register %g0 returning through %i7/%o7 */
bool SparcJmplIsReturn(decomp_result *res)
{
	struct cs_sparc *sparc = &(res->detail.sparc);
	uint32_t rd = SPARC_REG_G0;
	bool baseIsLink = false;
	int nreg = 0;

	for(int i = 0; i < (int)sparc->op_count; i++) {
		if(sparc->operands[i].type == SPARC_OP_REG) {
			if(nreg == 0)
				baseIsLink = (sparc->operands[i].reg == SPARC_REG_I7 ||
				              sparc->operands[i].reg == SPARC_REG_O7);
			rd = sparc->operands[i].reg;
			nreg++;
		}
		else if(sparc->operands[i].type == SPARC_OP_MEM) {
			baseIsLink = (sparc->operands[i].mem.base == SPARC_REG_I7 ||
			              sparc->operands[i].mem.base == SPARC_REG_O7);
			if(sparc->operands[i].mem.index)
				nreg++;   /* index is not rd */
		}
	}

	/* no second register operand: rd defaults to g0 */
	if(rd == SPARC_REG_G0 && nreg <= 1)
		return baseIsLink || sparc->op_count == 0;

	return false;
}

/* ---------------------------------------------------------------------------
 * branch patching (see il.h for the encoding notes)
 * ------------------------------------------------------------------------- */

#define IL_BRCOND_NIBBLE_MASK 0x1e000000   /* bits 28:25 */
#define IL_BRCOND_NIBBLE_SHIFT 25
#define IL_BRCOND_ALWAYS      8            /* "a" in capstone's numbering */
#define IL_BRCOND_NEVER       0            /* "n" */
#define IL_BRCOND_INVERT_BIT  0x10000000   /* xor 8 in the nibble */
#define IL_BRZ_INVERT_BIT     0x08000000   /* xor 4 nibble-steps: brz<->brnz etc. */

sparc_patch_kind_t SparcPatchBranchKind(uint32_t insnId)
{
	switch(insnId) {
		case SPARC_INS_B:
		case SPARC_INS_FB:
			return SPARC_PATCH_COND_BRANCH;
		case SPARC_INS_BRZ:
		case SPARC_INS_BRNZ:
		case SPARC_INS_BRLZ:
		case SPARC_INS_BRLEZ:
		case SPARC_INS_BRGZ:
		case SPARC_INS_BRGEZ:
			return SPARC_PATCH_BRZ_BRANCH;
		default:
			return SPARC_PATCH_NOT_BRANCH;
	}
}

bool SparcApplyBranchPatch(uint32_t *word, sparc_patch_kind_t kind, int mode)
{
	uint32_t w = *word;
	uint32_t nibble;

	switch(kind) {
		case SPARC_PATCH_COND_BRANCH:
			nibble = (w >> IL_BRCOND_NIBBLE_SHIFT) & 0xF;
			switch(mode) {
				case SPARC_PATCH_ALWAYS:
					if(nibble == IL_BRCOND_ALWAYS)
						return false;   /* already unconditional */
					w = (w & ~IL_BRCOND_NIBBLE_MASK) |
					    (IL_BRCOND_ALWAYS << IL_BRCOND_NIBBLE_SHIFT);
					*word = w;
					return true;
				case SPARC_PATCH_NEVER:
					if(nibble == IL_BRCOND_NEVER)
						return false;   /* already never-taken */
					w = (w & ~IL_BRCOND_NIBBLE_MASK) |
					    (IL_BRCOND_NEVER << IL_BRCOND_NIBBLE_SHIFT);
					*word = w;
					return true;
				case SPARC_PATCH_INVERT:
					/* every condition's complement is 8 away, in the icc,
					 * xcc and fcc tables alike */
					w ^= IL_BRCOND_INVERT_BIT;
					*word = w;
					return true;
			}
			return false;

		case SPARC_PATCH_BRZ_BRANCH:
			if(mode != SPARC_PATCH_INVERT)
				return false;   /* no always/never encoding for these */
			w ^= IL_BRZ_INVERT_BIT;
			*word = w;
			return true;

		default:
			return false;
	}
}

bool SparcEncodeReturnInO0(uint64_t value, uint32_t *word)
{
	int64_t sv = (int64_t)value;

	/* mov <simm>, %o0 = add %g0, simm13, %o0 (llvm-mc: mov 5,%o0 ->
	 * 0x90102005, mov -5,%o0 -> 0x90103ffb) */
	if(sv < -4096 || sv > 4095)
		return false;

	*word = 0x90102000 | ((uint32_t)value & 0x1fff);
	return true;
}

/* ---------------------------------------------------------------------------
 * branch IL emission
 * ------------------------------------------------------------------------- */

static ExprId CondExpr(LowLevelILFunction &il, branch_cond_t bc)
{
	ExprId icc, m, n, v, nv;

	icc = il.Register(1, SPARC_REG_ICC);

	switch(bc) {
		case BC_A:
			return il.Const(1, 1);
		case BC_N:
			return il.Const(1, 0);

		case BC_E:
			return il.CompareNotEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_Z)), il.Const(1, 0));
		case BC_NE:
			return il.CompareEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_Z)), il.Const(1, 0));

		case BC_NEG:
			return il.CompareNotEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_N)), il.Const(1, 0));
		case BC_POS:
			return il.CompareEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_N)), il.Const(1, 0));

		case BC_VS:
			return il.CompareNotEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_V)), il.Const(1, 0));
		case BC_VC:
			return il.CompareEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_V)), il.Const(1, 0));

		case BC_CS:
			return il.CompareNotEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_C)), il.Const(1, 0));
		case BC_CC:
			return il.CompareEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_C)), il.Const(1, 0));

		case BC_LEU:
			return il.CompareNotEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_C | IL_ICC_Z)), il.Const(1, 0));
		case BC_GU:
			return il.CompareEqual(0,
					il.And(1, icc, il.Const(1, IL_ICC_C | IL_ICC_Z)), il.Const(1, 0));

		case BC_GE:
		case BC_L:
		case BC_LE:
		case BC_G:
			/* n bit xor v bit: set for strictly less / strictly greater */
			n = il.LogicalShiftRight(1,
					il.And(1, icc, il.Const(1, IL_ICC_N)), il.Const(1, 3));
			v = il.And(1, icc, il.Const(1, IL_ICC_V));
			nv = il.Xor(1, n, v);

			if(bc == BC_GE)
				return il.CompareEqual(0, nv, il.Const(1, 0));
			if(bc == BC_L)
				return il.CompareNotEqual(0, nv, il.Const(1, 0));

			m = il.And(1, icc, il.Const(1, IL_ICC_Z));
			if(bc == BC_LE)
				return il.Or(1,
						il.CompareNotEqual(0, nv, il.Const(1, 0)),
						il.CompareNotEqual(0, m, il.Const(1, 0)));
			/* BC_G: n^v clear and z clear */
			return il.And(1,
					il.CompareEqual(0, nv, il.Const(1, 0)),
					il.CompareEqual(0, m, il.Const(1, 0)));

		default:
			return il.Const(1, 1);
	}
}

static void EmitCondBranch(Architecture *arch, LowLevelILFunction &il,
	uint64_t addr, uint64_t target, ExprId cond)
{
	BNLowLevelILLabel *takenLabel = il.GetLabelForAddress(arch, target);
	BNLowLevelILLabel *falseLabel = il.GetLabelForAddress(arch, addr + 4);
	LowLevelILLabel trueCode, falseCode;
	size_t asz = arch->GetAddressSize();

	if(takenLabel && falseLabel) {
		il.AddInstruction(il.If(cond, *takenLabel, *falseLabel));
	}
	else if(takenLabel) {
		il.AddInstruction(il.If(cond, *takenLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(asz, addr + 4)));
	}
	else if(falseLabel) {
		il.AddInstruction(il.If(cond, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(asz, target)));
	}
	else {
		il.AddInstruction(il.If(cond, trueCode, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(asz, addr + 4)));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(asz, target)));
	}
}

static void EmitUncondBranch(Architecture *arch, LowLevelILFunction &il, uint64_t target)
{
	il.AddInstruction(il.Jump(il.ConstPointer(arch->GetAddressSize(), target)));
}

/* ---------------------------------------------------------------------------
 * branch lifting (all forms, driven by capstone detail)
 *
 * returns true if the instruction was a branch and has been lifted
 * ------------------------------------------------------------------------- */

static bool LiftBranches(Architecture *arch, LowLevelILFunction &il,
	uint64_t addr, decomp_result *res)
{
	struct cs_insn *insn = &(res->insn);
	struct cs_sparc *sparc = &(res->detail.sparc);
	uint64_t target = 0;
	size_t asz = arch->GetAddressSize();
	sparc_branch_disp_t disp;

	switch(insn->id) {
		case SPARC_INS_CALL:
			if(SparcBranchTarget(res, &target)) {
				/* V9 delay slot: %o7 receives pc + 8 */
				il.AddInstruction(il.SetRegister(asz, SPARC_REG_LINK,
						il.Const(asz, addr + 8)));
				il.AddInstruction(il.Call(
						il.ConstPointer(asz, target)));
			}
			return true;

		case SPARC_INS_B:
		case SPARC_INS_FB:
			if(!SparcBranchTarget(res, &target))
				return true;
			disp = SparcClassifyBranch(insn->id, insn->mnemonic, sparc->cc);
			if(disp == SPARC_BRANCH_NEVER)
				return true;          /* bn: never taken, fall through */
			if(disp == SPARC_BRANCH_UNCOND) {
				EmitUncondBranch(arch, il, target);
				return true;
			}
			if(insn->id == SPARC_INS_FB) {
				/* float branch: capstone reports the condition as a
				 * SPARC_CC_FCC_* code and, when spelled out, the %fcc field
				 * as an operand; test the 2 bit %fcc value accordingly */
				EmitCondBranch(arch, il, addr, target,
						FloatCondExpr(il, sparc->cc, FccRegOf(sparc)));
			}
			else {
				branch_cond_t bc = BranchCondFromMnemonic(insn->mnemonic);
				if(bc == BC_NONE)
					bc = ccToCond(sparc->cc);
				EmitCondBranch(arch, il, addr, target, CondExpr(il, bc));
			}
			return true;

		case SPARC_INS_BRZ:
		case SPARC_INS_BRNZ:
		case SPARC_INS_BRLZ:
		case SPARC_INS_BRLEZ:
		case SPARC_INS_BRGZ:
		case SPARC_INS_BRGEZ:
		{
			if(!SparcBranchTarget(res, &target))
				return true;

			ExprId regVal;
			if(sparc->op_count && sparc->operands[0].type == SPARC_OP_REG)
				regVal = operToIL_sz(il, &(sparc->operands[0]), asz);
			else
				regVal = il.Const(asz, 0);
			ExprId zero = il.Const(asz, 0);
			ExprId cond;

			switch(insn->id) {
				case SPARC_INS_BRZ:
					cond = il.CompareEqual(0, regVal, zero); break;
				case SPARC_INS_BRNZ:
					cond = il.CompareNotEqual(0, regVal, zero); break;
				case SPARC_INS_BRLZ:
					cond = il.CompareSignedLessThan(0, regVal, zero); break;
				case SPARC_INS_BRLEZ:
					cond = il.CompareSignedLessEqual(0, regVal, zero); break;
				case SPARC_INS_BRGZ:
					cond = il.CompareSignedGreaterThan(0, regVal, zero); break;
				default: /* SPARC_INS_BRGEZ */
					cond = il.CompareSignedGreaterEqual(0, regVal, zero); break;
			}
			EmitCondBranch(arch, il, addr, target, cond);
			return true;
		}

		case SPARC_INS_RETL:
			il.AddInstruction(il.Return(il.Add(asz,
					il.Register(asz, SPARC_REG_LINK), il.Const(asz, 8))));
			return true;

		case SPARC_INS_RET:
		case SPARC_INS_RETT:
			/* ret == jmpl %i7 + 8, %g0 */
			il.AddInstruction(il.Return(il.Add(asz,
					il.Register(asz, SPARC_REG_I7), il.Const(asz, 8))));
			return true;

		case SPARC_INS_JMP:
		case SPARC_INS_JMPL:
		{
			ExprId dest = 0;
			uint64_t off = 0;
			uint32_t rd = SPARC_REG_G0;
			int nreg = 0;

			for(int i = 0; i < (int)sparc->op_count; i++) {
				struct cs_sparc_op *op = &(sparc->operands[i]);
				if(op->type == SPARC_OP_REG) {
					if(nreg == 0)
						dest = operToIL_sz(il, op, asz);
					else
						rd = op->reg;
					nreg++;
				}
				else if(op->type == SPARC_OP_IMM) {
					off += (uint64_t)op->imm;
				}
				else if(op->type == SPARC_OP_MEM) {
					dest = operToIL_sz(il, op, asz);
					nreg++;
				}
			}

			if(!dest)
				dest = il.Const(asz, off);
			else if(off)
				dest = il.Add(asz, dest, il.Const(asz, off));

			if(rd == SPARC_REG_G0) {
				if(SparcJmplIsReturn(res))
					il.AddInstruction(il.Return(dest));
				else
					il.AddInstruction(il.Jump(dest));
			}
			else {
				/* jmpl stores pc + 8 into rd */
				il.AddInstruction(il.SetRegister(asz, rd, il.Const(asz, addr + 8)));
				il.AddInstruction(il.Jump(dest));
			}
			return true;
		}

		default:
			return false;
	}
}

/* ---------------------------------------------------------------------------
 * main lifter
 * ------------------------------------------------------------------------- */

/* returns TRUE - if this IL continues
          FALSE - if this IL terminates a block */
bool GetLowLevelILForSparcInstruction(Architecture *arch, LowLevelILFunction &il,
  const uint8_t* data, uint64_t addr, decomp_result *res, bool le)
{
	bool rc = true;
	struct cs_insn *insn = &(res->insn);
	struct cs_detail *detail = &(res->detail);
	struct cs_sparc *sparc = &(detail->sparc);
	size_t asz = arch->GetAddressSize();

	(void)data;
	(void)le;

	/* all branch/call/return forms go through the branch lifter */
	if(LiftBranches(arch, il, addr, res) == true)
		return true;

	cs_sparc_op *oper0=NULL, *oper1=NULL, *oper2=NULL, *oper3=NULL, *oper4=NULL;
	#define REQUIRE1OP if(!oper0) goto ReturnUnimpl;
	#define REQUIRE2OPS if(!oper0 || !oper1) goto ReturnUnimpl;
	#define REQUIRE3OPS if(!oper0 || !oper1 || !oper2) goto ReturnUnimpl;
	#define REQUIRE4OPS if(!oper0 || !oper1 || !oper2 || !oper3) goto ReturnUnimpl;
	#define REQUIRE5OPS if(!oper0 || !oper1 || !oper2 || !oper3 || !oper4) goto ReturnUnimpl;

	switch(sparc->op_count) {
		default:
		case 5: oper4 = &(sparc->operands[4]); FALL_THROUGH
		case 4: oper3 = &(sparc->operands[3]); FALL_THROUGH
		case 3: oper2 = &(sparc->operands[2]); FALL_THROUGH
		case 2: oper1 = &(sparc->operands[1]); FALL_THROUGH
		case 1: oper0 = &(sparc->operands[0]); FALL_THROUGH
		case 0: while(0);
	}

	ExprId ei0;

	/* helper: write a 32 bit result into a (possibly 64 bit) register */
	#define SET32(reg, expr) do { \
		if((reg) != SPARC_REG_G0) { \
			ExprId _e = (expr); \
			if(asz == 8) \
				_e = il.ZeroExtend(8, _e); \
			il.AddInstruction(il.SetRegister(asz, (reg), _e)); \
		} \
	} while(0)

	#define SETREG(reg, expr) do { \
		if((reg) != SPARC_REG_G0) \
			il.AddInstruction(il.SetRegister(asz, (reg), (expr))); \
	} while(0)

	switch(insn->id) {

	/* ---- arithmetic ---------------------------------------------------- */

		case SPARC_INS_ADD:
		case SPARC_INS_ADDCC:
		case SPARC_INS_ADDX:
		case SPARC_INS_ADDXCC:
		{
			/* integer arithmetic is 64 bits wide on SPARCv9.  ADDX/ADDXCC are
			 * the V8 names for ADDC/ADDCcc: they also add CCR.icc.c. */
			REQUIRE3OPS
			size_t sz = asz;
			bool carry = (insn->id == SPARC_INS_ADDX || insn->id == SPARC_INS_ADDXCC);
			ExprId a0 = operToIL_sz(il, oper0, sz);
			ExprId a1 = operToIL_sz(il, oper1, sz);
			ei0 = il.Add(sz, a0, a1);
			if(carry)
				ei0 = il.Add(sz, ei0, IccCarry(il, sz));
			if(insn->id == SPARC_INS_ADDCC || insn->id == SPARC_INS_ADDXCC)
				EmitIccView(il, sz, ei0, a0, a1, ICC_KIND_ADD);
			SETREG(oper2->reg, ei0);
			break;
		}

		case SPARC_INS_SUB:
		case SPARC_INS_SUBCC:
		case SPARC_INS_SUBX:
		case SPARC_INS_SUBXCC:
		{
			/* SUBX/SUBXCC are the V8 names for SUBC/SUBCcc: they also subtract
			 * CCR.icc.c (used for multi-precision arithmetic) */
			REQUIRE3OPS
			size_t sz = asz;
			bool carry = (insn->id == SPARC_INS_SUBX || insn->id == SPARC_INS_SUBXCC);
			ExprId a0 = operToIL_sz(il, oper0, sz);
			ExprId a1 = operToIL_sz(il, oper1, sz);
			ei0 = il.Sub(sz, a0, a1);
			if(carry)
				ei0 = il.Sub(sz, ei0, IccCarry(il, sz));
			if(insn->id == SPARC_INS_SUBCC || insn->id == SPARC_INS_SUBXCC)
				EmitIccView(il, sz, ei0, a0, a1, ICC_KIND_SUB);
			SETREG(oper2->reg, ei0);
			break;
		}

		case SPARC_INS_CMP:
		{
			REQUIRE2OPS
			ei0 = il.Sub(asz, operToIL(il, oper0), operToIL(il, oper1));
			EmitIccView(il, asz, ei0, operToIL(il, oper0), operToIL(il, oper1),
					ICC_KIND_SUB);
			break;
		}

		case SPARC_INS_UMUL:
		case SPARC_INS_UMULCC:
		case SPARC_INS_SMUL:
		case SPARC_INS_SMULCC:
		{
			REQUIRE3OPS
			ExprId m0 = operToIL_sz(il, oper0, 4);
			ExprId m1 = operToIL_sz(il, oper1, 4);
			bool sgn = (insn->id == SPARC_INS_SMUL || insn->id == SPARC_INS_SMULCC);
			bool cc  = (insn->id == SPARC_INS_UMULCC || insn->id == SPARC_INS_SMULCC);

			if(asz == 8) {
				/* SPARCv9: the entire 64 bit product is written to rd and
				 * %y is left untouched */
				ei0 = il.Mult(8,
						sgn ? il.SignExtend(8, m0) : il.ZeroExtend(8, m0),
						sgn ? il.SignExtend(8, m1) : il.ZeroExtend(8, m1));
				if(cc)
					EmitIcc(il, 8, ei0, ei0, ei0, ICC_KIND_LOGIC);
				SETREG(oper2->reg, ei0);
			} else {
				/* SPARCv8: the low half goes to rd and the high half to %y,
				 * which is what 'rd %y' reads in compiler generated division
				 * sequences */
				ei0 = il.Mult(4, m0, m1);
				if(cc)
					EmitIcc(il, 4, ei0, m0, m1, ICC_KIND_LOGIC);
				ExprId wide = sgn ?
						il.Mult(8, il.SignExtend(8, m0), il.SignExtend(8, m1)) :
						il.Mult(8, il.ZeroExtend(8, m0), il.ZeroExtend(8, m1));
				ExprId hi = sgn ? il.ArithShiftRight(8, wide, il.Const(8, 32))
						: il.LogicalShiftRight(8, wide, il.Const(8, 32));
				il.AddInstruction(il.SetRegister(4, SPARC_REG_Y, il.LowPart(4, hi)));
				SET32(oper2->reg, ei0);
			}
			break;
		}

		case SPARC_INS_MULX:
			REQUIRE3OPS
			ei0 = il.Mult(8, operToIL_sz(il, oper0, 8), operToIL_sz(il, oper1, 8));
			SETREG(oper2->reg, ei0);
			break;

		case SPARC_INS_UDIV:
		case SPARC_INS_UDIVCC:
			REQUIRE3OPS
			ei0 = il.DivUnsigned(4, operToIL_sz(il, oper0, 4), operToIL_sz(il, oper1, 4));
			if(insn->id == SPARC_INS_UDIVCC)
				EmitIcc(il, 4, ei0, ei0, ei0, ICC_KIND_LOGIC);
			SET32(oper2->reg, ei0);
			break;

		case SPARC_INS_SDIV:
		case SPARC_INS_SDIVCC:
			REQUIRE3OPS
			ei0 = il.DivSigned(4, operToIL_sz(il, oper0, 4), operToIL_sz(il, oper1, 4));
			if(insn->id == SPARC_INS_SDIVCC)
				EmitIcc(il, 4, ei0, ei0, ei0, ICC_KIND_LOGIC);
			SET32(oper2->reg, ei0);
			break;

		case SPARC_INS_UDIVX:
			REQUIRE3OPS
			ei0 = il.DivUnsigned(8, operToIL_sz(il, oper0, 8), operToIL_sz(il, oper1, 8));
			SETREG(oper2->reg, ei0);
			break;

		case SPARC_INS_SDIVX:
			REQUIRE3OPS
			ei0 = il.DivSigned(8, operToIL_sz(il, oper0, 8), operToIL_sz(il, oper1, 8));
			SETREG(oper2->reg, ei0);
			break;

	/* ---- logical -------------------------------------------------------- */

		case SPARC_INS_AND:
		case SPARC_INS_ANDCC:
		case SPARC_INS_ANDN:
		case SPARC_INS_ANDNCC:
		case SPARC_INS_OR:
		case SPARC_INS_ORCC:
		case SPARC_INS_ORN:
		case SPARC_INS_ORNCC:
		case SPARC_INS_XOR:
		case SPARC_INS_XORCC:
		case SPARC_INS_XNOR:
		case SPARC_INS_XNORCC:
		{
			/* Two operand form is a %g0-sourced alias: capstone reports
			 * 'mov src, dst' as OR and 'not src, dst' as ORN (id of the
			 * underlying boolean op) with only two operands. */
			if(!oper2 && oper1) {
				if(oper1->type != SPARC_OP_REG)
					goto ReturnUnimpl;
				ei0 = operToIL(il, oper0);
				switch(insn->id) {
					case SPARC_INS_OR:  case SPARC_INS_XOR:   /* mov */
						break;
					case SPARC_INS_ORN: case SPARC_INS_XNOR:  /* not */
						ei0 = il.Not(asz, ei0); break;
					case SPARC_INS_AND: case SPARC_INS_ANDN:  /* clr */
						ei0 = il.Const(asz, 0); break;
					default:
						goto ReturnUnimpl;
				}
				SETREG(oper1->reg, ei0);
				break;
			}
			REQUIRE3OPS
			switch(insn->id) {
				case SPARC_INS_AND: case SPARC_INS_ANDCC:
					ei0 = il.And(asz, operToIL(il, oper0), operToIL(il, oper1)); break;
				case SPARC_INS_ANDN: case SPARC_INS_ANDNCC:
					ei0 = il.And(asz, operToIL(il, oper0),
							il.Not(asz, operToIL(il, oper1))); break;
				case SPARC_INS_OR: case SPARC_INS_ORCC:
					ei0 = il.Or(asz, operToIL(il, oper0), operToIL(il, oper1)); break;
				case SPARC_INS_ORN: case SPARC_INS_ORNCC:
					ei0 = il.Or(asz, operToIL(il, oper0),
							il.Not(asz, operToIL(il, oper1))); break;
				case SPARC_INS_XOR: case SPARC_INS_XORCC:
					ei0 = il.Xor(asz, operToIL(il, oper0), operToIL(il, oper1)); break;
				default: /* XNOR */
					ei0 = il.Xor(asz, operToIL(il, oper0),
							il.Not(asz, operToIL(il, oper1))); break;
			}
			switch(insn->id) {
				case SPARC_INS_ANDCC: case SPARC_INS_ANDNCC:
				case SPARC_INS_ORCC:  case SPARC_INS_ORNCC:
				case SPARC_INS_XORCC: case SPARC_INS_XNORCC:
					EmitIccView(il, asz, ei0, ei0, ei0, ICC_KIND_LOGIC);
				default:
					break;
			}
			SETREG(oper2->reg, ei0);
			break;
		}

	/* ---- shifts ---------------------------------------------------------- */

		case SPARC_INS_SLL:
			REQUIRE3OPS
			ei0 = il.ShiftLeft(4, operToIL_sz(il, oper0, 4), operToIL_sz(il, oper1, 4));
			SET32(oper2->reg, ei0);
			break;

		case SPARC_INS_SRL:
			REQUIRE3OPS
			ei0 = il.LogicalShiftRight(4, operToIL_sz(il, oper0, 4), operToIL_sz(il, oper1, 4));
			SET32(oper2->reg, ei0);
			break;

		case SPARC_INS_SRA:
			/* SRA shifts the low 32 bits and replicates bit 31 through the rest
			 * of the register on SPARCv9 (SRAX is the true 64 bit shift) */
			REQUIRE3OPS
			ei0 = il.ArithShiftRight(4, operToIL_sz(il, oper0, 4), operToIL_sz(il, oper1, 4));
			if(asz == 8) SETREG(oper2->reg, il.SignExtend(8, ei0));
			else         SET32(oper2->reg, ei0);
			break;

		case SPARC_INS_SLLX:
			REQUIRE3OPS
			ei0 = il.ShiftLeft(8, operToIL_sz(il, oper0, 8), operToIL_sz(il, oper1, 8));
			SETREG(oper2->reg, ei0);
			break;

		case SPARC_INS_SRLX:
			REQUIRE3OPS
			ei0 = il.LogicalShiftRight(8, operToIL_sz(il, oper0, 8), operToIL_sz(il, oper1, 8));
			SETREG(oper2->reg, ei0);
			break;

		case SPARC_INS_SRAX:
			REQUIRE3OPS
			ei0 = il.ArithShiftRight(8, operToIL_sz(il, oper0, 8), operToIL_sz(il, oper1, 8));
			SETREG(oper2->reg, ei0);
			break;

	/* ---- misc ------------------------------------------------------------ */

		case SPARC_INS_MOV:
			REQUIRE2OPS
			SETREG(oper1->reg, operToIL(il, oper0));
			break;

		case SPARC_INS_SETHI:
			REQUIRE2OPS
			ei0 = il.ShiftLeft(4, operToIL_sz(il, oper0, 4), il.Const(4, 10));
			SET32(oper1->reg, ei0);
			break;

		case SPARC_INS_NOP:
			il.AddInstruction(il.Nop());
			break;

		case SPARC_INS_FLUSHW:
		case SPARC_INS_MEMBAR:
			il.AddInstruction(il.Nop());
			break;

		case SPARC_INS_UNIMP:
			/* illegal instruction (usually 0x00000000 linker padding).
			 * Modeled as a no-op: it does trap on real hardware, but treating
			 * it as a terminator stops analysis from following the code that
			 * actually follows the padding. */
			il.AddInstruction(il.Nop());
			break;

		case SPARC_INS_RD:
			/* capstone reports no operands for rd (the destination register is
			 * lost), so decode it from the instruction word.  Only the plain
			 * 'rd %y, %rd' form (no state register field) is modelled. */
			{
				uint32_t w = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
				             ((uint32_t)data[2] << 8) | (uint32_t)data[3];
				if(w & 0x7ffff)
					goto ReturnUnimpl;	/* rd %tick/%pc/%fprs...: not modelled */
				int n = (w >> 25) & 0x1f;
				uint32_t reg = n < 8  ? SPARC_REG_G0 + n :
				               n < 16 ? SPARC_REG_O0 + (n - 8) :
				               n < 24 ? SPARC_REG_L0 + (n - 16)
				                      : SPARC_REG_I0 + (n - 24);
				SETREG(reg, il.Register(asz, SPARC_REG_Y));
			}
			break;

		case SPARC_INS_WR:
			/* wr %rs1, %rs2, %y  ->  %y = %rs1 + %rs2 */
			if(oper2 && oper2->reg == SPARC_REG_Y &&
					oper0 && oper1 &&
					oper0->type == SPARC_OP_REG && oper1->type == SPARC_OP_REG)
				SETREG(SPARC_REG_Y, il.Add(asz, operToIL(il, oper0),
							operToIL(il, oper1)));
			else
				goto ReturnUnimpl;
			break;

		case SPARC_INS_T:
			/* Linux/Solaris syscall trap */
			if(oper0 && oper0->type == SPARC_OP_IMM &&
					(oper0->imm == 8 || oper0->imm == 0x16))
				il.AddInstruction(il.SystemCall());
			else
				il.AddInstruction(il.Unimplemented());
			break;

	/* ---- loads ----------------------------------------------------------- */

		case SPARC_INS_LD:     /* 32 bit load, zero extended on v9 */
		case SPARC_INS_LDX:    /* 64 bit load */
		case SPARC_INS_LDSB:
		case SPARC_INS_LDSH:
		case SPARC_INS_LDSW:
		case SPARC_INS_LDUB:
		case SPARC_INS_LDUH:
		{
			REQUIRE2OPS
			size_t n;
			bool sxt = false;

			switch(insn->id) {
				case SPARC_INS_LDSB: n = 1; sxt = true; break;
				case SPARC_INS_LDUB: n = 1; break;
				case SPARC_INS_LDSH: n = 2; sxt = true; break;
				case SPARC_INS_LDUH: n = 2; break;
				case SPARC_INS_LDSW: n = 4; sxt = true; break;
				case SPARC_INS_LDX:  n = 8; break;
				default:             n = 4; break;   /* SPARC_INS_LD */
			}

			/* the destination may be an 8 byte FP register even on the 32 bit
			 * architecture, so extend to the destination width */
			size_t dw = arch->GetRegisterInfo(oper1->reg).size;
			if(dw == 0)
				dw = asz;
			ei0 = il.Load(n, operToIL(il, oper0));
			if(n < dw) {
				if(sxt && !IsFReg(oper1->reg))
					ei0 = il.SignExtend(dw, ei0);
				else
					ei0 = il.ZeroExtend(dw, ei0);
			} else if(n > dw) {
				ei0 = il.LowPart(dw, ei0);
			}
			if(oper1->reg != SPARC_REG_G0)
				il.AddInstruction(il.SetRegister(dw, oper1->reg, ei0));
			break;
		}

	/* ---- stores ----------------------------------------------------------- */

		case SPARC_INS_ST:
		case SPARC_INS_STB:
		case SPARC_INS_STH:
		case SPARC_INS_STX:
		{
			REQUIRE2OPS
			size_t n = (insn->id == SPARC_INS_STB) ? 1 :
			           (insn->id == SPARC_INS_STH) ? 2 :
			           (insn->id == SPARC_INS_STX) ? 8 : 4;
			/* an FP source register is 8 bytes wide, so read it at full width
			 * and hand the store the low bytes it asked for */
			size_t rw = arch->GetRegisterInfo(oper0->reg).size;
			if(rw == 0)
				rw = asz;
			ExprId src = il.Register(rw, oper0->reg);
			ei0 = il.Store(n, operToIL_sz(il, oper1, asz),
					rw > n ? il.LowPart(n, src) : src);
			il.AddInstruction(ei0);
			break;
		}

	/* 8 byte accesses; the FP forms move a whole register (a register pair on
	 * real hardware, which the 8 byte FP model represents directly) */

		case SPARC_INS_LDD:
		case SPARC_INS_LDQ:
			REQUIRE2OPS
			if(arch->GetRegisterInfo(oper1->reg).size != 8)
				goto ReturnUnimpl;	/* integer quad: needs a pair model */
			il.AddInstruction(il.SetRegister(8, oper1->reg,
					il.Load(8, operToIL(il, oper0))));
			break;

		case SPARC_INS_STD:
		case SPARC_INS_STQ:
			REQUIRE2OPS
			if(arch->GetRegisterInfo(oper0->reg).size != 8)
				goto ReturnUnimpl;
			il.AddInstruction(il.Store(8, operToIL_sz(il, oper1, asz),
					il.Register(8, oper0->reg)));
			break;

	/* ---- register windows --------------------------------------------------
	 *
	 * capstone's register enum has no I6/O6 entries (%i6 == SPARC_REG_FP,
	 * %o6 == SPARC_REG_SP) so window slot arithmetic must use explicit maps.
	 */

		case SPARC_INS_SAVE:
		case SPARC_INS_RESTORE:
		{
			static const uint32_t iregs[8] = {
				SPARC_REG_I0, SPARC_REG_I1, SPARC_REG_I2, SPARC_REG_I3,
				SPARC_REG_I4, SPARC_REG_I5, SPARC_REG_FP,  SPARC_REG_I7
			};
			static const uint32_t oregs[8] = {
				SPARC_REG_O0, SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3,
				SPARC_REG_O4, SPARC_REG_O5, SPARC_REG_SP,  SPARC_REG_O7
			};
			static const uint32_t lregs[8] = {
				SPARC_REG_L0, SPARC_REG_L1, SPARC_REG_L2, SPARC_REG_L3,
				SPARC_REG_L4, SPARC_REG_L5, SPARC_REG_L6, SPARC_REG_L7
			};
			int i;
			ExprId newSp = 0;

			/* compute the new %o6 value first (operands read old state) */
			if(insn->id == SPARC_INS_SAVE) {
				if(oper0 && oper1)
					newSp = il.Add(asz, operToIL_sz(il, oper0, asz),
							operToIL_sz(il, oper1, asz));
				else if(oper0)
					newSp = operToIL_sz(il, oper0, asz);
				else
					newSp = il.Register(asz, SPARC_REG_SP);
			}
			else {
				/* restore: %o6 <- %i6 - (rs1o + rs2) ; capstone prints the
				 * first source as %sp but hardware reads %i6, our FP */
				ExprId src = il.Register(asz, SPARC_REG_FP);
				if(oper1) {
					if(oper0 && oper0->type == SPARC_OP_REG &&
							oper0->reg == SPARC_REG_G0 && oper1->type == SPARC_OP_IMM)
						src = il.Sub(asz, src, il.Const(asz, oper1->imm));
					else if(oper0 == NULL || (oper0->type == SPARC_OP_REG &&
							oper0->reg == SPARC_REG_SP)) {
						if(oper1->type == SPARC_OP_IMM)
							src = il.Sub(asz, src, il.Const(asz, oper1->imm));
						else
							src = il.Sub(asz, src, operToIL_sz(il, oper1, asz));
					}
					else
						src = il.Sub(asz,
								operToIL_sz(il, oper0, asz),
								operToIL_sz(il, oper1, asz));
				}
				newSp = src;
			}

			if(insn->id == SPARC_INS_SAVE) {
				/* new locals <- old ins */
				for(i = 0; i < 8; i++)
					il.AddInstruction(il.SetRegister(asz, lregs[i],
							il.Register(asz, iregs[i])));
				/* new ins <- old outs (slot 6: %fp <- %sp) */
				for(i = 0; i < 8; i++)
					il.AddInstruction(il.SetRegister(asz, iregs[i],
							il.Register(asz, oregs[i])));
				/* new outs are undefined (slot 6 %sp fixed up below) */
				for(i = 0; i < 8; i++)
					il.AddInstruction(il.SetRegister(asz, oregs[i],
							il.Undefined()));
			}
			else {
				/* new outs <- old ins (slot 6 %sp fixed up below) */
				for(i = 0; i < 8; i++)
					il.AddInstruction(il.SetRegister(asz, oregs[i],
							il.Register(asz, iregs[i])));
				/* new ins <- old locals */
				for(i = 0; i < 8; i++)
					il.AddInstruction(il.SetRegister(asz, iregs[i],
							il.Register(asz, lregs[i])));
				/* new locals are undefined */
				for(i = 0; i < 8; i++)
					il.AddInstruction(il.SetRegister(asz, lregs[i],
							il.Undefined()));
			}

			il.AddInstruction(il.SetRegister(asz, SPARC_REG_SP, newSp));
			break;
		}

	/* ---- swap ------------------------------------------------------------- */

		case SPARC_INS_SWAP:
			REQUIRE2OPS
			/* swap reg,[rs1+rs2]: emulate as load/store pair */
			ei0 = il.Load(asz, operToIL_sz(il, oper1, asz));
			SETREG(oper0->reg, ei0);
			il.AddInstruction(il.Store(asz, operToIL_sz(il, oper1, asz),
					operToIL_sz(il, oper0, asz)));
			break;

	/* ---- floating point ----------------------------------------------------
	 *
	 * The Q (quad precision) forms are deliberately absent: they need a
	 * register pair model and never occur in the samples.
	 */

		case SPARC_INS_FMOVS:
			REQUIRE2OPS
			FWrite(il, oper1, 4, FRead(il, oper0, 4));
			break;

		case SPARC_INS_FMOVD:
			REQUIRE2OPS
			FWrite(il, oper1, 8, FRead(il, oper0, 8));
			break;

		case SPARC_INS_FADDS: case SPARC_INS_FSUBS:
		case SPARC_INS_FMULS: case SPARC_INS_FDIVS:
		case SPARC_INS_FADDD: case SPARC_INS_FSUBD:
		case SPARC_INS_FMULD: case SPARC_INS_FDIVD:
		{
			REQUIRE3OPS
			size_t fs = (insn->id == SPARC_INS_FADDD || insn->id == SPARC_INS_FSUBD ||
			             insn->id == SPARC_INS_FMULD || insn->id == SPARC_INS_FDIVD) ? 8 : 4;
			ExprId a = FRead(il, oper0, fs);
			ExprId b = FRead(il, oper1, fs);
			switch(insn->id) {
				case SPARC_INS_FADDS: case SPARC_INS_FADDD:
					FWrite(il, oper2, fs, il.FloatAdd(fs, a, b)); break;
				case SPARC_INS_FSUBS: case SPARC_INS_FSUBD:
					FWrite(il, oper2, fs, il.FloatSub(fs, a, b)); break;
				case SPARC_INS_FMULS: case SPARC_INS_FMULD:
					FWrite(il, oper2, fs, il.FloatMult(fs, a, b)); break;
				default: /* SPARC_INS_FDIVS / SPARC_INS_FDIVD */
					FWrite(il, oper2, fs, il.FloatDiv(fs, a, b)); break;
			}
			break;
		}

		case SPARC_INS_FABSS: case SPARC_INS_FABSD:
		case SPARC_INS_FNEGS: case SPARC_INS_FNEGD:
		case SPARC_INS_FSQRTS: case SPARC_INS_FSQRTD:
		{
			REQUIRE2OPS
			size_t fs = (insn->id == SPARC_INS_FABSD || insn->id == SPARC_INS_FNEGD ||
			             insn->id == SPARC_INS_FSQRTD) ? 8 : 4;
			ExprId a = FRead(il, oper0, fs);
			switch(insn->id) {
				case SPARC_INS_FABSS: case SPARC_INS_FABSD:
					FWrite(il, oper1, fs, il.FloatAbs(fs, a)); break;
				case SPARC_INS_FNEGS: case SPARC_INS_FNEGD:
					FWrite(il, oper1, fs, il.FloatNeg(fs, a)); break;
				default: /* SPARC_INS_FSQRTS / SPARC_INS_FSQRTD */
					FWrite(il, oper1, fs, il.FloatSqrt(fs, a)); break;
			}
			break;
		}

		case SPARC_INS_FSMULD:
			/* single precision operands, double precision result: converting
			 * to double first is exact, so the product is computed exactly */
			REQUIRE3OPS
			FWrite(il, oper2, 8, il.FloatMult(8,
					il.FloatConvert(8, FRead(il, oper0, 4)),
					il.FloatConvert(8, FRead(il, oper1, 4))));
			break;

		case SPARC_INS_FITOS:
			REQUIRE2OPS
			FWrite(il, oper1, 4, il.IntToFloat(4, FRead(il, oper0, 4)));
			break;

		case SPARC_INS_FITOD:
			REQUIRE2OPS
			FWrite(il, oper1, 8, il.IntToFloat(8, FRead(il, oper0, 4)));
			break;

		case SPARC_INS_FDTOI:
			REQUIRE2OPS
			FWrite(il, oper1, 4, il.FloatToInt(4, FRead(il, oper0, 8)));
			break;

		case SPARC_INS_FSTOI:
			REQUIRE2OPS
			FWrite(il, oper1, 4, il.FloatToInt(4, FRead(il, oper0, 4)));
			break;

		case SPARC_INS_FDTOS:
			REQUIRE2OPS
			FWrite(il, oper1, 4, il.FloatConvert(4, FRead(il, oper0, 8)));
			break;

		case SPARC_INS_FSTOD:
			REQUIRE2OPS
			FWrite(il, oper1, 8, il.FloatConvert(8, FRead(il, oper0, 4)));
			break;

		case SPARC_INS_FCMPS: case SPARC_INS_FCMPES:
		case SPARC_INS_FCMPD: case SPARC_INS_FCMPED:
		{
			/* set %fccn: 0 = equal, 1 = less, 2 = greater, 3 = unordered.
			 * The trapping (E) forms are modelled like the quiet ones. */
			REQUIRE2OPS
			size_t fs = (insn->id == SPARC_INS_FCMPD || insn->id == SPARC_INS_FCMPED) ? 8 : 4;
			ExprId a = FRead(il, oper0, fs);
			ExprId b = FRead(il, oper1, fs);
			ExprId code = il.Or(1,
					il.And(1, il.FloatCompareLessThan(1, a, b), il.Const(1, 1)),
					il.Or(1,
						il.And(1, il.FloatCompareGreaterThan(1, a, b), il.Const(1, 2)),
						il.And(1, il.FloatCompareUnordered(1, a, b), il.Const(1, 3))));
			il.AddInstruction(il.SetRegister(1, FccRegOf(sparc), code));
			break;
		}

	ReturnUnimpl:
	default:
		MYLOG("%s:%s() returning Unimplemented(...) on:\n",
		  __FILE__, __func__);

		MYLOG("    %08llx: %02X %02X %02X %02X %s %s\n",
		  addr, data[0], data[1], data[2], data[3],
		  res->insn.mnemonic, res->insn.op_str);

		il.AddInstruction(il.Unimplemented());
	}

	return rc;
}
