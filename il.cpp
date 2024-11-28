#include <binaryninjaapi.h>

#include "disassembler.h"

using namespace BinaryNinja;

#include "il.h"
#include "util.h"

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

#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug

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
			//MYLOG("case PPC_OP_REG returning reg %d\n", op->reg);
			if (options & OTI_GPR0_ZERO)
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
			/* the immediate is just a plain boring immediate */
			else {
				res = il.Const(archsz, op->imm);
			}
			break;

		case SPARC_OP_MEM:
			//MYLOG("case PPC_OP_MEM returning regs (%d,%d)\n", op->mem.base, op->mem.disp);

			if (options & OTI_GPR0_ZERO)
				res = il.Const(archsz, 0);
			else
				res = il.Register(archsz, op->mem.base);

			if(options & OTI_IMM_BIAS)
				res = il.Add(archsz, res, il.Const(archsz, op->mem.disp + extra));
			else
				res = il.Add(archsz, res, il.Const(archsz, op->mem.disp));
			break;

		case SPARC_OP_INVALID:
		default:
			MYLOG("ERROR: don't know how to convert operand to IL\n");
			res = il.Unimplemented();
	}

	switch(options) {
		case OTI_SEXT32_REGS:
			if(op->type == SPARC_OP_REG)
				res = il.SignExtend(4, res);
			break;
		case OTI_SEXT64_REGS:
			if(op->type == SPARC_OP_REG)
				res = il.SignExtend(8, res);
			break;
		case OTI_ZEXT32_REGS:
			if(op->type == SPARC_OP_REG)
				res = il.ZeroExtend(4, res);
			break;
		case OTI_ZEXT64_REGS:
			if(op->type == SPARC_OP_REG)
				res = il.ZeroExtend(8, res);
			break;
		case OTI_SEXT32_IMMS:
			if(op->type == SPARC_OP_REG)
				res = il.SignExtend(4, res);
			break;
		case OTI_SEXT64_IMMS:
			if(op->type == SPARC_OP_REG)
				res = il.SignExtend(8, res);
			break;
		case OTI_ZEXT32_IMMS:
			if(op->type == SPARC_OP_REG)
				res = il.ZeroExtend(4, res);
			break;
		case OTI_ZEXT64_IMMS:
			if(op->type == SPARC_OP_REG)
				res = il.ZeroExtend(8, res);
			break;
	}

	return res;
}

#define operToIL(il, op)	operToIL_sz(il, op, arch->GetAddressSize())

/* map PPC_REG_CRX to an IL flagwrite type (a named set of written flags */
int crxToFlagWriteType(int crx, bool signedComparison = true)
{
	/* when we have more flags... */
	switch(crx)
	{
		case SPARC_REG_XCC:
			return signedComparison ? IL_FLAGWRITE_CC_S : IL_FLAGWRITE_CC_U;
		default:
			return 0;
	}
}


static ExprId ExtractConditionClause(LowLevelILFunction& il, uint8_t crBit, bool negate = false)
{
	uint32_t flagBase = (crBit / 4) * 10;

	switch (crBit & 3)
	{
		case IL_FLAG_LT:
			if (negate) return il.FlagGroup(flagBase + IL_FLAGGROUP_CC_GE);
			else        return il.FlagGroup(flagBase + IL_FLAGGROUP_CC_LT);
		case IL_FLAG_GT:
			if (negate) return il.FlagGroup(flagBase + IL_FLAGGROUP_CC_LE);
			else        return il.FlagGroup(flagBase + IL_FLAGGROUP_CC_GT);
		case IL_FLAG_EQ:
			if (negate) return il.FlagGroup(flagBase + IL_FLAGGROUP_CC_NE);
			else        return il.FlagGroup(flagBase + IL_FLAGGROUP_CC_EQ);
	}

	ExprId result = il.Flag(crBit);

	if (negate)
		result = il.Not(0, result);

	return result;
}


static bool LiftConditionalBranch(LowLevelILFunction& il, uint8_t bo, uint8_t bi, BNLowLevelILLabel& takenLabel, BNLowLevelILLabel& falseLabel)
{
	bool testsCtr = !(bo & 4);
	bool testsCrBit = !(bo & 0x10);
	bool isConditional = testsCtr || testsCrBit;

	if (testsCtr)
	{
	}

	if (testsCrBit)
	{
	}

	return isConditional;
}

static bool LiftBranches(Architecture* arch, LowLevelILFunction &il, const uint8_t* data, uint64_t addr, bool le)
{
	bool result = false;
	uint32_t insn = *(const uint32_t *) data;
	ExprId dest = 0;
	BNLowLevelILLabel *label = 0;
	uint64_t target = 0;
	BNLowLevelILLabel *existingTakenLabel = 0;
	BNLowLevelILLabel *existingFalseLabel = 0;
	LowLevelILLabel trueCode, falseCode;
	ExprId condition = 0;

	if (!le)
	{
		insn = bswap32(insn);
	}

	if ((insn & SPARC_CALL_MASK) == SPARC_CALL_MASKED)
	{
		target = sign_extend_bitnn(insn, 0, 30);

		target = target << 2;

		/* account for absolute addressing */
		target += addr;

		label = il.GetLabelForAddress(arch, target);
	
		dest = il.ConstPointer(arch->GetAddressSize(), target);

		il.AddInstruction(il.Call(dest));
		
		result = true;
	}
	else if (
		((insn & SPARC_B_MASK) == SPARC_BIC_MASKED) ||
		((insn & SPARC_B_MASK) == SPARC_BPC_MASKED))
	{
		int bitwidth = 0;
		int bitoffset = 0;

		if ((insn & SPARC_B_MASK) == SPARC_BIC_MASKED)
		{
			bitwidth = SPARC_BIC_BITWIDTH;
			bitoffset = 0;
		}
		else
		{
			bitwidth = SPARC_BPC_BITWIDTH;
			bitoffset = 0;
		}

		target = sign_extend_bitnn(insn, bitoffset, bitwidth);

		target = target << 2;
		target += addr;
		
		dest = il.ConstPointer(arch->GetAddressSize(), target);

		// conditional branch
		if ((insn >> 25) & 0x7)
		{
			condition = il.CompareEqual(4, il.Const(1, 1), il.Const(1, 1));
			existingTakenLabel = il.GetLabelForAddress(arch, target);
			existingFalseLabel = il.GetLabelForAddress(arch, addr + 4);

			if (existingTakenLabel && existingFalseLabel)
			{
				il.AddInstruction(il.If(condition, *existingTakenLabel, *existingFalseLabel));
			}
			if (existingTakenLabel)
			{
				il.AddInstruction(il.If(condition, *existingTakenLabel, falseCode));
				il.MarkLabel(falseCode);
				il.AddInstruction(il.Jump(il.ConstPointer(arch->GetAddressSize(), addr + 4)));
			}

			if (existingFalseLabel)
			{
				il.AddInstruction(il.If(condition, trueCode, *existingFalseLabel));
				il.MarkLabel(trueCode);
				il.AddInstruction(il.Jump(il.ConstPointer(arch->GetAddressSize(), target)));
			}

		}
		// branch always
		else if ((insn >> 25) & 0x8)
		{
			il.AddInstruction(il.Jump(dest));
		}
		result = true;
	}
	else if ((insn & SPARC_BP_MASK) == SPARC_BP_MASKED)
	{
		target = (insn & 0x00300000) >> 6;
		target |= (insn & 0x00003fff);

		// 16 bit immediate
		if ((target >> 15) == 1)
		{
			target |= 0xffffffffffff0000;
		}

		target = target << 2;
		target += addr;

		condition = il.CompareEqual(4, il.Const(1, 1), il.Const(1, 1));
		existingTakenLabel = il.GetLabelForAddress(arch, target);
		existingFalseLabel = il.GetLabelForAddress(arch, addr + 4);

		if (existingTakenLabel && existingFalseLabel)
		{
			il.AddInstruction(il.If(condition, *existingTakenLabel, *existingFalseLabel));
		}
		if (existingTakenLabel)
		{
			il.AddInstruction(il.If(condition, *existingTakenLabel, falseCode));
			il.MarkLabel(falseCode);
			il.AddInstruction(il.Jump(il.ConstPointer(arch->GetAddressSize(), addr + 4)));
		}

		if (existingFalseLabel)
		{
			il.AddInstruction(il.If(condition, trueCode, *existingFalseLabel));
			il.MarkLabel(trueCode);
			il.AddInstruction(il.Jump(il.ConstPointer(arch->GetAddressSize(), target)));
		}

		result = true;
	}

	return result;
}

static ExprId ByteReverseRegister(LowLevelILFunction &il, uint32_t reg, size_t size)
{
	ExprId swap = BN_INVALID_EXPR;

	for (size_t srcIndex = 0; srcIndex < size; srcIndex++)
	{
		ExprId extracted = il.Register(4, reg);
		size_t dstIndex = size - srcIndex - 1;

		if (dstIndex > srcIndex)
		{
			ExprId mask = il.Const(4, 0xffull << (srcIndex * 8));
			extracted = il.And(4, extracted, mask);
			extracted = il.ShiftLeft(4, extracted, il.Const(4, (dstIndex - srcIndex) * 8));
		}
		else if (srcIndex > dstIndex)
		{
			ExprId mask = il.Const(4, 0xffull << (dstIndex * 8));
			extracted = il.LogicalShiftRight(4, extracted, il.Const(4, (srcIndex - dstIndex) * 8));
			extracted = il.And(4, extracted, mask);
		}

		if (swap == BN_INVALID_EXPR)
			swap = extracted;
		else
			swap = il.Or(4, swap, extracted);
	}

	return swap;
}

// static void ByteReversedLoad(LowLevelILFunction &il, struct cs_sparc* sparc, size_t size)
// {
// 	ExprId addr = operToIL(il, &sparc->operands[1], OTI_GPR0_ZERO);                  // (rA|0)
// 	ExprId  val = il.Load(size, il.Add(4, addr, operToIL(il, &sparc->operands[2]))); // [(rA|0) + (rB)]

// 	if (size < 4)
// 		val = il.ZeroExtend(4, val);

// 	/* set reg immediately; this will cause xrefs to be sized correctly,
// 	 * we'll use this as the scratch while we calculate the swapped value */
// 	il.AddInstruction(il.SetRegister(4, sparc->operands[0].reg, val));               // rD = [(rA|0) + (rB)]
// 	ExprId swap = ByteReverseRegister(il, sparc->operands[0].reg, size);

// 	il.AddInstruction(il.SetRegister(4, sparc->operands[0].reg, swap));              // rD = swap([(rA|0) + (rB)])
// }

// static void ByteReversedStore(LowLevelILFunction &il, struct cs_sparc* sparc, size_t size)
// {
// 	ExprId addr = operToIL(il, &sparc->operands[1], OTI_GPR0_ZERO);     // (rA|0)
// 	addr = il.Add(4, addr, operToIL(il, &sparc->operands[2]));          // (rA|0) + (rB)
// 	ExprId val = ByteReverseRegister(il, sparc->operands[0].reg, size); // rS = swap(rS)
// 	il.AddInstruction(il.Store(size, addr, val));                     // [(rA|0) + (rB)] = swap(rS)
// }

/* returns TRUE - if this IL continues
          FALSE - if this IL terminates a block */
bool GetLowLevelILForSparcInstruction(Architecture *arch, LowLevelILFunction &il,
  const uint8_t* data, uint64_t addr, decomp_result *res, bool le)
{
	int i;
	bool rc = true;
	struct cs_insn *insn = 0;
	struct cs_detail *detail = 0;
	struct cs_sparc *sparc = 0;

	/* bypass capstone path for *all* branching instructions; capstone
	 * is too difficult to work with and is outright broken for some
	 * branch instructions (bdnz, etc.)
	 */
	if (LiftBranches(arch, il, data, addr, le) == true)
	{
		return true;
	}

	insn = &(res->insn);
	detail = &(res->detail);
	sparc = &(detail->sparc);

	/* create convenient access to instruction operands */
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

	/* for conditionals that specify a crx, treat it special */
	if(sparc->cc != SPARC_CC_INVALID)
	{
		if(oper0 && oper0->type == SPARC_OP_REG)
		{
			oper0 = oper1;
			oper1 = oper2;
			oper2 = oper3;
			oper3 = NULL;
		}
	}

	ExprId ei0, ei1, ei2;

	// BinaryNinja::LogWarn("addr:%llx inst:%s id:%d", addr, insn->mnemonic, insn->id);

	switch(insn->id) {
		/* add
			"add." also updates the CR0 bits */
		case SPARC_INS_ADD: /* add */
			REQUIRE3OPS
			ei0 = il.Add(
				arch->GetAddressSize(),
				operToIL(il, oper0),
				operToIL(il, oper1)
			);
			ei0 = il.SetRegister(arch->GetAddressSize(), oper2->reg, ei0
				// sparc->cc ? IL_FLAGWRITE_CC_S : 0
			);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SUB:
			REQUIRE3OPS
			ei0 = il.Sub(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1));
			ei0 = il.SetRegister(arch->GetAddressSize(), oper2->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_MOV:
			REQUIRE2OPS
			ei0 = il.SetRegister(arch->GetAddressSize(),
				oper1->reg, operToIL(il, oper0));
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_NOP:
			ei0 = il.Nop();
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_OR:
			REQUIRE2OPS
			if (oper2 != 0)
			{
				ei0 = il.Or(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1));
				ei0 = il.SetRegister(arch->GetAddressSize(), oper2->reg, ei0);
				il.AddInstruction(ei0);
			}
			else
			{
				ei0 = il.SetRegister(arch->GetAddressSize(), oper1->reg, operToIL(il, oper0));
				il.AddInstruction(ei0);
			}
			break;

		case SPARC_INS_LD:
		case SPARC_INS_LDX:
			REQUIRE2OPS
			// BinaryNinja::LogWarn("oper0 typeval %d  oper1 typeval %d ", oper0->type, oper1->type);
			ei0 = il.Load(arch->GetAddressSize(), operToIL(il, oper0));
			ei0 = il.SetRegister(arch->GetAddressSize(), oper1->reg, ei0);
			il.AddInstruction(ei0);
			break;
		
		case SPARC_INS_LDUB:
			REQUIRE2OPS
			ei0 = il.Load(1, operToIL(il, oper0));
			ei0 = il.SetRegister(1, oper1->reg, ei0);
			il.AddInstruction(ei0);
			break;
		
		case SPARC_INS_XOR:
			REQUIRE3OPS
			ei0 = il.Xor(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1));
			ei0 = il.SetRegister(arch->GetAddressSize(), oper2->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SETHI:
			REQUIRE2OPS
			// ei0 = il.And(arch->GetAddressSize(), operToIL(il, oper1), il.Const(arch->GetAddressSize(), ~(uint64_t)0x3ff));
			ei0 = il.ShiftLeft(arch->GetAddressSize(), operToIL(il, oper0), il.Const(arch->GetAddressSize(), 10));
			ei0 = il.SetRegister(arch->GetAddressSize(), oper1->reg, ei0);

			il.AddInstruction(ei0);
			break;

		case SPARC_INS_STX:
		case SPARC_INS_ST:
			REQUIRE2OPS
			ei0 = il.Store(arch->GetAddressSize(), operToIL(il, oper1), operToIL(il, oper0));
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SLL:
		case SPARC_INS_SLLX:
			REQUIRE3OPS
			ei0 = il.ShiftLeft(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1));
			ei0 = il.SetRegister(arch->GetAddressSize(), oper2->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SRA:
			REQUIRE3OPS
			ei0 = il.ArithShiftRight(4, operToIL(il, oper0), operToIL(il, oper1));
			ei0 = il.SetRegister(4, oper2->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SRAX:
			REQUIRE3OPS
			ei0 = il.ArithShiftRight(8, operToIL(il, oper0), operToIL(il, oper1));
			ei0 = il.SetRegister(8, oper2->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SRL:
			REQUIRE3OPS
			ei0 = il.LogicalShiftRight(4, operToIL(il, oper0), operToIL(il, oper1));
			ei0 = il.SetRegister(4, oper2->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SRLX:
			REQUIRE3OPS
			ei0 = il.LogicalShiftRight(8, operToIL(il, oper0), operToIL(il, oper1));
			ei0 = il.SetRegister(8, oper2->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_CMP:
			ei0 = il.Sub(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1));
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_STB:
			REQUIRE2OPS
			ei0 = il.Store(1, operToIL(il, oper1), operToIL(il, oper0));
			il.AddInstruction(ei0);
			break;

		// capstone painted this one with a broad brush, technically this
		// is supposed to be SPARC_INS_JMPL, but they categorize it as
		// SPARC_INS_CALL
		case SPARC_INS_CALL:
			if (oper1 != 0)
			{
				ei0 = il.Add(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1));
			}
			else if (oper0 != 0)
			{
				ei0 = operToIL(il, oper0);
			}
			ei0 = il.Call(ei0);
			il.AddInstruction(ei0);
			ei0 = il.SetRegister(arch->GetAddressSize(), SPARC_REG_LINK, il.Register(arch->GetAddressSize(), SPARC_REG_PC));
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_SAVE:
			ei0 = il.Add(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1), operToIL(il, oper2));
			il.AddInstruction(ei0);
			break;

		case SPARC_INS_RETT:
			if (oper1 != 0)
			{
				ei0 = il.Add(arch->GetAddressSize(), operToIL(il, oper0), operToIL(il, oper1));
			}
			else if (oper0 != 0)
			{
				ei0 = operToIL(il, oper0);
			}
			ei0 = il.Return(ei0);
			il.AddInstruction(ei0);
			break;

		// this one straight up has the same opcode as SPARC_INS_JMPL
		case SPARC_INS_RETL:
		case SPARC_INS_RET:
			if (oper0 == 0)
			{
				ei0 = il.Register(arch->GetAddressSize(), SPARC_REG_LINK);
				ei1 = il.Const(arch->GetAddressSize(), 8);
				ei0 = il.Add(arch->GetAddressSize(), ei0, ei1);
				ei0 = il.Return(ei0);
				il.AddInstruction(ei0);
			}
			break;

		case SPARC_INS_RESTORE:

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

