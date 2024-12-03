#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <map>
#include <vector>

#include <binaryninjaapi.h>
#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug
//#define MYLOG printf

#include "lowlevelilinstruction.h"
using namespace BinaryNinja; // for ::LogDebug, etc.

#include "disassembler.h"

#include "il.h"
#include "util.h"

using namespace std;

/*
 * Sparc ELF relocation types
 */
enum ElfSparcRelocationType
{
	R_SPARC_NONE = 0,
	R_SPARC_8 = 1,
	R_SPARC_16 = 2,
	R_SPARC_32 = 3,
	R_SPARC_DISP8 = 4,
	R_SPARC_DISP16 = 5,
	R_SPARC_DISP32 = 6,
	R_SPARC_WDISP30 = 7,
	R_SPARC_WDISP22 = 8,
	R_SPARC_HI22 = 9,
	R_SPARC_22 = 10,
	R_SPARC_13 = 11,
	R_SPARC_LO10 = 12,
	R_SPARC_GOT10 = 13,
	R_SPARC_GOT13 = 14,
	R_SPARC_GOT22 = 15,
	R_SPARC_PC10 = 16,
	R_SPARC_PC22 = 17,
	R_SPARC_WPLT30 = 18,
	R_SPARC_COPY = 19,
	R_SPARC_GLOB_DAT = 20,
	R_SPARC_JMP_SLOT = 21,
	R_SPARC_RELATIVE = 22,
	R_SPARC_UA32 = 23,
	R_SPARC_PLT32 = 24,
	R_SPARC_HIPLT22 = 25,
	R_SPARC_LOPLT10 = 26,
	R_SPARC_PCPLT32 = 27,
	R_SPARC_PCPLT22 = 28,
	R_SPARC_PCPLT10 = 29,
	R_SPARC_10 = 30,
	R_SPARC_11 = 31,
	R_SPARC_64 = 32,
	R_SPARC_OLO10 = 33,
	R_SPARC_WDISP16 = 40,
	R_SPARC_WDISP19 = 41,
	R_SPARC_7 = 43,
	R_SPARC_5 = 44,
	R_SPARC_6 = 45,
	MAX_ELF_SPARC_RELOCATION
};

#define HA(x) (uint16_t)((((x) >> 16) + (((x) & 0x8000) ? 1 : 0)) & 0xffff)

static const char* GetRelocationString(ElfSparcRelocationType relocType)
{
	static map<ElfSparcRelocationType, const char *> relocTable = {
		{R_SPARC_NONE, "R_SPARC_NONE"},
		{R_SPARC_8, "R_SPARC_8"},
		{R_SPARC_16, "R_SPARC_16"},
		{R_SPARC_32, "R_SPARC_32"},
		{R_SPARC_DISP8, "R_SPARC_DISP8"},
		{R_SPARC_DISP16, "R_SPARC_DISP16"},
		{R_SPARC_DISP32, "R_SPARC_DISP32"},
		{R_SPARC_WDISP30, "R_SPARC_WDISP30"},
		{R_SPARC_WDISP22, "R_SPARC_WDISP22"},
		{R_SPARC_HI22, "R_SPARC_HI22"},
		{R_SPARC_22, "R_SPARC_22"},
		{R_SPARC_13, "R_SPARC_13"},
		{R_SPARC_LO10, "R_SPARC_LO10"},
		{R_SPARC_GOT10, "R_SPARC_GOT10"},
		{R_SPARC_GOT13, "R_SPARC_GOT13"},
		{R_SPARC_GOT22, "R_SPARC_GOT22"},
		{R_SPARC_PC10, "R_SPARC_PC10"},
		{R_SPARC_PC22, "R_SPARC_PC22"},
		{R_SPARC_WPLT30, "R_SPARC_WPLT30"},
		{R_SPARC_COPY, "R_SPARC_COPY"},
		{R_SPARC_GLOB_DAT, "R_SPARC_GLOB_DAT"},
		{R_SPARC_JMP_SLOT, "R_SPARC_JMP_SLOT"},
		{R_SPARC_RELATIVE, "R_SPARC_RELATIVE"},
		{R_SPARC_UA32, "R_SPARC_UA32"},
		{R_SPARC_PLT32, "R_SPARC_PLT32"},
		{R_SPARC_HIPLT22, "R_SPARC_HIPLT22"},
		{R_SPARC_LOPLT10, "R_SPARC_LOPLT10"},
		{R_SPARC_PCPLT32, "R_SPARC_PCPLT32"},
		{R_SPARC_PCPLT22, "R_SPARC_PCPLT22"},
		{R_SPARC_PCPLT10, "R_SPARC_PCPLT10"},
		{R_SPARC_10, "R_SPARC_10"},
		{R_SPARC_11, "R_SPARC_11"},
		{R_SPARC_64, "R_SPARC_64"},
		{R_SPARC_OLO10, "R_SPARC_OLO10"},
		{R_SPARC_WDISP16, "R_SPARC_WDISP16"},
		{R_SPARC_WDISP19, "R_SPARC_WDISP19"},
		{R_SPARC_7, "R_SPARC_7"},
		{R_SPARC_5, "R_SPARC_5"},
		{R_SPARC_6, "R_SPARC_6"}
	};
	if (relocTable.count(relocType))
		return relocTable.at(relocType);
	return "Unknown PPC relocation";
}

/* class Architecture from binaryninjaapi.h */
class SparcArchitecture: public Architecture
{
	private:
	BNEndianness endian;
	int cs_mode_local;
	size_t addressSize;

	/* this can maybe be moved to the API later */
	BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
	{
		BNRegisterInfo result;
		result.fullWidthRegister = fullWidthReg;
		result.offset = offset;
		result.size = size;
		result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
		return result;
	}

	public:

	/* initialization list */
	SparcArchitecture(const char* name, BNEndianness endian_, size_t addressSize_=4, int cs_mode_=0): Architecture(name)
	{
		endian = endian_;
		addressSize = addressSize_;
		cs_mode_local = cs_mode_;
	}

	/*************************************************************************/

	virtual BNEndianness GetEndianness() const override
	{
		//MYLOG("%s()\n", __func__);
		return endian;
	}

	virtual size_t GetAddressSize() const override
	{
		//MYLOG("%s()\n", __func__);
		return addressSize;
	}

	virtual size_t GetDefaultIntegerSize() const override
	{
		MYLOG("%s()\n", __func__);
		return 4;
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 4;
	}

	/* think "GetInstructionBranchBehavior()"

	   populates struct Instruction Info (api/binaryninjaapi.h)
	   which extends struct BNInstructionInfo (core/binaryninjacore.h)

	   tasks:
		1) set the length
		2) invoke AddBranch() for every non-sequential execution possibility

	   */
	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr,
		size_t maxLen, InstructionInfo& result) override
	{
		struct decomp_result res;
		struct cs_insn *insn = &(res.insn);
		uint64_t target = 0;
		uint32_t raw_insn = 0;
		int bitwidth = 0;
		int bitoffset = 0;

		//MYLOG("%s()\n", __func__);

		if (maxLen < 4) {
			MYLOG("ERROR: need at least 4 bytes\n");
			return false;
		}

		if (DoesQualifyForLocalDisassembly(data, endian == BigEndian) != SPARC_INS_INVALID)
		{
			result.length = 4;
			return true;
		}

		/* decompose the instruction to get branch info */
		if(sparc_decompose(data, 4, (uint32_t)addr, endian == LittleEndian, &res, GetAddressSize() == 8, cs_mode_local))
		{
			MYLOG("ERROR: sparc_decompose()\n");
			return false;
		}

		raw_insn = *(const uint32_t *) data;

		if (endian == BigEndian)
		{
			raw_insn = bswap32(raw_insn);
		}

		if ((raw_insn & SPARC_CALL_MASK) == SPARC_CALL_MASKED)
		{
			target = sign_extend_bitnn(raw_insn, 0, 30);
			target = target << 2;

			/* account for absolute addressing */
			target += addr;

			result.AddBranch(CallDestination, target);
		}
		else
		{
			switch (res.insn.id)
			{
			case SPARC_INS_BRZ:
			case SPARC_INS_BRLZ:
			case SPARC_INS_BRLEZ:
			case SPARC_INS_BRNZ:
			case SPARC_INS_BRGZ:
			case SPARC_INS_BRGEZ:
				target = (raw_insn & 0x00300000) >> 6;
				target |= (raw_insn & 0x00003fff);

				// 16 bit immediate
				if ((target >> 15) == 1)
				{
					target |= 0xffffffffffff0000;
				}

				target = target << 2;
				target += addr;

				result.AddBranch(FalseBranch, addr + 4);
				result.AddBranch(TrueBranch, target);

				break;
			case SPARC_INS_B:
				if ((raw_insn & SPARC_B_MASK) == SPARC_BIC_MASKED)
				{
					bitwidth = SPARC_BIC_BITWIDTH;
					bitoffset = 0;
				}
				else if ((raw_insn & SPARC_B_MASK) == SPARC_BPC_MASKED)
				{
					bitwidth = SPARC_BPC_BITWIDTH;
					bitoffset = 0;
				}

				// BinaryNinja::LogWarn("%s addr:0x%llx bitw:%d", __func__, addr, bitwidth);
				target = sign_extend_bitnn(raw_insn, bitoffset, bitwidth);
				target = target << 2;
				target += addr;

				// conditional branch
				if ((raw_insn >> 25) & 0x7)
				{
					result.AddBranch(FalseBranch, addr + 4);
					result.AddBranch(TrueBranch, target);
				}
				// branch always
				else if ((raw_insn >> 25) & 0x8)
				{
					result.AddBranch(UnconditionalBranch, target);
				}

				break;
			
			// assuming that jmpl, is a ret. which sometimes it is
			case SPARC_INS_JMPL:
			case SPARC_INS_RET:
			case SPARC_INS_RETT:
				result.AddBranch(FunctionReturn);
				break;
			case SPARC_INS_JMP:
				break;
			}

		}

		switch(insn->id) {
			case PPC_INS_TRAP:
				result.AddBranch(UnresolvedBranch);
				break;
			case PPC_INS_RFI:
				result.AddBranch(UnresolvedBranch);
				break;
		}

		result.length = 4;
		return true;
	}

	bool PrintLocalDisassembly(const uint8_t *data, uint64_t addr, size_t &len, vector<InstructionTextToken> &result, decomp_result* res)
	{
		(void)addr;
		char buf[16];
		uint32_t local_op = SPARC_INS_INVALID;

		struct cs_detail *detail = 0;
		struct cs_sparc *sparco = 0;
		struct cs_insn *insn = &(res->insn);

		detail = &(res->detail);
		sparco = &(detail->sparc);

		if (len < 4)
			return false;
		len = 4;

		local_op = DoesQualifyForLocalDisassembly(data, endian == BigEndian);
		PerformLocalDisassembly(data, addr, len, res, endian == BigEndian);		

		switch (local_op)
		{
		default:
			return false;
		}
		return true;
	}

	/* populate the vector result with InstructionTextToken

	*/
	virtual bool GetInstructionText(const uint8_t *data, uint64_t addr, size_t &len, vector<InstructionTextToken> &result) override
	{
		bool rc = false;
		bool capstoneWorkaround = false;
		char buf[32];
		size_t strlenMnem;
		struct decomp_result res;
		struct cs_insn *insn = &(res.insn);
		struct cs_detail *detail = &(res.detail);
		struct cs_sparc *sparco = &(detail->sparc);

		// MYLOG("%s()\n", __func__);

		if (len < 4)
		{
			MYLOG("ERROR: need at least 4 bytes\n");
			goto cleanup;
		}

		if (sparc_decompose(data, 4, (uint32_t)addr, endian == LittleEndian, &res, GetAddressSize() == 8, cs_mode_local))
		{
			MYLOG("ERROR: powerpc_decompose()\n");
			goto cleanup;
		}

		/* mnemonic */
		result.emplace_back(InstructionToken, insn->mnemonic);

		/* padding between mnemonic and operands */
		memset(buf, ' ', 8);
		strlenMnem = strlen(insn->mnemonic);
		if (strlenMnem < 8)
			buf[8 - strlenMnem] = '\0';
		else
			buf[1] = '\0';
		result.emplace_back(TextToken, buf);

		/* operands */
		for (int i = 0; i < sparco->op_count; ++i)
		{
			struct cs_sparc_op *op = &(sparco->operands[i]);

			switch (op->type)
			{
			case SPARC_OP_REG:
				// MYLOG("pushing a register\n");
				result.emplace_back(RegisterToken, GetRegisterName(op->reg));
				break;
			case SPARC_OP_IMM:
				// MYLOG("pushing an integer\n");

				switch (insn->id)
				{
				case SPARC_INS_B:
				case SPARC_INS_BRGEZ:
				case SPARC_INS_BRGZ:
				case SPARC_INS_BRLEZ:
				case SPARC_INS_BRLZ:
				case SPARC_INS_BRNZ:
				case SPARC_INS_BRZ:
				case SPARC_INS_CALL:
				case SPARC_INS_JMP:
					snprintf(buf, sizeof(buf), "0x%llx", op->imm);
					result.emplace_back(CodeRelativeAddressToken, buf, (uint32_t)op->imm, 4);
					break;
				// intended to be for instructions with immediates, addis or something
				case SPARC_INS_ADD:
					snprintf(buf, sizeof(buf), "0x%x", (uint16_t)op->imm);
					result.emplace_back(IntegerToken, buf, (uint16_t)op->imm, 4);
					break;
				default:
					if (op->imm < 0 && op->imm > -0x10000)
						snprintf(buf, sizeof(buf), "-0x%llx", -op->imm);
					else
						snprintf(buf, sizeof(buf), "0x%llx", op->imm);
					result.emplace_back(IntegerToken, buf, op->imm, 4);
				}

				break;
			case SPARC_OP_MEM:
				// eg: lwz r11, 8(r11)
				snprintf(buf, sizeof(buf), "%d", op->mem.disp);
				result.emplace_back(IntegerToken, buf, op->mem.disp, 4);

				result.emplace_back(BraceToken, "(");
				result.emplace_back(RegisterToken, GetRegisterName(op->mem.base));
				result.emplace_back(BraceToken, ")");
				break;
			case SPARC_OP_INVALID:
			default:
				// MYLOG("pushing a ???\n");
				result.emplace_back(TextToken, "???");
			}

			if (i < sparco->op_count - 1)
			{
				// MYLOG("pushing a comma\n");
				result.emplace_back(OperandSeparatorToken, ", ");
			}
		}

		rc = true;
		len = 4;
	cleanup:
		return rc;
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t *data, uint64_t addr, size_t &len, LowLevelILFunction &il) override
	{
		bool rc = false;
		struct decomp_result res = {0};

		if (len < 4)
		{
			MYLOG("ERROR: need at least 4 bytes\n");
			goto cleanup;
		}

		// if(addr >= 0x10000300 && addr <= 0x10000320) {
		//	MYLOG("%s(data, 0x%llX, 0x%zX, il)\n", __func__, addr, len);
		// }

		if (sparc_decompose(data, 4, (uint32_t)addr, endian == LittleEndian, &res, GetAddressSize() == 8, cs_mode_local))
		{
			MYLOG("ERROR: powerpc_decompose()\n");
			il.AddInstruction(il.Undefined());
			goto cleanup;
		}

	getil:
		// TODO add sparc il stuff
		rc = GetLowLevelILForSparcInstruction(this, il, data, addr, &res, endian == LittleEndian);
		len = 4;

	cleanup:
		return rc;
	}

	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override
	{
		MYLOG("%s()\n", __func__);

		bool signedWrite = true;
		ExprId left, right;

		switch (flagWriteType)
		{
		}

		auto liftOps = [&]() {
			if ((op == LLIL_SUB) || (op == LLIL_FSUB))
			{
				left = il.GetExprForRegisterOrConstant(operands[0], size);
				right = il.GetExprForRegisterOrConstant(operands[1], size);
			}
			else
			{
				left = il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount);
				right = il.Const(size, 0);
			}
		};

		switch (flag)
		{
			case IL_FLAG_LT:
				liftOps();

				if (signedWrite)
					return il.CompareSignedLessThan(size, left, right);
				else
					return il.CompareUnsignedLessThan(size, left, right);

			case IL_FLAG_GT:
				liftOps();

				if (signedWrite)
					return il.CompareSignedGreaterThan(size, left, right);
				else
					return il.CompareUnsignedGreaterThan(size, left, right);

			case IL_FLAG_EQ:
				liftOps();
				return il.CompareEqual(size, left, right);
		}

		BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
		return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
	}

	virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override
	{
		uint32_t flagBase = (semGroup / 10) * 4; // get to flags from the right cr

		switch (semGroup % 10)
		{
			case IL_FLAGGROUP_CC_LT: return il.Flag(flagBase + IL_FLAG_LT);
			case IL_FLAGGROUP_CC_LE: return il.Not(0, il.Flag(flagBase + IL_FLAG_GT));
			case IL_FLAGGROUP_CC_GT: return il.Flag(flagBase + IL_FLAG_GT);
			case IL_FLAGGROUP_CC_GE: return il.Not(0, il.Flag(flagBase + IL_FLAG_LT));
			case IL_FLAGGROUP_CC_EQ: return il.Flag(flagBase + IL_FLAG_EQ);
			case IL_FLAGGROUP_CC_NE: return il.Not(0, il.Flag(flagBase + IL_FLAG_EQ));
		}

		return il.Unimplemented();
	}

	virtual string GetRegisterName(uint32_t regId) override
	{
		const char *result = sparc_reg_to_str(regId, cs_mode_local);

		if(result == NULL)
			result = "";

		//MYLOG("%s(%d) returns %s\n", __func__, regId, result);
		return result;
	}

	/*************************************************************************/
	/* FLAGS API
		1) flag identifiers and names
		2) flag write types and names
		3) flag roles "which flags act like a carry flag?"
		4) map flag condition to set-of-flags
	*/
	/*************************************************************************/

	/*
		flag identifiers and names
	*/
	// virtual vector<uint32_t> GetAllFlags() override
	// {
	// 	MYLOG("%s()\n", __func__);
	// 	return vector<uint32_t> {
	// 		IL_FLAG_LT, IL_FLAG_GT, IL_FLAG_EQ, IL_FLAG_SO,
	// 		IL_FLAG_LT_1, IL_FLAG_GT_1, IL_FLAG_EQ_1, IL_FLAG_SO_1,
	// 		IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2,
	// 		IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3,
	// 		IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4,
	// 		IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5,
	// 		IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6,
	// 		IL_FLAG_LT_7, IL_FLAG_GT_7, IL_FLAG_EQ_7, IL_FLAG_SO_7,
	// 		IL_FLAG_XER_SO, IL_FLAG_XER_OV, IL_FLAG_XER_CA
	// 	};
	// }

	virtual string GetFlagName(uint32_t flag) override
	{
		MYLOG("%s(%d)\n", __func__, flag);

		switch(flag)
		{
			case IL_FLAG_LT: return "lt";
			case IL_FLAG_GT: return "gt";
			case IL_FLAG_EQ: return "eq";
			case IL_FLAG_SO: return "so";
			default: return "ERR_FLAG_NAME";
		}
	}

	/*
		flag write types
	*/
	virtual vector<uint32_t> GetAllFlagWriteTypes() override
	{
		return vector<uint32_t> {
			IL_FLAGWRITE_NONE,
			IL_FLAGWRITE_INVALL
		};
	}

	virtual string GetFlagWriteTypeName(uint32_t writeType) override
	{
		MYLOG("%s(%d)\n", __func__, writeType);

		switch (writeType)
		{
			case IL_FLAGWRITE_INVALL:
				return "invall";

			default:
				MYLOG("ERROR: unrecognized writeType\n");
				return "none";
		}
	}

	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override
	{
		MYLOG("%s(%d)\n", __func__, writeType);

		switch (writeType)
		{
			case IL_FLAGWRITE_INVALL:
				return GetAllFlags();

			default:
				return vector<uint32_t>();
		}
	}
	virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override
	{
		switch (writeType)
		{
		}

		return IL_FLAGCLASS_NONE;
	}

	/*
		flag classes
	*/
	virtual vector<uint32_t> GetAllSemanticFlagClasses() override
	{
		return vector<uint32_t> {
			IL_FLAGCLASS_NONE,
		};
	}

	// virtual std::string GetSemanticFlagClassName(uint32_t semClass) override
	// {
	// 	return GetFlagWriteTypeName(semClass);
	// }

	/*
	   semantic flag groups
	 */
	virtual vector<uint32_t> GetAllSemanticFlagGroups() override
	{
		return vector<uint32_t> {
		};
	}

	virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override
	{
		char name[32];
		const char* suffix;

		/* remove the cr part of the semGroup id from the equation */
		switch (semGroup % 10)
		{
			case IL_FLAGGROUP_CC_LT: suffix = "lt"; break;
			case IL_FLAGGROUP_CC_LE: suffix = "le"; break;
			case IL_FLAGGROUP_CC_GT: suffix = "gt"; break;
			case IL_FLAGGROUP_CC_GE: suffix = "ge"; break;
			case IL_FLAGGROUP_CC_EQ: suffix = "eq"; break;
			case IL_FLAGGROUP_CC_NE: suffix = "ne"; break;
			default: suffix = "invalid"; break;
		}

		snprintf(name, sizeof(name), "cr%d_%s", semGroup / 10, suffix);

		return std::string(name);
	}

	virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override
	{
		uint32_t flag = IL_FLAG_LT + ((semGroup / 10) * 4); // get to flags from the right cr
		flag += ((semGroup % 10) / 2);

		return { flag };
	}

	virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup) override
	{
		uint32_t flagClassBase = IL_FLAGCLASS_CC_S + ((semGroup / 10) * 2);
		uint32_t groupType = semGroup % 10;

		switch (groupType)
		{
		case IL_FLAGGROUP_CC_LT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SLT},
				{flagClassBase + 1, LLFC_ULT}
			};
		case IL_FLAGGROUP_CC_LE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SLE},
				{flagClassBase + 1, LLFC_ULE}
			};
		case IL_FLAGGROUP_CC_GT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SGT},
				{flagClassBase + 1, LLFC_UGT}
			};
		case IL_FLAGGROUP_CC_GE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SGE},
				{flagClassBase + 1, LLFC_UGE}
			};
		case IL_FLAGGROUP_CC_EQ:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_E},
				{flagClassBase + 1, LLFC_E}
			};
		case IL_FLAGGROUP_CC_NE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_NE},
				{flagClassBase + 1, LLFC_NE}
			};
		default:
			return map<uint32_t, BNLowLevelILFlagCondition>();
		}
	}

	/*
		flag roles
	*/

	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override
	{
		MYLOG("%s(%d)\n", __func__, flag);

		bool signedClass = true;

		switch (semClass)
		{
		}

		switch (flag)
		{
			return signedClass ? NegativeSignFlagRole : SpecialFlagRole;
		}
		return signedClass ? NegativeSignFlagRole : SpecialFlagRole;
	}

	/*
		flag conditions -> set of flags
		LLFC is "low level flag condition"
	*/
	virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override
	{
		MYLOG("%s(%d)\n", __func__, cond);

		switch (cond)
		{
			case LLFC_E: /* equal */
			case LLFC_NE: /* not equal */
				// return vector<uint32_t>{ IL_FLAG_EQ };

			case LLFC_ULT: /* (unsigned) less than == LT */
			case LLFC_SLT: /* (signed) less than == LT */
			case LLFC_SGE: /* (signed) greater-or-equal == !LT */
			case LLFC_UGE: /* (unsigned) greater-or-equal == !LT */
				// return vector<uint32_t>{ IL_FLAG_LT };

			case LLFC_SGT: /* (signed) greater-than == GT */
			case LLFC_UGT: /* (unsigned) greater-than == GT */
			case LLFC_ULE: /* (unsigned) less-or-equal == !GT */
			case LLFC_SLE: /* (signed) lesser-or-equal == !GT */
				// return vector<uint32_t>{ IL_FLAG_GT };

			case LLFC_NEG:
			case LLFC_POS:
				/* no ppc flags (that I'm aware of) indicate sign of result */
				return vector<uint32_t>();

			case LLFC_O:
			case LLFC_NO:
				/* difficult:
					crX: 8 signed sticky versions
					XER: 1 unsigned sticky, 1 unsigned traditional */
				return vector<uint32_t>{
					// IL_FLAG_XER_OV
				};

			default:
				return vector<uint32_t>();
		}
	}


	/*************************************************************************/
	/* REGISTERS API
		1) registers' ids and names
		2) register info (size)
		3) special registers: stack pointer, link register
	*/
	/*************************************************************************/

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		MYLOG("%s()\n", __func__);

		return vector<uint32_t>{
			SPARC_REG_G0, SPARC_REG_G1, SPARC_REG_G2, SPARC_REG_G3, SPARC_REG_G4, SPARC_REG_G5, SPARC_REG_G6,
			SPARC_REG_G7,
			
			SPARC_REG_O0, SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3, SPARC_REG_O4, SPARC_REG_O5, SPARC_REG_SP,
			SPARC_REG_O7,

			SPARC_REG_L0, SPARC_REG_L1, SPARC_REG_L2, SPARC_REG_L3, SPARC_REG_L4, SPARC_REG_L5, SPARC_REG_L6,
			SPARC_REG_L7,

			SPARC_REG_I0, SPARC_REG_I1, SPARC_REG_I2, SPARC_REG_I3, SPARC_REG_I4, SPARC_REG_I5, SPARC_REG_FP,
			SPARC_REG_I7,
		};
	}

	#define PPC_REG_CC (PPC_REG_ENDING + 1)
	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> result = {
			SPARC_REG_F0, SPARC_REG_F1, SPARC_REG_F2, SPARC_REG_F3, SPARC_REG_F4, SPARC_REG_F5, SPARC_REG_F6,
			SPARC_REG_F7, SPARC_REG_F8, SPARC_REG_F9, SPARC_REG_F10, SPARC_REG_F11, SPARC_REG_F12, SPARC_REG_F13,
			SPARC_REG_F14, SPARC_REG_F15, SPARC_REG_F16, SPARC_REG_F17, SPARC_REG_F18, SPARC_REG_F19, SPARC_REG_F20,
			SPARC_REG_F21, SPARC_REG_F22, SPARC_REG_F23, SPARC_REG_F24, SPARC_REG_F25, SPARC_REG_F26, SPARC_REG_F27,
			SPARC_REG_F28, SPARC_REG_F29, SPARC_REG_F30, SPARC_REG_F31, SPARC_REG_F32, SPARC_REG_F34, SPARC_REG_F36,
			SPARC_REG_F38, SPARC_REG_F40, SPARC_REG_F42, SPARC_REG_F44, SPARC_REG_F46, SPARC_REG_F48, SPARC_REG_F50,
			SPARC_REG_F52, SPARC_REG_F54, SPARC_REG_F56, SPARC_REG_F58, SPARC_REG_F60, SPARC_REG_F62,
			
			// Floating condition codes
 			SPARC_REG_FCC0, SPARC_REG_FCC1, SPARC_REG_FCC2, SPARC_REG_FCC3,
			
			SPARC_REG_FP,
			
			SPARC_REG_G0, SPARC_REG_G1, SPARC_REG_G2, SPARC_REG_G3, SPARC_REG_G4, SPARC_REG_G5, SPARC_REG_G6,
			SPARC_REG_G7,
			
			SPARC_REG_I0, SPARC_REG_I1, SPARC_REG_I2, SPARC_REG_I3, SPARC_REG_I4, SPARC_REG_I5, SPARC_REG_FP,
			SPARC_REG_I7,
			
			SPARC_REG_ICC, // Integer condition codes
			
			SPARC_REG_L0, SPARC_REG_L1, SPARC_REG_L2, SPARC_REG_L3, SPARC_REG_L4, SPARC_REG_L5, SPARC_REG_L6,
			SPARC_REG_L7,
			
			SPARC_REG_O0, SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3, SPARC_REG_O4, SPARC_REG_O5, SPARC_REG_SP,
			SPARC_REG_O7,

			SPARC_REG_Y,

			// special register
			SPARC_REG_XCC,
		};

		return result;
	}


	virtual std::vector<uint32_t> GetGlobalRegisters() override
	{
		return vector<uint32_t>{
			SPARC_REG_G0, SPARC_REG_G1, SPARC_REG_G2, SPARC_REG_G3,
			SPARC_REG_G4, SPARC_REG_G5, SPARC_REG_G6, SPARC_REG_G7,
			};
	}


	/* binja asks us about subregisters
		the full width reg is the enveloping register, if it exists,
		and also we report our offset within it (0 if we are not enveloped)
		and our size */
	virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
	{
		//MYLOG("%s(%s)\n", __func__, powerpc_reg_to_str(regId));

		switch(regId)
		{
			// BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset,
			//   size_t size, bool zeroExtend = false)
		case SPARC_REG_F0: return RegisterInfo(SPARC_REG_F0, 0, 4);
		case SPARC_REG_F1: return RegisterInfo(SPARC_REG_F1, 0, 4);
		case SPARC_REG_F2: return RegisterInfo(SPARC_REG_F2, 0, 4);
		case SPARC_REG_F3: return RegisterInfo(SPARC_REG_F3, 0, 4);
		case SPARC_REG_F4: return RegisterInfo(SPARC_REG_F4, 0, 4);
		case SPARC_REG_F5: return RegisterInfo(SPARC_REG_F5, 0, 4);
		case SPARC_REG_F6: return RegisterInfo(SPARC_REG_F6, 0, 4);
		case SPARC_REG_F7: return RegisterInfo(SPARC_REG_F7, 0, 4);
		case SPARC_REG_F8: return RegisterInfo(SPARC_REG_F8, 0, 4);
		case SPARC_REG_F9: return RegisterInfo(SPARC_REG_F9, 0, 4);
		case SPARC_REG_F10: return RegisterInfo(SPARC_REG_F10, 0, 4);
		case SPARC_REG_F11: return RegisterInfo(SPARC_REG_F11, 0, 4);
		case SPARC_REG_F12: return RegisterInfo(SPARC_REG_F12, 0, 4);
		case SPARC_REG_F13: return RegisterInfo(SPARC_REG_F13, 0, 4);
		case SPARC_REG_F14: return RegisterInfo(SPARC_REG_F14, 0, 4);
		case SPARC_REG_F15: return RegisterInfo(SPARC_REG_F15, 0, 4);
		case SPARC_REG_F16: return RegisterInfo(SPARC_REG_F16, 0, 4);
		case SPARC_REG_F17: return RegisterInfo(SPARC_REG_F17, 0, 4);
		case SPARC_REG_F18: return RegisterInfo(SPARC_REG_F18, 0, 4);
		case SPARC_REG_F19: return RegisterInfo(SPARC_REG_F19, 0, 4);
		case SPARC_REG_F20: return RegisterInfo(SPARC_REG_F20, 0, 4);
		case SPARC_REG_F21: return RegisterInfo(SPARC_REG_F21, 0, 4);
		case SPARC_REG_F22: return RegisterInfo(SPARC_REG_F22, 0, 4);
		case SPARC_REG_F23: return RegisterInfo(SPARC_REG_F23, 0, 4);
		case SPARC_REG_F24: return RegisterInfo(SPARC_REG_F24, 0, 4);
		case SPARC_REG_F25: return RegisterInfo(SPARC_REG_F25, 0, 4);
		case SPARC_REG_F26: return RegisterInfo(SPARC_REG_F26, 0, 4);
		case SPARC_REG_F27: return RegisterInfo(SPARC_REG_F27, 0, 4);
		case SPARC_REG_F28: return RegisterInfo(SPARC_REG_F28, 0, 4);
		case SPARC_REG_F29: return RegisterInfo(SPARC_REG_F29, 0, 4);
		case SPARC_REG_F30: return RegisterInfo(SPARC_REG_F30, 0, 4);
		case SPARC_REG_F31: return RegisterInfo(SPARC_REG_F31, 0, 4);
		case SPARC_REG_F32: return RegisterInfo(SPARC_REG_F32, 0, 4);
		case SPARC_REG_F34: return RegisterInfo(SPARC_REG_F34, 0, 4);
		case SPARC_REG_F36: return RegisterInfo(SPARC_REG_F36, 0, 4);
		case SPARC_REG_F38: return RegisterInfo(SPARC_REG_F38, 0, 4);
		case SPARC_REG_F40: return RegisterInfo(SPARC_REG_F40, 0, 4);
		case SPARC_REG_F42: return RegisterInfo(SPARC_REG_F42, 0, 4);
		case SPARC_REG_F44: return RegisterInfo(SPARC_REG_F44, 0, 4);
		case SPARC_REG_F46: return RegisterInfo(SPARC_REG_F46, 0, 4);
		case SPARC_REG_F48: return RegisterInfo(SPARC_REG_F48, 0, 4);
		case SPARC_REG_F50: return RegisterInfo(SPARC_REG_F50, 0, 4);
		case SPARC_REG_F52: return RegisterInfo(SPARC_REG_F52, 0, 4);
		case SPARC_REG_F54: return RegisterInfo(SPARC_REG_F54, 0, 4);
		case SPARC_REG_F56: return RegisterInfo(SPARC_REG_F56, 0, 4);
		case SPARC_REG_F58: return RegisterInfo(SPARC_REG_F58, 0, 4);
		case SPARC_REG_F60: return RegisterInfo(SPARC_REG_F60, 0, 4);
		case SPARC_REG_F62: return RegisterInfo(SPARC_REG_F62, 0, 4);
		case SPARC_REG_FCC0: return RegisterInfo(SPARC_REG_FCC0, 0, 4);
		case SPARC_REG_FCC1: return RegisterInfo(SPARC_REG_FCC1, 0, 4);
		case SPARC_REG_FCC2: return RegisterInfo(SPARC_REG_FCC2, 0, 4);
		case SPARC_REG_FCC3: return RegisterInfo(SPARC_REG_FCC3, 0, 4);
		case SPARC_REG_G0: return RegisterInfo(SPARC_REG_G0, 0, addressSize);
		case SPARC_REG_G1: return RegisterInfo(SPARC_REG_G1, 0, addressSize);
		case SPARC_REG_G2: return RegisterInfo(SPARC_REG_G2, 0, addressSize);
		case SPARC_REG_G3: return RegisterInfo(SPARC_REG_G3, 0, addressSize);
		case SPARC_REG_G4: return RegisterInfo(SPARC_REG_G4, 0, addressSize);
		case SPARC_REG_G5: return RegisterInfo(SPARC_REG_G5, 0, addressSize);
		case SPARC_REG_G6: return RegisterInfo(SPARC_REG_G6, 0, addressSize);
		case SPARC_REG_G7: return RegisterInfo(SPARC_REG_G7, 0, addressSize);
		case SPARC_REG_I0: return RegisterInfo(SPARC_REG_I0, 0, addressSize);
		case SPARC_REG_I1: return RegisterInfo(SPARC_REG_I1, 0, addressSize);
		case SPARC_REG_I2: return RegisterInfo(SPARC_REG_I2, 0, addressSize);
		case SPARC_REG_I3: return RegisterInfo(SPARC_REG_I3, 0, addressSize);
		case SPARC_REG_I4: return RegisterInfo(SPARC_REG_I4, 0, addressSize);
		case SPARC_REG_I5: return RegisterInfo(SPARC_REG_I5, 0, addressSize);
		case SPARC_REG_FP: return RegisterInfo(SPARC_REG_FP, 0, addressSize);
		case SPARC_REG_I7: return RegisterInfo(SPARC_REG_I7, 0, addressSize);
		case SPARC_REG_ICC: return RegisterInfo(SPARC_REG_ICC, 0, addressSize);
		case SPARC_REG_L0: return RegisterInfo(SPARC_REG_L0, 0, addressSize);
		case SPARC_REG_L1: return RegisterInfo(SPARC_REG_L1, 0, addressSize);
		case SPARC_REG_L2: return RegisterInfo(SPARC_REG_L2, 0, addressSize);
		case SPARC_REG_L3: return RegisterInfo(SPARC_REG_L3, 0, addressSize);
		case SPARC_REG_L4: return RegisterInfo(SPARC_REG_L4, 0, addressSize);
		case SPARC_REG_L5: return RegisterInfo(SPARC_REG_L5, 0, addressSize);
		case SPARC_REG_L6: return RegisterInfo(SPARC_REG_L6, 0, addressSize);
		case SPARC_REG_L7: return RegisterInfo(SPARC_REG_L7, 0, addressSize);
		case SPARC_REG_O0: return RegisterInfo(SPARC_REG_O0, 0, addressSize);
		case SPARC_REG_O1: return RegisterInfo(SPARC_REG_O1, 0, addressSize);
		case SPARC_REG_O2: return RegisterInfo(SPARC_REG_O2, 0, addressSize);
		case SPARC_REG_O3: return RegisterInfo(SPARC_REG_O3, 0, addressSize);
		case SPARC_REG_O4: return RegisterInfo(SPARC_REG_O4, 0, addressSize);
		case SPARC_REG_O5: return RegisterInfo(SPARC_REG_O5, 0, addressSize);
		case SPARC_REG_SP: return RegisterInfo(SPARC_REG_SP, 0, addressSize);
		case SPARC_REG_O7: return RegisterInfo(SPARC_REG_O7, 0, addressSize);
		case SPARC_REG_Y: return RegisterInfo(SPARC_REG_Y, 0, addressSize);
		case SPARC_REG_XCC: return RegisterInfo(SPARC_REG_XCC, 0, addressSize);
		default:
				//LogError("%s(%d == \"%s\") invalid argument", __func__,
				//  regId, powerpc_reg_to_str(regId));
				return RegisterInfo(0,0,0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		//MYLOG("%s()\n", __func__);
		return SPARC_REG_SP;
	}

	virtual uint32_t GetLinkRegister() override
	{
		//MYLOG("%s()\n", __func__);
		return SPARC_REG_LINK;
	}

	/*************************************************************************/

	virtual bool CanAssemble() override
	{
		return false;
	}

	// bool Assemble(const string &code, uint64_t addr, DataBuffer &result, string &errors) override
	// {
	// 	MYLOG("%s()\n", __func__);

	// 	/* prepend directives to command the assembler's origin and endianness */
	// 	string src;
	// 	char buf[1024];
	// 	snprintf(buf, sizeof(buf), ".org %" PRIx64 "\n", addr);
	// 	src += string(buf);
	// 	snprintf(buf, sizeof(buf), ".endian %s\n", (endian == BigEndian) ? "big" : "little");
	// 	src += string(buf);
	// 	src += code;

	// 	/* assemble */
	// 	vector<uint8_t> byteEncoding;
	// 	if (assemble_multiline(src, byteEncoding, errors))
	// 	{
	// 		MYLOG("assemble_multiline() failed, errors contains: %s\n", errors.c_str());
	// 		return false;
	// 	}

	// 	result.Clear();
	// 	// for(int i=0; i<byteEncoding.size(); ++i)
	// 	result.Append(&(byteEncoding[0]), byteEncoding.size());
	// 	return true;
	// }

	/*************************************************************************/

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);
		return false;
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;

		MYLOG("%s()\n", __func__);

		if (len < 4)
		{
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if (endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if ((iw & 0xfc000000) == 0x40000000)
		{ /* BXX B-form */
			MYLOG("BXX B-form\n");
			return true;
		}

		if ((iw & 0xfc0007fe) == 0x4c000020)
		{ /* BXX to LR, XL-form */
			MYLOG("BXX to LR, XL-form\n");

			if ((iw & 0x03E00000) != 0x02800000) /* is already unconditional? */
				return true;
		}

		if ((iw & 0xfc0007fe) == 0x4c000420)
		{ /* BXX to count reg, XL-form */
			MYLOG("BXX to count reg, XL-form\n");

			if ((iw & 0x03E00000) != 0x02800000) /* is already unconditional? */
				return true;
		}

		return false;
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if ((iw & 0xfc000000) == 0x40000000)
		{
			MYLOG("BXX B-form\n");
		}
		else if ((iw & 0xfc0007fe) == 0x4c000020)
		{
			MYLOG("BXX to LR, XL-form\n");
		}
		else if ((iw & 0xfc0007fe) == 0x4c000420)
		{
			MYLOG("BXX to count reg, XL-form\n");
		}
		else
		{
			return false;
		}

		/* BO and BI exist in all 3 of the above forms */
		uint32_t bo = (iw >> 21) & 0x1F;
		if((bo & 0x1E) == 0) return true; // (--ctr)!=0 && cr_bi==0
		if((bo & 0x1E) == 2) return true; // (--ctr)==0 && cr_bi==0
		if((bo & 0x1C) == 4) return true; // cr_bi==0
		if((bo & 0x1E) == 8) return true; // (--ctr)!=0 && cr_bi==1
		if((bo & 0x1E) == 10) return true; // (--ctr)==0 && cr_bi==1
		if((bo & 0x1C) == 12) return true; // cr_bi==1
		return false;
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		uint32_t iw = *(uint32_t *)data;
		if (endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if ((iw & 0xfc000001) == 0x48000001)
		{
			MYLOG("B I-form with LK==1\n");
			return true;
		}
		else if ((iw & 0xfc000001) == 0x40000001)
		{
			MYLOG("BXX B-form with LK==1\n");
			return true;
		}
		else if ((iw & 0xfc0007fe) == 0x4c000020)
		{
			MYLOG("BXX to LR, XL-form\n");
			return true;
		}
		else if ((iw & 0xfc0007ff) == 0x4c000421)
		{
			MYLOG("BXX to count reg, XL-form with LK==1\n");
			return true;
		}

		return false;
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);
		return IsSkipAndReturnZeroPatchAvailable(data, addr, len);
	}

	/*************************************************************************/

	virtual bool ConvertToNop(uint8_t *data, uint64_t, size_t len) override
	{
		(void)len;

		MYLOG("%s()\n", __func__);
		uint32_t nop;
		if (endian == LittleEndian)
		{
			nop = 0x00000001;
		}
		else
		{
			nop = 0x01000000;
		}
		if (len < 4)
		{
			return false;
		}
		for (size_t i = 0; i < len / 4; ++i)
		{
			((uint32_t *)data)[i] = nop;
		}
		return true;
	}

	virtual bool AlwaysBranch(uint8_t *data, uint64_t addr, size_t len) override
	{
		MYLOG("%s()\n", __func__);

		(void)len;
		(void)addr;

		uint32_t iwAfter = 0;
		uint32_t iwBefore = *(uint32_t *)data;
		if (endian == BigEndian)
			iwBefore = bswap32(iwBefore);

		if ((iwBefore & 0xfc000000) == 0x40000000)
		{ /* BXX B-form */
			MYLOG("BXX B-form\n");

			uint32_t li_aa_lk = iwBefore & 0xffff; /* grab BD,AA,LK */
			if (li_aa_lk & 0x8000)				   /* sign extend? */
				li_aa_lk |= 0x03FF0000;

			iwAfter = 0x48000000 | li_aa_lk;
		}
		else if ((iwBefore & 0xfc0007fe) == 0x4c000020)
		{ /* BXX to LR, XL-form */
			MYLOG("BXX to LR, XL-form\n");

			iwAfter = (iwBefore & 0xFC1FFFFF) | 0x02800000; /* set BO = 10100 */
		}
		else if ((iwBefore & 0xfc0007fe) == 0x4c000420)
		{ /* BXX to count reg, XL-form */
			MYLOG("BXX to count reg, XL-form\n");

			iwAfter = (iwBefore & 0xFC1FFFFF) | 0x02800000; /* set BO = 10100 */
		}
		else
		{
			return false;
		}

		if (endian == BigEndian)
			iwAfter = bswap32(iwAfter);
		*(uint32_t *)data = iwAfter;
		return true;
	}

	virtual bool InvertBranch(uint8_t *data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000000) == 0x40000000) {
			MYLOG("BXX B-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000020) {
			MYLOG("BXX to LR, XL-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000420) {
			MYLOG("BXX to count reg, XL-form\n");
		} else {
			return false;
		}

		iw ^= 0x1000000;

		/* success */
		if(endian == BigEndian)
			iw = bswap32(iw);
		*(uint32_t *)data = iw;
		return true;
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)data;
		(void)addr;
		(void)len;
		(void)value;
		MYLOG("%s()\n", __func__);

		if(value > 0x4000)
			return false;

		/* li (load immediate) is pseudo-op for addi rD,rA,SIMM with rA=0 */
		uint32_t iw = 0x38600000 | (value & 0xFFFF); // li (load immediate)

		/* success */
		if(endian == BigEndian)
			iw = bswap32(iw);
		*(uint32_t *)data = iw;
		return true;
	}

	/*************************************************************************/

};

class SparcImportedFunctionRecognizer: public FunctionRecognizer
{
	private:
	bool RecognizeELFPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		MYLOG("%s()\n", __func__);
		LowLevelILInstruction lis, lwz, mtctr, tmp;
		int64_t entry, constGotBase;
		uint32_t regGotBase, regJump;

		// lis   r11, 0x1002     ; r11 -> base of GOT
		// lwz   r11, ???(r11)   ; get GOT[???]
		// mtctr r11             ; move to ctr
		// bctr                  ; branch to ctr
		if(il->GetInstructionCount() != 4)
			return false;

		//
		// LIS   r11, 0x1002
		//
		lis = il->GetInstruction(0);
		if(lis.operation != LLIL_SET_REG)
			return false;
		/* get the constant, address of GOT */
		tmp = lis.GetSourceExpr<LLIL_SET_REG>();
		if ((tmp.operation != LLIL_CONST) && (tmp.operation != LLIL_CONST_PTR) && (tmp.operation != LLIL_EXTERN_PTR))
			return false;
		constGotBase = tmp.GetConstant();
		/* get the destination register, is assigned the address of GOT */
		regGotBase = lis.GetDestRegister<LLIL_SET_REG>();
		//
		// LWZ   r11, ???(r11)
		//
		lwz = il->GetInstruction(1);
		if(lwz.operation != LLIL_SET_REG)
			return false;

		if(lwz.GetDestRegister<LLIL_SET_REG>() != regGotBase) // lwz must assign to same reg
			return false;

		tmp = lwz.GetSourceExpr<LLIL_SET_REG>(); // lwz must read from LOAD
		if(tmp.operation != LLIL_LOAD)
			return false;

		// "dereference" the load(...) to get either:
		tmp = tmp.GetSourceExpr<LLIL_LOAD>();
		// r11         (LLIL_REG)
		if(tmp.operation == LLIL_REG) {
			if(regGotBase != tmp.GetSourceRegister<LLIL_REG>()) // lwz must read from same reg
				return false;

			entry = constGotBase;
		}
		// r11 + ???   (LLIL_ADD)
		else if(tmp.operation == LLIL_ADD) {
			LowLevelILInstruction lhs, rhs;

			lhs = tmp.GetLeftExpr<LLIL_ADD>();
			rhs = tmp.GetRightExpr<LLIL_ADD>();

			if(lhs.operation != LLIL_REG)
				return false;
			if(lhs.GetSourceRegister<LLIL_REG>() != regGotBase)
				return false;

			if(rhs.operation != LLIL_CONST)
				return false;

			entry = constGotBase + rhs.GetConstant();
		}
		else {
			return false;
		}

		//
		// MTCTR
		//
		mtctr = il->GetInstruction(2);
		if(mtctr.operation != LLIL_SET_REG)
			return false;
		/* from regGotBase */
		tmp = mtctr.GetSourceExpr();
		if(tmp.operation != LLIL_REG)
			return false;
		if(tmp.GetSourceRegister<LLIL_REG>() != regGotBase)
			return false;
		/* to new register (probably CTR) */
		regJump = mtctr.GetDestRegister<LLIL_SET_REG>();

		//
		// JUMP
		//
		tmp = il->GetInstruction(3);
		if((tmp.operation != LLIL_JUMP) && (tmp.operation != LLIL_TAILCALL))
			return false;
		tmp = (tmp.operation == LLIL_JUMP) ? tmp.GetDestExpr<LLIL_JUMP>() : tmp.GetDestExpr<LLIL_TAILCALL>();
		if(tmp.operation != LLIL_REG)
			return false;
		if(tmp.GetSourceRegister<LLIL_REG>() != regJump)
			return false;

		// done!
		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym) {
			return false;
		}
		if (sym->GetType() != ImportAddressSymbol) {
			return false;
		}
		data->DefineImportedFunction(sym, func);

		return true;
	}

	public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		if (RecognizeELFPLTEntries(data, func, il))
			return true;
		return false;
	}
};

class SparcSWCallingConvention: public CallingConvention
{
public:
	SparcSWCallingConvention(Architecture* arch): CallingConvention(arch, "sparc_window")
	{
	}

	// Per the sparc spec, I0-I7 should be an input register, but seems
	// like its usually O0-O7
	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			SPARC_REG_O0, SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3,
			SPARC_REG_O4, SPARC_REG_O5, SPARC_REG_O7
			/* remaining arguments onto stack */
		};
	}


	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t>{
			// SPARC_REG_O0, SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3,
			// SPARC_REG_O4, SPARC_REG_O5
		};
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			// SPARC_REG_O0, SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3,
			// SPARC_REG_O4, SPARC_REG_O5, SPARC_REG_SP, SPARC_REG_O7,
		};
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{

			SPARC_REG_I0, SPARC_REG_I1, SPARC_REG_I2, SPARC_REG_I3,
			SPARC_REG_I4, SPARC_REG_I5, SPARC_REG_I7,
			SPARC_REG_L0, SPARC_REG_L1, SPARC_REG_L2, SPARC_REG_L3,
			SPARC_REG_L4, SPARC_REG_L5, SPARC_REG_L6, SPARC_REG_L7,
		};
	}


	virtual uint32_t GetGlobalPointerRegister() override
	{
		return SPARC_REG_G0;
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return SPARC_REG_O0;
	}


	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return SPARC_REG_F0;
	}
};

class SparcLinuxSyscallCallingConvention: public CallingConvention
{
public:
	SparcLinuxSyscallCallingConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	// using the same as the SWCallingConvention
	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			SPARC_REG_O0, SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3,
			SPARC_REG_O4, SPARC_REG_O5, SPARC_REG_O7
			/* remaining arguments onto stack */
		};
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
		};
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{
			SPARC_REG_I0, SPARC_REG_I1, SPARC_REG_I2, SPARC_REG_I3,
			SPARC_REG_I4, SPARC_REG_I5, SPARC_REG_I7,
			SPARC_REG_L0, SPARC_REG_L1, SPARC_REG_L2, SPARC_REG_L3,
			SPARC_REG_L4, SPARC_REG_L5, SPARC_REG_L6, SPARC_REG_L7,
		};
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return SPARC_REG_O0;
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};

uint16_t bswap16(uint16_t x)
{
	return (x >> 8) | (x << 8);
}

class SparcElfRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		(void)view;
		(void)len;
		auto info = reloc->GetInfo();
		uint32_t* dest32 = (uint32_t*)dest;
		uint16_t* dest16 = (uint16_t*)dest;
		auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap32(x); };
		auto swap16 = [&arch](uint16_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap16(x); };
		uint64_t target = reloc->GetTarget();
		switch (info.nativeType)
		{
		// case R_PPC_ADDR16_LO:
		// 	dest16[0] = swap16((uint16_t)((target + info.addend) & 0xffff));
		// 	break;
		// case R_PPC_ADDR16_HA:
		// 	dest16[0] = swap16((uint16_t)((target + info.addend) >> 16));
		// 	break;
		// case R_PPC_REL24:
		// 	dest32[0] = swap((swap(dest32[0]) & 0xfc000003) |
		// 		(uint32_t)((((target + info.addend - reloc->GetAddress()) >> 2) & 0xffffff) << 2));
		// 	break;
		// case R_PPC_REL16_HA:
		// 	dest16[0] = swap16(HA(target - reloc->GetAddress() + info.addend));
		// 	break;
		// case R_PPC_REL16_HI:
		// 	dest16[0] = swap16((uint16_t)((target - reloc->GetAddress()+ info.addend) >> 16));
		// 	break;
		// case R_PPC_REL16_LO:
		// 	dest16[0] = swap16((uint16_t)((target - reloc->GetAddress()+ info.addend) & 0xffff));
		// 	break;
		case R_SPARC_JMP_SLOT:
		case R_SPARC_GLOB_DAT:
		case R_SPARC_COPY:
			dest32[0] = swap((uint32_t)target);
			break;
		// case R_PPC_PLTREL24:
		// 	dest32[0] = swap((swap(dest32[0]) & 0xfc000003) |
		// 		(uint32_t)((((target + info.addend - reloc->GetAddress()) >> 2) & 0xffffff) << 2));
		// 	break;
		// case R_PPC_LOCAL24PC:
		// 	dest32[0] = swap((swap(dest32[0]) & 0xfc000003) |
		// 		(uint32_t)((((target + info.addend - reloc->GetAddress()) >> 2) & 0xffffff) << 2));
		// 	break;
		// case R_PPC_ADDR32:
		// 	dest32[0] = swap((uint32_t)(target + info.addend));
		// 	break;
		case R_SPARC_RELATIVE:
			dest32[0] = swap((uint32_t)info.base);
			break;
		// case R_PPC_REL32:
		// 	dest32[0] = swap((uint32_t)(target - reloc->GetAddress() + info.addend));
		// 	break;
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch; (void)result;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = StandardRelocationType;
			reloc.size = 4;
			reloc.pcRelative = false;
			reloc.dataRelocation = false;
			switch (reloc.nativeType)
			{
			case R_SPARC_NONE:
				reloc.type = IgnoredRelocation;
				break;
			case R_SPARC_COPY:
				reloc.type = ELFCopyRelocationType;
				break;
			case R_SPARC_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				break;
			case R_SPARC_JMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				break;
			// case R_PPC_ADDR16_HA:
			// case R_PPC_ADDR16_LO:
			// 	reloc.size = 2;
			// 	break;
			// case R_PPC_REL16_HA:
			// case R_PPC_REL16_HI:
			// case R_PPC_REL16_LO:
			// 	reloc.size = 2;
			// 	reloc.pcRelative = true;
			// 	break;
			// case R_PPC_REL24:
			// case R_PPC_PLTREL24:
			// 	reloc.pcRelative = true;
			// 	break;
			// case R_PPC_ADDR32:
			// 	reloc.dataRelocation = true;
			// 	break;
			// case R_PPC_RELATIVE:
			// 	reloc.dataRelocation = true;
			// 	reloc.baseRelative = true;
			// 	reloc.base += reloc.addend;
			// 	break;
			// case R_SPARC_REL32:
			// 	reloc.pcRelative = true;
			// 	break;
			// case R_PPC_LOCAL24PC:
			// 	reloc.pcRelative = true;
			// 	break;
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported ELF relocation type: %s", GetRelocationString((ElfSparcRelocationType)reloc));
		return true;
	}

	virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
		Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override
	{
		(void)data;
		(void)addr;
		(void)length;
		(void)il;
		auto info = relocation->GetInfo();
		switch (info.nativeType)
		{
		// case R_PPC_ADDR16_HA:
		// case R_PPC_REL16_HA:
		// case R_PPC_REL16_HI:
		// 	return BN_NOCOERCE_EXTERN_PTR;
		default:
			return BN_AUTOCOERCE_EXTERN_PTR;
		}
	}
};

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
		AddOptionalPluginDependency("view_macho");
		AddOptionalPluginDependency("view_pe");
	}
#endif

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		MYLOG("ARCH SPARC compiled at %s %s\n", __DATE__, __TIME__);

		/* create, register arch in global list of available architectures */
		Architecture* sparco = new SparcArchitecture("sparc", BigEndian);
		Architecture::Register(sparco);

		// Architecture* sparc9 = new SparcArchitecture("sparcv9", BigEndian, 4, CS_MODE_V9);
		// Architecture::Register(sparc9);

		Architecture* sparc9_64 = new SparcArchitecture("sparcv9_64", BigEndian, 8, CS_MODE_V9);
		Architecture::Register(sparc9_64);

		/* calling conventions */
		Ref<CallingConvention> conv;
		conv = new SparcSWCallingConvention(sparco);
		sparco->RegisterCallingConvention(conv);
		sparco->SetDefaultCallingConvention(conv);
		// sparc9->RegisterCallingConvention(conv);
		// sparc9->SetDefaultCallingConvention(conv);
		sparc9_64->RegisterCallingConvention(conv);
		sparc9_64->SetDefaultCallingConvention(conv);
		conv = new SparcLinuxSyscallCallingConvention(sparco);
		sparco->RegisterCallingConvention(conv);
		// sparc9->RegisterCallingConvention(conv);
		sparc9_64->RegisterCallingConvention(conv);

		/* function recognizer */
		sparco->RegisterFunctionRecognizer(new SparcImportedFunctionRecognizer());
		// sparc9->RegisterFunctionRecognizer(new SparcImportedFunctionRecognizer());
		sparc9_64->RegisterFunctionRecognizer(new SparcImportedFunctionRecognizer());

		sparco->RegisterRelocationHandler("ELF", new SparcElfRelocationHandler());
		// sparc9->RegisterRelocationHandler("ELF", new SparcElfRelocationHandler());
		sparc9_64->RegisterRelocationHandler("ELF", new SparcElfRelocationHandler());

		/* for e_machine field in Elf32_Ehdr */
		#define EM_SPARC 0x02
		#define EM_SPARC9 0x2b
		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_SPARC, /* id (key in m_arch map) */
			BigEndian,
			sparco /* the architecture */
		);

		// BinaryViewType::RegisterArchitecture(
		// 	"ELF", /* name of the binary view type */
		// 	EM_SPARC9, /* id (key in m_arch map) */
		// 	BigEndian,
		// 	sparco /* the architecture */
		// );

		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_SPARC9, /* id (key in m_arch map) */
			BigEndian,
			sparc9_64 /* the architecture */
		);

		return true;
	}
}
