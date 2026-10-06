/*
 * ICC model: %icc is lifted as a 1-byte register (SPARC_REG_ICC) with the
 * following bit layout:
 *
 *   bit 3 (0x8) N   negative result
 *   bit 2 (0x4) Z   zero result
 *   bit 1 (0x2) C   carry (add) / borrow (sub, cmp)
 *   bit 0 (0x1) V   signed overflow
 */

#define IL_ICC_N 8
#define IL_ICC_Z 4
#define IL_ICC_C 2
#define IL_ICC_V 1

#define IL_FLAG_LT 0
#define IL_FLAG_GT 1
#define IL_FLAG_EQ 2
#define IL_FLAG_SO 3

/* the different types of influence an instruction can have over flags */
#define IL_FLAGWRITE_NONE 0
#define IL_FLAGWRITE_CC_S 1
#define IL_FLAGWRITE_CC_U 2

#define IL_FLAGWRITE_INVALL 40

/* the different classes of writes to each cr */
#define IL_FLAGCLASS_NONE 0
#define IL_FLAGCLASS_CC_S 1
#define IL_FLAGCLASS_CC_U 2

#define IL_FLAGGROUP_CC_LT (0 + 0)
#define IL_FLAGGROUP_CC_LE (0 + 1)
#define IL_FLAGGROUP_CC_GT (0 + 2)
#define IL_FLAGGROUP_CC_GE (0 + 3)
#define IL_FLAGGROUP_CC_EQ (0 + 4)
#define IL_FLAGGROUP_CC_NE (0 + 5)

bool GetLowLevelILForSparcInstruction(Architecture *arch, LowLevelILFunction& il, const uint8_t *data, uint64_t addr, decomp_result *res, bool le);

typedef enum {
	SPARC_BRANCH_CONDITIONAL = 0,
	SPARC_BRANCH_UNCOND,
	SPARC_BRANCH_NEVER
} sparc_branch_disp_t;

sparc_branch_disp_t SparcClassifyBranch(uint32_t insnId, const char *mnemonic, sparc_cc cc);
bool SparcBranchTarget(decomp_result *res, uint64_t *target);
bool SparcJmplIsReturn(decomp_result *res);

/* ---------------------------------------------------------------------------
 * branch patching support (arch_sparc.cpp Is*PatchAvailable / patch funcs)
 *
 * Branch instructions (b/fb families) carry their condition in a 4-bit field
 * (word bits 28:25) that uses the same numbering as the low nibble of
 * capstone's SPARC_CC_ICC_* / SPARC_CC_FCC_* enums (verified against
 * llvm-mc): n=0, e=1, le=2, l=3, leu=4, cs=5, neg=6, vs=7, a=8, ne=9, g=10,
 * ge=11, gu=12, cc=13, pos=14, vc=15. Every condition's complement is 8 away
 * and "always" is 8, so forcing or flipping a condition never requires
 * interpreting the table: set, clear or xor bit 28. Both hold identically for
 * icc, xcc and fcc conditions -- the nibble is shared and the cc selector
 * bits elsewhere in the word pick the table.
 *
 * The V9 branch-register forms (brz family) encode their condition elsewhere;
 * there the complements brz/brnz, brlez/brgz and brlz/brgez are 4 nibble
 * steps apart, i.e. inversion is an xor of bit 27. They have no "always"
 * encoding, so those are only invertible.
 * ------------------------------------------------------------------------- */

typedef enum {
	SPARC_PATCH_NOT_BRANCH = 0,
	SPARC_PATCH_COND_BRANCH,   /* b / fb: condition nibble at bits 28:25 */
	SPARC_PATCH_BRZ_BRANCH     /* brz family: condition bit at bit 26 */
} sparc_patch_kind_t;

#define SPARC_PATCH_ALWAYS 0
#define SPARC_PATCH_NEVER  1
#define SPARC_PATCH_INVERT 2

sparc_patch_kind_t SparcPatchBranchKind(uint32_t insnId);
bool SparcApplyBranchPatch(uint32_t *word, sparc_patch_kind_t kind, int mode);

/* mov <simm>, %%o0 (i.e. add %%g0, simm13, %%o0): the one-instruction body
 * Binary Ninja writes over a call site to skip the call and "return" value.
 * Only the simm13 range encodes this way; anything else fails. */
bool SparcEncodeReturnInO0(uint64_t value, uint32_t *word);
