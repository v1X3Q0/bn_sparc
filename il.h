/* these are the flags in cr0
	(the default condition field in condition register CR)

PPC docs conceptualize this in a reverse bit order of sorts:

     CR0         CR1
 ----------- ----------- 
 b0 b1 b2 b3 b4 b5 b6 b7 
+--+--+--+--+--+--+--+--+ ...
|LT|GT|EQ|SO|LT|GT|EQ|SO|
+--+--+--+--+--+--+--+--+  

or is it: |SO|LT|GT|EQ
eg: cmp a, b
if a<b  then c=0b100 (not setting SO, setting LT)
if a>b  then c=0b010 (not setting SO, setting GT)
if a==b then c=0b001 (not setting SO, setting EQ)
 */

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
