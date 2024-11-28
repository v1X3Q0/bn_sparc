/******************************************************************************

This is the layer that the architecture module uses to access disassemble
functionality.

Currently, it wraps capstone, but that could change in the future. It exists
precisely to make swapping out disassemblers easy, because disassembler details
(like capstone types) will not be intertwined in the architecture plugin code.

Also, with the disassembler object separate, we can link it against
easy-to-compile test harnesses like the speed test.

There are three main functions:

sparc_init() - initializes this module
sparc_release() - un-initializes this module
sparc_decompose() - converts bytes into decomp_result
sparc_disassemble() - converts decomp_result to string

Then some helpers if you need them:

******************************************************************************/

/* capstone stuff /usr/local/include/capstone */
#include "capstone/capstone.h"
#include "capstone/cs_priv.h"
#include "capstone/sparc.h"

#define SPARC_CALL_MASK		0xc0000000
#define SPARC_CALL_MASKED	0x40000000

#define SPARC_B_MASK		0xc1c00000
#define SPARC_B_MASKED		0x00400000

#define SPARC_BP_MASK		0xd1c00000
#define SPARC_BP_MASKED		0x00c00000

//*****************************************************************************
// structs and types
//*****************************************************************************
enum sparc_status_t {
    STATUS_ERROR_UNSPEC=-1, STATUS_SUCCESS=0, STATUS_UNDEF_INSTR
};

/* operand type */
enum operand_type_t { REG, VAL, LABEL };

struct decomp_request
{
    uint8_t *data;
	int size;
    uint32_t addr;
    bool lil_end;
};

struct decomp_result
{
	/* actual capstone handle used, in case caller wants to do extra stuff
		(this can be one of two handles opened for BE or LE disassembling) */
	csh handle;

    sparc_status_t status;

	cs_insn insn;
	cs_detail detail;
};

//*****************************************************************************
// function prototypes
//*****************************************************************************
int DoesQualifyForLocalDisassembly(const uint8_t *data, bool bigendian);
bool PerformLocalDisassembly(const uint8_t *data, uint64_t addr, size_t &len, decomp_result* res, bool bigendian);

extern "C" int sparc_init(int);
extern "C" void sparc_release(void);
extern "C" int sparc_decompose(const uint8_t *data, int size, uint32_t addr, 
	bool lil_end, struct decomp_result *result, bool is_64bit, int cs_mode);
extern "C" int sparc_disassemble(struct decomp_result *, char *buf, size_t len);

extern "C" const char *sparc_reg_to_str(uint32_t rid, int);

