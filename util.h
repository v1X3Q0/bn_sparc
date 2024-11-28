#ifdef __clang__
#define FALL_THROUGH
#elif defined(__GNUC__) && __GNUC__ >= 7
#define FALL_THROUGH __attribute__((fallthrough));
#else
#define FALL_THROUGH
#endif

inline uint32_t bswap32(uint32_t x)
{
	return ((x&0xFF)<<24) |
		((x&0xFF00)<<8) |
		((x&0xFF0000)>>8) |
		((x&0xFF000000)>>24);
}

void printOperandVerbose(decomp_result *res, cs_ppc_op *opers);
void printInstructionVerbose(decomp_result *res);

uint32_t genMask(uint32_t mb, uint32_t me);
uint64_t sign_extend_bitnn(uint64_t in, int bitoffset, int bitwidth);
