#include <stdint.h>

uint32_t genMask(uint32_t mb, uint32_t me)
{
	uint32_t maskBegin = ~0u >> mb;
	uint32_t maskEnd = ~0u << (31 - me);

	return (mb <= me) ? (maskBegin & maskEnd) : (maskBegin | maskEnd);
}

uint64_t sign_extend_bitnn(uint64_t in, int bitoffset, int bitwidth)
{
	uint64_t target = 0;
	uint64_t bitwidthmask = 0;
	uint64_t semask = 0;

	// target = insn & 0x003fffff;

	// // 22 bit immediate
	// if ((target >> 21) == 1)
	// {
	// 	target |= 0xffffffffffc00000;
	// }

	semask = (1 << (bitwidth + bitoffset)) - 1;

	bitwidthmask = (1 << (bitwidth + bitoffset)) - 1;
	
	// remove lower bits
	bitwidthmask = bitwidthmask & ~((1 << bitoffset) - 1);
	target = in & bitwidthmask;

	// check for signage
	if ((target >> ((bitwidth + bitoffset) - 1)) == 1)
	{
		// sign extend
		target |= ~semask;
	}
	return target;
}

