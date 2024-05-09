/******************************************************************************

Tests just the disassembler part (NOT the architecture plugin).

Provide command line arguments for different cool tests.
Like `./test repl` to get an interactive disassembler
Like `./test speed` to get a timed test of instruction decomposition

g++ -std=c++11 -O0 -g -I capstone/include -L./build/capstone test_disasm.cpp disassembler.cpp -o test_disasm -lcapstone

******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <unistd.h>

#include "disassembler.h"

int print_errors = 1;
int cs_mode_local = 0;
size_t address_size_ = 4;
bool bigendian = true;

int disas_instr_word(uint32_t instr_word, char *buf)
{
	int rc = -1;

	struct decomp_result res = {0};
	struct cs_insn *insn = &(res.insn);
	struct cs_detail *detail = &(res.detail);
	struct cs_ppc *ppc = &(detail->ppc);

	if (sparc_decompose((const uint8_t *)&instr_word, 4, 0, bigendian, &res, address_size_, cs_mode_local))
	{
		if (print_errors)
		{
			if (DoesQualifyForLocalDisassembly((uint8_t *)&instr_word, !bigendian) != PPC_INS_INVALID)
			{
				size_t instsz = 4;
				PerformLocalDisassembly((uint8_t *)&instr_word, 0, instsz, &res, !bigendian);
			}
			else
			{
				printf("ERROR: sparc_decompose()\n");
				goto cleanup;
			}
		}
	}

	if (sparc_disassemble(&res, buf, 128))
	{
		if (print_errors)
			printf("ERROR: sparc_disassemble()\n");
		goto cleanup;
	}

	rc = 0;
cleanup:
	return rc;
}

void usage()
{
	printf("send argument \"repl\" or \"speed\"\n");
}

int main(int ac, char **av)
{
	int rc = -1;
	char buf[256];
	int index;
	char *disasm_cmd = 0;
	int c;

#define BATCH 10000000
	opterr = 0;

	while ((c = getopt(ac, av, "")) != -1)
	{
		switch (c)
		{
		default:
			usage();
			goto cleanup;
		}
	}

	if (optind >= ac)
	{
		usage();
		goto cleanup;
	}

	disasm_cmd = av[optind];

	sparc_init(cs_mode_local);

	printf("REPL mode!\n");
	printf("example inputs (write the words as if after endian fetch):\n");
	printf("93e1fffc\n");
	printf("9421ffe0\n");
	printf("7c3fb380\n");
	printf("38a00000\n");
	while (1)
	{
		printf("disassemble> ");

		/* get line */
		if (NULL == fgets(buf, sizeof(buf), stdin))
		{
			printf("ERROR: fgets()\n");
			continue;
		}

		uint32_t instr_word = strtoul(buf, NULL, 16);
		// printf("instruction word: %08X\n", instr_word);

		/* convert to string */
		if (disas_instr_word(instr_word, buf))
		{
			printf("ERROR: disas_instr_word()\n");
			continue;
		}

		printf("%s\n", buf);
	}

	rc = 0;
cleanup:
	return rc;
}
