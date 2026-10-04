
bitops.x86.o:	file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <ctz_nonzero>:
       0:      	tzcntq	%rdi, %rax
       5:      	retq
       6:      	nopw	%cs:(%rax,%rax)

0000000000000010 <ctz_defined>:
      10:      	tzcntq	%rdi, %rax
      15:      	retq
      16:      	nopw	%cs:(%rax,%rax)

0000000000000020 <popcount>:
      20:      	popcntq	%rdi, %rax
      25:      	retq
      26:      	nopw	%cs:(%rax,%rax)

0000000000000030 <clz_defined>:
      30:      	lzcntq	%rdi, %rax
      35:      	retq
      36:      	nopw	%cs:(%rax,%rax)

0000000000000040 <lowest_bit>:
      40:      	blsiq	%rdi, %rax
      45:      	retq
      46:      	nopw	%cs:(%rax,%rax)

0000000000000050 <rotate>:
      50:      	movq	%rsi, %rcx
      53:      	movq	%rdi, %rax
      56:      	rolq	%cl, %rax
      59:      	retq
