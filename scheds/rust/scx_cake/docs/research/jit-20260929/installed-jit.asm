
/usr/lib/modules/7.2.8-1-cachyos/build/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81378a10 <do_jit>:
ffffffff81378a10: 0f 1f 44 00 00       	nopl	(%rax,%rax)
ffffffff81378a15: 55                   	pushq	%rbp
ffffffff81378a16: 48 89 e5             	movq	%rsp, %rbp
ffffffff81378a19: 41 57                	pushq	%r15
ffffffff81378a1b: 41 56                	pushq	%r14
ffffffff81378a1d: 41 55                	pushq	%r13
ffffffff81378a1f: 41 54                	pushq	%r12
ffffffff81378a21: 53                   	pushq	%rbx
ffffffff81378a22: 48 83 e4 f0          	andq	$-0x10, %rsp
ffffffff81378a26: 48 81 ec a0 01 00 00 	subq	$0x1a0, %rsp            # imm = 0x1A0
ffffffff81378a2d: 48 89 54 24 20       	movq	%rdx, 0x20(%rsp)
ffffffff81378a32: 44 89 8c 24 a4 00 00 00      	movl	%r9d, 0xa4(%rsp)
ffffffff81378a3a: 4c 89 44 24 70       	movq	%r8, 0x70(%rsp)
ffffffff81378a3f: 48 89 4c 24 78       	movq	%rcx, 0x78(%rsp)
ffffffff81378a44: 45 31 e4             	xorl	%r12d, %r12d
ffffffff81378a47: 49 89 ff             	movq	%rdi, %r15
ffffffff81378a4a: 48 8d bc 24 d0 00 00 00      	leaq	0xd0(%rsp), %rdi
ffffffff81378a52: ba c0 00 00 00       	movl	$0xc0, %edx
ffffffff81378a57: 48 89 f3             	movq	%rsi, %rbx
ffffffff81378a5a: 65 48 8b 05 b6 b5 44 03      	movq	%gs:0x344b5b6(%rip), %rax
ffffffff81378a62: 48 89 84 24 90 01 00 00      	movq	%rax, 0x190(%rsp)
ffffffff81378a6a: 4c 8b 76 50          	movq	0x50(%rsi), %r14
ffffffff81378a6e: 41 8a 86 96 00 00 00 	movb	0x96(%r14), %al
ffffffff81378a75: 44 89 a4 24 cc 00 00 00      	movl	%r12d, 0xcc(%rsp)
ffffffff81378a7d: 44 8b 6e 10          	movl	0x10(%rsi), %r13d
ffffffff81378a81: 31 f6                	xorl	%esi, %esi
ffffffff81378a83: 88 44 24 46          	movb	%al, 0x46(%rsp)
ffffffff81378a87: e8 84 fd 29 01       	callq	0xffffffff82618810 <memset>
ffffffff81378a8c: 48 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %rax
ffffffff81378a94: 4c 89 bc 24 b8 00 00 00      	movq	%r15, 0xb8(%rsp)
ffffffff81378a9c: 4c 89 ff             	movq	%r15, %rdi
ffffffff81378a9f: 48 89 de             	movq	%rbx, %rsi
ffffffff81378aa2: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81378aaa: 45 8b 76 1c          	movl	0x1c(%r14), %r14d
ffffffff81378aae: e8 dd 12 0e 00       	callq	0xffffffff81459d90 <bpf_out_stack_arg_cnt>
ffffffff81378ab3: 48 8b 4b 50          	movq	0x50(%rbx), %rcx
ffffffff81378ab7: 48 89 44 24 10       	movq	%rax, 0x10(%rsp)
ffffffff81378abc: 4c 8b 79 58          	movq	0x58(%rcx), %r15
ffffffff81378ac0: 48 8b b9 c8 00 00 00 	movq	0xc8(%rcx), %rdi
ffffffff81378ac7: 4d 85 ff             	testq	%r15, %r15
ffffffff81378aca: 45 0f 44 e6          	cmovel	%r14d, %r12d
ffffffff81378ace: 4c 89 64 24 58       	movq	%r12, 0x58(%rsp)
ffffffff81378ad3: e8 b8 13 0e 00       	callq	0xffffffff81459e90 <bpf_arena_get_kern_vm_start>
ffffffff81378ad8: 48 8b 4b 50          	movq	0x50(%rbx), %rcx
ffffffff81378adc: 48 89 84 24 80 00 00 00      	movq	%rax, 0x80(%rsp)
ffffffff81378ae4: 48 8b b9 c8 00 00 00 	movq	0xc8(%rcx), %rdi
ffffffff81378aeb: e8 00 13 0e 00       	callq	0xffffffff81459df0 <bpf_arena_get_user_vm_start>
ffffffff81378af0: 44 8a 4c 24 46       	movb	0x46(%rsp), %r9b
ffffffff81378af5: 48 89 84 24 b0 00 00 00      	movq	%rax, 0xb0(%rsp)
ffffffff81378afd: 4c 89 ac 24 90 00 00 00      	movq	%r13, 0x90(%rsp)
ffffffff81378b05: 45 85 ed             	testl	%r13d, %r13d
ffffffff81378b08: 0f 8f 70 0a 00 00    	jg	0xffffffff8137957e <do_jit+0xb6e>
ffffffff81378b0e: 48 8b 43 50          	movq	0x50(%rbx), %rax
ffffffff81378b12: 8b 73 08             	movl	0x8(%rbx), %esi
ffffffff81378b15: 8b 3d 9d dc dc 01    	movl	0x1dcdc9d(%rip), %edi   # 0xffffffff831467b8 <cfi_mode>
ffffffff81378b1b: 49 89 dd             	movq	%rbx, %r13
ffffffff81378b1e: 8b 48 2c             	movl	0x2c(%rax), %ecx
ffffffff81378b21: 8a 90 98 00 00 00    	movb	0x98(%rax), %dl
ffffffff81378b27: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff81378b2f: 85 c9                	testl	%ecx, %ecx
ffffffff81378b31: 74 4a                	je	0xffffffff81378b7d <do_jit+0x16d>
ffffffff81378b33: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff81378b38: 83 ff 02             	cmpl	$0x2, %edi
ffffffff81378b3b: 0f 84 83 00 00 00    	je	0xffffffff81378bc4 <do_jit+0x1b4>
ffffffff81378b41: 83 ff 03             	cmpl	$0x3, %edi
ffffffff81378b44: 0f 85 aa 00 00 00    	jne	0xffffffff81378bf4 <do_jit+0x1e4>
ffffffff81378b4a: bf 0c f0 e1 05       	movl	$0x5e1f00c, %edi        # imm = 0x5E1F00C
ffffffff81378b4f: f7 d7                	notl	%edi
ffffffff81378b51: 89 38                	movl	%edi, (%rax)
ffffffff81378b53: bf 14 00 00 00       	movl	$0x14, %edi
ffffffff81378b58: c6 40 04 2d          	movb	$0x2d, 0x4(%rax)
ffffffff81378b5c: c7 40 05 00 00 00 00 	movl	$0x0, 0x5(%rax)
ffffffff81378b63: c7 40 09 2e 0f 85 00 	movl	$0x850f2e, 0x9(%rax)    # imm = 0x850F2E
ffffffff81378b6a: c7 40 0c 03 00 00 00 	movl	$0x3, 0xc(%rax)
ffffffff81378b71: c7 40 10 0f 1f 40 d6 	movl	$0xd6401f0f, 0x10(%rax) # imm = 0xD6401F0F
ffffffff81378b78: e9 85 00 00 00       	jmp	0xffffffff81378c02 <do_jit+0x1f2>
ffffffff81378b7d: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff81378b82: 83 ff 02             	cmpl	$0x2, %edi
ffffffff81378b85: 0f 84 fc 05 00 00    	je	0xffffffff81379187 <do_jit+0x777>
ffffffff81378b8b: 83 ff 03             	cmpl	$0x3, %edi
ffffffff81378b8e: 0f 85 26 06 00 00    	jne	0xffffffff813791ba <do_jit+0x7aa>
ffffffff81378b94: bf 0c f0 e1 05       	movl	$0x5e1f00c, %edi        # imm = 0x5E1F00C
ffffffff81378b99: f7 d7                	notl	%edi
ffffffff81378b9b: 89 38                	movl	%edi, (%rax)
ffffffff81378b9d: bf 14 00 00 00       	movl	$0x14, %edi
ffffffff81378ba2: c6 40 04 2d          	movb	$0x2d, 0x4(%rax)
ffffffff81378ba6: c7 40 05 00 00 00 00 	movl	$0x0, 0x5(%rax)
ffffffff81378bad: c7 40 09 2e 0f 85 00 	movl	$0x850f2e, 0x9(%rax)    # imm = 0x850F2E
ffffffff81378bb4: c7 40 0c 03 00 00 00 	movl	$0x3, 0xc(%rax)
ffffffff81378bbb: c7 40 10 0f 1f 40 d6 	movl	$0xd6401f0f, 0x10(%rax) # imm = 0xD6401F0F
ffffffff81378bc2: eb 3e                	jmp	0xffffffff81378c02 <do_jit+0x1f2>
ffffffff81378bc4: c6 00 b8             	movb	$-0x48, (%rax)
ffffffff81378bc7: c7 40 01 00 00 00 00 	movl	$0x0, 0x1(%rax)
ffffffff81378bce: 48 bf 90 90 90 90 90 90 90 90	movabsq	$-0x6f6f6f6f6f6f6f70, %rdi # imm = 0x9090909090909090
ffffffff81378bd8: 48 89 78 05          	movq	%rdi, 0x5(%rax)
ffffffff81378bdc: c7 40 0c 90 90 90 90 	movl	$0x90909090, 0xc(%rax)  # imm = 0x90909090
ffffffff81378be3: bf 0c f0 e1 05       	movl	$0x5e1f00c, %edi        # imm = 0x5E1F00C
ffffffff81378be8: f7 d7                	notl	%edi
ffffffff81378bea: 89 78 10             	movl	%edi, 0x10(%rax)
ffffffff81378bed: bf 14 00 00 00       	movl	$0x14, %edi
ffffffff81378bf2: eb 0e                	jmp	0xffffffff81378c02 <do_jit+0x1f2>
ffffffff81378bf4: bf 0c f0 e1 05       	movl	$0x5e1f00c, %edi        # imm = 0x5E1F00C
ffffffff81378bf9: f7 d7                	notl	%edi
ffffffff81378bfb: 89 38                	movl	%edi, (%rax)
ffffffff81378bfd: bf 04 00 00 00       	movl	$0x4, %edi
ffffffff81378c02: c7 04 38 0f 1f 44 00 	movl	$0x441f0f, (%rax,%rdi)  # imm = 0x441F0F
ffffffff81378c09: c6 44 38 04 00       	movb	$0x0, 0x4(%rax,%rdi)
ffffffff81378c0e: 85 f6                	testl	%esi, %esi
ffffffff81378c10: 0f 84 20 0a 00 00    	je	0xffffffff81379636 <do_jit+0xc26>
ffffffff81378c16: 48 01 f8             	addq	%rdi, %rax
ffffffff81378c19: 85 c9                	testl	%ecx, %ecx
ffffffff81378c1b: 40 0f 94 c6          	sete	%sil
ffffffff81378c1f: 44 84 ce             	testb	%r9b, %sil
ffffffff81378c22: 74 09                	je	0xffffffff81378c2d <do_jit+0x21d>
ffffffff81378c24: c7 40 05 48 31 c0 00 	movl	$0xc03148, 0x5(%rax)    # imm = 0xC03148
ffffffff81378c2b: eb 0a                	jmp	0xffffffff81378c37 <do_jit+0x227>
ffffffff81378c2d: 66 c7 40 05 0f 1f    	movw	$0x1f0f, 0x5(%rax)      # imm = 0x1F0F
ffffffff81378c33: c6 40 07 00          	movb	$0x0, 0x7(%rax)
ffffffff81378c37: 48 83 c0 08          	addq	$0x8, %rax
ffffffff81378c3b: 84 d2                	testb	%dl, %dl
ffffffff81378c3d: 74 32                	je	0xffffffff81378c71 <do_jit+0x261>
ffffffff81378c3f: c7 00 48 89 f4 00    	movl	$0xf48948, (%rax)       # imm = 0xF48948
ffffffff81378c45: ba 12 00 00 00       	movl	$0x12, %edx
ffffffff81378c4a: c7 40 03 48 89 d5 00 	movl	$0xd58948, 0x3(%rax)    # imm = 0xD58948
ffffffff81378c51: c7 40 06 41 5f 41 5e 	movl	$0x5e415f41, 0x6(%rax)  # imm = 0x5E415F41
ffffffff81378c58: 66 c7 40 0a 41 5d    	movw	$0x5d41, 0xa(%rax)      # imm = 0x5D41
ffffffff81378c5e: c6 40 0c 5b          	movb	$0x5b, 0xc(%rax)
ffffffff81378c62: 66 c7 40 0d 41 5c    	movw	$0x5c41, 0xd(%rax)      # imm = 0x5C41
ffffffff81378c68: c7 40 0f 48 89 ec 00 	movl	$0xec8948, 0xf(%rax)    # imm = 0xEC8948
ffffffff81378c6f: eb 0f                	jmp	0xffffffff81378c80 <do_jit+0x270>
ffffffff81378c71: c6 00 55             	movb	$0x55, (%rax)
ffffffff81378c74: c7 40 01 48 89 e5 00 	movl	$0xe58948, 0x1(%rax)    # imm = 0xE58948
ffffffff81378c7b: ba 04 00 00 00       	movl	$0x4, %edx
ffffffff81378c80: be 0c f0 e1 05       	movl	$0x5e1f00c, %esi        # imm = 0x5E1F00C
ffffffff81378c85: f7 d6                	notl	%esi
ffffffff81378c87: 89 b4 24 a0 00 00 00 	movl	%esi, 0xa0(%rsp)
ffffffff81378c8e: 89 34 10             	movl	%esi, (%rax,%rdx)
ffffffff81378c91: 45 85 c0             	testl	%r8d, %r8d
ffffffff81378c94: 0f 84 b6 04 00 00    	je	0xffffffff81379150 <do_jit+0x740>
ffffffff81378c9a: 41 8d 70 ff          	leal	-0x1(%r8), %esi
ffffffff81378c9e: 48 01 d0             	addq	%rdx, %rax
ffffffff81378ca1: 83 ce 07             	orl	$0x7, %esi
ffffffff81378ca4: c7 40 04 48 81 ec 00 	movl	$0xec8148, 0x4(%rax)    # imm = 0xEC8148
ffffffff81378cab: ff c6                	incl	%esi
ffffffff81378cad: 89 70 07             	movl	%esi, 0x7(%rax)
ffffffff81378cb0: 48 83 c0 0b          	addq	$0xb, %rax
ffffffff81378cb4: 45 84 c9             	testb	%r9b, %r9b
ffffffff81378cb7: 0f 85 83 09 00 00    	jne	0xffffffff81379640 <do_jit+0xc30>
ffffffff81378cbd: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81378cc5: 4c 8d 8c 24 d0 00 00 00      	leaq	0xd0(%rsp), %r9
ffffffff81378ccd: 41 ff ce             	decl	%r14d
ffffffff81378cd0: 49 8b 4d 50          	movq	0x50(%r13), %rcx
ffffffff81378cd4: 44 29 c8             	subl	%r9d, %eax
ffffffff81378cd7: 89 81 74 03 00 00    	movl	%eax, 0x374(%rcx)
ffffffff81378cdd: 49 8b 45 50          	movq	0x50(%r13), %rax
ffffffff81378ce1: 80 b8 99 00 00 00 01 	cmpb	$0x1, 0x99(%rax)
ffffffff81378ce8: 0f 85 78 09 00 00    	jne	0xffffffff81379666 <do_jit+0xc56>
ffffffff81378cee: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff81378cf6: 66 c7 00 41 54       	movw	$0x5441, (%rax)         # imm = 0x5441
ffffffff81378cfb: c6 40 02 53          	movb	$0x53, 0x2(%rax)
ffffffff81378cff: c7 40 03 41 55 41 56 	movl	$0x56415541, 0x3(%rax)  # imm = 0x56415541
ffffffff81378d06: 48 83 c0 07          	addq	$0x7, %rax
ffffffff81378d0a: 66 c7 00 41 57       	movw	$0x5741, (%rax)         # imm = 0x5741
ffffffff81378d0f: 48 83 c0 02          	addq	$0x2, %rax
ffffffff81378d13: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81378d1b: 41 83 ce 07          	orl	$0x7, %r14d
ffffffff81378d1f: 48 83 bc 24 80 00 00 00 00   	cmpq	$0x0, 0x80(%rsp)
ffffffff81378d28: 49 8b 4d 50          	movq	0x50(%r13), %rcx
ffffffff81378d2c: 40 0f 95 c6          	setne	%sil
ffffffff81378d30: 8a 91 99 00 00 00    	movb	0x99(%rcx), %dl
ffffffff81378d36: 40 08 d6             	orb	%dl, %sil
ffffffff81378d39: 44 0f b6 e6          	movzbl	%sil, %r12d
ffffffff81378d3d: 41 c1 e4 03          	shll	$0x3, %r12d
ffffffff81378d41: 84 d2                	testb	%dl, %dl
ffffffff81378d43: 0f 85 97 09 00 00    	jne	0xffffffff813796e0 <do_jit+0xcd0>
ffffffff81378d49: 0f b6 b4 24 cc 00 00 00      	movzbl	0xcc(%rsp), %esi
ffffffff81378d51: 0f b6 bc 24 cd 00 00 00      	movzbl	0xcd(%rsp), %edi
ffffffff81378d59: 41 8d 34 f4          	leal	(%r12,%rsi,8), %esi
ffffffff81378d5d: 8d 34 fe             	leal	(%rsi,%rdi,8), %esi
ffffffff81378d60: 0f b6 bc 24 ce 00 00 00      	movzbl	0xce(%rsp), %edi
ffffffff81378d68: 8d 34 fe             	leal	(%rsi,%rdi,8), %esi
ffffffff81378d6b: 0f b6 bc 24 cf 00 00 00      	movzbl	0xcf(%rsp), %edi
ffffffff81378d73: 44 8d 24 fe          	leal	(%rsi,%rdi,8), %r12d
ffffffff81378d77: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81378d7c: 41 ff c6             	incl	%r14d
ffffffff81378d7f: 31 f6                	xorl	%esi, %esi
ffffffff81378d81: 66 83 ff 02          	cmpw	$0x2, %di
ffffffff81378d85: 8d 3c fd f8 ff ff ff 	leal	-0x8(,%rdi,8), %edi
ffffffff81378d8c: 0f 42 fe             	cmovbl	%esi, %edi
ffffffff81378d8f: 84 d2                	testb	%dl, %dl
ffffffff81378d91: 0f 85 52 09 00 00    	jne	0xffffffff813796e9 <do_jit+0xcd9>
ffffffff81378d97: 89 7c 24 6c          	movl	%edi, 0x6c(%rsp)
ffffffff81378d9b: 66 85 ff             	testw	%di, %di
ffffffff81378d9e: 0f 85 59 09 00 00    	jne	0xffffffff813796fd <do_jit+0xced>
ffffffff81378da4: 48 83 bc 24 80 00 00 00 00   	cmpq	$0x0, 0x80(%rsp)
ffffffff81378dad: 4b 8d 5c 37 08       	leaq	0x8(%r15,%r14), %rbx
ffffffff81378db2: 0f 85 67 09 00 00    	jne	0xffffffff8137971f <do_jit+0xd0f>
ffffffff81378db8: 4d 85 ff             	testq	%r15, %r15
ffffffff81378dbb: 0f 94 c0             	sete	%al
ffffffff81378dbe: 48 85 db             	testq	%rbx, %rbx
ffffffff81378dc1: 0f 94 c1             	sete	%cl
ffffffff81378dc4: 08 c1                	orb	%al, %cl
ffffffff81378dc6: 88 4c 24 47          	movb	%cl, 0x47(%rsp)
ffffffff81378dca: 0f 84 82 09 00 00    	je	0xffffffff81379752 <do_jit+0xd42>
ffffffff81378dd0: 48 8b 9c 24 c0 00 00 00      	movq	0xc0(%rsp), %rbx
ffffffff81378dd8: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81378ddd: 4c 29 cb             	subq	%r9, %rbx
ffffffff81378de0: 48 83 7c 24 70 00    	cmpq	$0x0, 0x70(%rsp)
ffffffff81378de6: 0f 85 88 09 00 00    	jne	0xffffffff81379774 <do_jit+0xd64>
ffffffff81378dec: 83 bc 24 90 00 00 00 00      	cmpl	$0x0, 0x90(%rsp)
ffffffff81378df4: 41 89 1f             	movl	%ebx, (%r15)
ffffffff81378df7: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81378dff: 4c 89 6c 24 60       	movq	%r13, 0x60(%rsp)
ffffffff81378e04: 0f 8e ae 09 00 00    	jle	0xffffffff813797b8 <do_jit+0xda8>
ffffffff81378e0a: 41 8d 40 ff          	leal	-0x1(%r8), %eax
ffffffff81378e0e: b9 ef ff ff ff       	movl	$0xffffffef, %ecx       # imm = 0xFFFFFFEF
ffffffff81378e13: 49 8d 7d 60          	leaq	0x60(%r13), %rdi
ffffffff81378e17: 48 c7 44 24 50 00 00 00 00   	movq	$0x0, 0x50(%rsp)
ffffffff81378e20: 48 c7 84 24 a8 00 00 00 00 00 00 00  	movq	$0x0, 0xa8(%rsp)
ffffffff81378e2c: 48 89 5c 24 30       	movq	%rbx, 0x30(%rsp)
ffffffff81378e31: 83 c8 07             	orl	$0x7, %eax
ffffffff81378e34: 29 c1                	subl	%eax, %ecx
ffffffff81378e36: f7 d0                	notl	%eax
ffffffff81378e38: 44 29 e0             	subl	%r12d, %eax
ffffffff81378e3b: 41 bc 01 00 00 00    	movl	$0x1, %r12d
ffffffff81378e41: 89 8c 24 9c 00 00 00 	movl	%ecx, 0x9c(%rsp)
ffffffff81378e48: 89 84 24 8c 00 00 00 	movl	%eax, 0x8c(%rsp)
ffffffff81378e4f: 8b 47 04             	movl	0x4(%rdi), %eax
ffffffff81378e52: ba 0f 00 00 00       	movl	$0xf, %edx
ffffffff81378e57: 48 89 7c 24 10       	movq	%rdi, 0x10(%rsp)
ffffffff81378e5c: 41 8d 5c 24 ff       	leal	-0x1(%r12), %ebx
ffffffff81378e61: 4c 89 64 24 28       	movq	%r12, 0x28(%rsp)
ffffffff81378e66: 48 89 44 24 48       	movq	%rax, 0x48(%rsp)
ffffffff81378e6b: 0f b6 47 01          	movzbl	0x1(%rdi), %eax
ffffffff81378e6f: 48 8b bc 24 b8 00 00 00      	movq	0xb8(%rsp), %rdi
ffffffff81378e77: 89 c1                	movl	%eax, %ecx
ffffffff81378e79: c1 e8 04             	shrl	$0x4, %eax
ffffffff81378e7c: 80 e1 0f             	andb	$0xf, %cl
ffffffff81378e7f: 83 f8 0a             	cmpl	$0xa, %eax
ffffffff81378e82: 89 c6                	movl	%eax, %esi
ffffffff81378e84: 0f 44 f2             	cmovel	%edx, %esi
ffffffff81378e87: 80 f9 0a             	cmpb	$0xa, %cl
ffffffff81378e8a: 0f b6 c9             	movzbl	%cl, %ecx
ffffffff81378e8d: 41 89 cd             	movl	%ecx, %r13d
ffffffff81378e90: 44 0f 44 ea          	cmovel	%edx, %r13d
ffffffff81378e94: 80 7c 24 47 00       	cmpb	$0x0, 0x47(%rsp)
ffffffff81378e99: 89 da                	movl	%ebx, %edx
ffffffff81378e9b: 0f 45 f0             	cmovnel	%eax, %esi
ffffffff81378e9e: 44 0f 45 e9          	cmovnel	%ecx, %r13d
ffffffff81378ea2: 48 89 74 24 38       	movq	%rsi, 0x38(%rsp)
ffffffff81378ea7: 48 8b 74 24 60       	movq	0x60(%rsp), %rsi
ffffffff81378eac: e8 7f 0f 0e 00       	callq	0xffffffff81459e30 <bpf_insn_is_indirect_target>
ffffffff81378eb1: 4c 8b 8c 24 c0 00 00 00      	movq	0xc0(%rsp), %r9
ffffffff81378eb9: 84 c0                	testb	%al, %al
ffffffff81378ebb: 0f 85 07 03 00 00    	jne	0xffffffff813791c8 <do_jit+0x7b8>
ffffffff81378ec1: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81378ec6: 4c 63 db             	movslq	%ebx, %r11
ffffffff81378ec9: 48 8b 44 24 78       	movq	0x78(%rsp), %rax
ffffffff81378ece: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff81378ed6: 4d 89 ce             	movq	%r9, %r14
ffffffff81378ed9: 45 0f b6 d5          	movzbl	%r13b, %r10d
ffffffff81378edd: 4b 63 0c 9f          	movslq	(%r15,%r11,4), %rcx
ffffffff81378ee1: 4d 29 c6             	subq	%r8, %r14
ffffffff81378ee4: 44 8a 3f             	movb	(%rdi), %r15b
ffffffff81378ee7: 4e 8d 24 30          	leaq	(%rax,%r14), %r12
ffffffff81378eeb: 49 01 cc             	addq	%rcx, %r12
ffffffff81378eee: 41 0f b6 f7          	movzbl	%r15b, %esi
ffffffff81378ef2: 83 fe 5c             	cmpl	$0x5c, %esi
ffffffff81378ef5: 0f 8f e8 02 00 00    	jg	0xffffffff813791e3 <do_jit+0x7d3>
ffffffff81378efb: 83 fe 28             	cmpl	$0x28, %esi
ffffffff81378efe: 0f 8f a6 03 00 00    	jg	0xffffffff813792aa <do_jit+0x89a>
ffffffff81378f04: 83 fe 0b             	cmpl	$0xb, %esi
ffffffff81378f07: 0f 8f b3 04 00 00    	jg	0xffffffff813793c0 <do_jit+0x9b0>
ffffffff81378f0d: 8d 46 fb             	leal	-0x5(%rsi), %eax
ffffffff81378f10: 83 f8 02             	cmpl	$0x2, %eax
ffffffff81378f13: 72 7e                	jb	0xffffffff81378f93 <do_jit+0x583>
ffffffff81378f15: 83 fe 04             	cmpl	$0x4, %esi
ffffffff81378f18: 74 09                	je	0xffffffff81378f23 <do_jit+0x513>
ffffffff81378f1a: 83 fe 07             	cmpl	$0x7, %esi
ffffffff81378f1d: 0f 85 5b 05 00 00    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff81378f23: 41 f6 d7             	notb	%r15b
ffffffff81378f26: b0 48                	movb	$0x48, %al
ffffffff81378f28: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff81378f2c: 0f 85 c1 08 00 00    	jne	0xffffffff813797f3 <do_jit+0xde3>
ffffffff81378f32: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff81378f37: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff81378f3b: 0f 92 c1             	setb	%cl
ffffffff81378f3e: 08 c1                	orb	%al, %cl
ffffffff81378f40: 41 88 09             	movb	%cl, (%r9)
ffffffff81378f43: 49 ff c1             	incq	%r9
ffffffff81378f46: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81378f4e: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81378f53: 48 8b 74 24 48       	movq	0x48(%rsp), %rsi
ffffffff81378f58: 31 c0                	xorl	%eax, %eax
ffffffff81378f5a: 0f b6 17             	movzbl	(%rdi), %edx
ffffffff81378f5d: c1 ea 04             	shrl	$0x4, %edx
ffffffff81378f60: 83 fa 03             	cmpl	$0x3, %edx
ffffffff81378f63: 0f 8e 4f 01 00 00    	jle	0xffffffff813790b8 <do_jit+0x6a8>
ffffffff81378f69: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81378f6e: 83 fa 04             	cmpl	$0x4, %edx
ffffffff81378f71: 0f 84 e3 01 00 00    	je	0xffffffff8137915a <do_jit+0x74a>
ffffffff81378f77: 83 fa 05             	cmpl	$0x5, %edx
ffffffff81378f7a: 0f 84 e3 01 00 00    	je	0xffffffff81379163 <do_jit+0x753>
ffffffff81378f80: b9 00 00 00 00       	movl	$0x0, %ecx
ffffffff81378f85: 83 fa 0a             	cmpl	$0xa, %edx
ffffffff81378f88: 0f 85 45 01 00 00    	jne	0xffffffff813790d3 <do_jit+0x6c3>
ffffffff81378f8e: e9 e2 01 00 00       	jmp	0xffffffff81379175 <do_jit+0x765>
ffffffff81378f93: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81378f98: 41 80 ff 05          	cmpb	$0x5, %r15b
ffffffff81378f9c: 0f 85 b4 05 00 00    	jne	0xffffffff81379556 <do_jit+0xb46>
ffffffff81378fa2: 0f bf 57 02          	movswl	0x2(%rdi), %edx
ffffffff81378fa6: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81378fab: b8 fe ff ff ff       	movl	$0xfffffffe, %eax       # imm = 0xFFFFFFFE
ffffffff81378fb0: 83 fa ff             	cmpl	$-0x1, %edx
ffffffff81378fb3: 75 1c                	jne	0xffffffff81378fd1 <do_jit+0x5c1>
ffffffff81378fb5: 80 7d 18 00          	cmpb	$0x0, 0x18(%rbp)
ffffffff81378fb9: 0f 85 6a 08 00 00    	jne	0xffffffff81379829 <do_jit+0xe19>
ffffffff81378fbf: c1 e0 08             	shll	$0x8, %eax
ffffffff81378fc2: 0d eb 00 00 00       	orl	$0xeb, %eax
ffffffff81378fc7: 66 41 89 01          	movw	%ax, (%r9)
ffffffff81378fcb: 49 83 c1 02          	addq	$0x2, %r9
ffffffff81378fcf: eb 3f                	jmp	0xffffffff81379010 <do_jit+0x600>
ffffffff81378fd1: 44 01 e2             	addl	%r12d, %edx
ffffffff81378fd4: 48 63 c2             	movslq	%edx, %rax
ffffffff81378fd7: 49 63 d4             	movslq	%r12d, %rdx
ffffffff81378fda: 41 8b 04 87          	movl	(%r15,%rax,4), %eax
ffffffff81378fde: 41 8b 14 97          	movl	(%r15,%rdx,4), %edx
ffffffff81378fe2: 29 d0                	subl	%edx, %eax
ffffffff81378fe4: 0f 84 c7 08 00 00    	je	0xffffffff813798b1 <do_jit+0xea1>
ffffffff81378fea: 8d 90 80 00 00 00    	leal	0x80(%rax), %edx
ffffffff81378ff0: 81 fa fb 00 00 00    	cmpl	$0xfb, %edx
ffffffff81378ff6: 76 bd                	jbe	0xffffffff81378fb5 <do_jit+0x5a5>
ffffffff81378ff8: 49 8d 49 01          	leaq	0x1(%r9), %rcx
ffffffff81378ffc: 41 c6 01 e9          	movb	$-0x17, (%r9)
ffffffff81379000: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff81379008: 41 89 41 01          	movl	%eax, 0x1(%r9)
ffffffff8137900c: 49 83 c1 05          	addq	$0x5, %r9
ffffffff81379010: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81379018: 48 8b 4c 24 30       	movq	0x30(%rsp), %rcx
ffffffff8137901d: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff81379025: 4c 29 c0             	subq	%r8, %rax
ffffffff81379028: 3d 81 00 00 00       	cmpl	$0x81, %eax
ffffffff8137902d: 0f 8d 18 04 00 00    	jge	0xffffffff8137944b <do_jit+0xa3b>
ffffffff81379033: 48 83 7c 24 78 00    	cmpq	$0x0, 0x78(%rsp)
ffffffff81379039: 8d 1c 01             	leal	(%rcx,%rax), %ebx
ffffffff8137903c: 75 30                	jne	0xffffffff8137906e <do_jit+0x65e>
ffffffff8137903e: 4d 63 f4             	movslq	%r12d, %r14
ffffffff81379041: 41 ff c4             	incl	%r12d
ffffffff81379044: 48 83 c7 08          	addq	$0x8, %rdi
ffffffff81379048: 43 89 1c b7          	movl	%ebx, (%r15,%r14,4)
ffffffff8137904c: 89 d8                	movl	%ebx, %eax
ffffffff8137904e: 4c 89 84 24 c0 00 00 00      	movq	%r8, 0xc0(%rsp)
ffffffff81379056: 48 89 44 24 30       	movq	%rax, 0x30(%rsp)
ffffffff8137905b: 44 3b a4 24 90 00 00 00      	cmpl	0x90(%rsp), %r12d
ffffffff81379063: 0f 8e e6 fd ff ff    	jle	0xffffffff81378e4f <do_jit+0x43f>
ffffffff81379069: e9 53 07 00 00       	jmp	0xffffffff813797c1 <do_jit+0xdb1>
ffffffff8137906e: 3b 9c 24 a4 00 00 00 	cmpl	0xa4(%rsp), %ebx
ffffffff81379075: 0f 8f dc 03 00 00    	jg	0xffffffff81379457 <do_jit+0xa47>
ffffffff8137907b: 4d 63 f4             	movslq	%r12d, %r14
ffffffff8137907e: 43 3b 1c b7          	cmpl	(%r15,%r14,4), %ebx
ffffffff81379082: 0f 85 cf 03 00 00    	jne	0xffffffff81379457 <do_jit+0xa47>
ffffffff81379088: 48 63 d0             	movslq	%eax, %rdx
ffffffff8137908b: 48 81 fa c1 00 00 00 	cmpq	$0xc1, %rdx
ffffffff81379092: 0f 83 11 07 00 00    	jae	0xffffffff813797a9 <do_jit+0xd99>
ffffffff81379098: 49 89 fd             	movq	%rdi, %r13
ffffffff8137909b: 48 63 f9             	movslq	%ecx, %rdi
ffffffff8137909e: 48 03 7c 24 70       	addq	0x70(%rsp), %rdi
ffffffff813790a3: 4c 89 c6             	movq	%r8, %rsi
ffffffff813790a6: e8 35 f4 29 01       	callq	0xffffffff826184e0 <memcpy>
ffffffff813790ab: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff813790b3: 4c 89 ef             	movq	%r13, %rdi
ffffffff813790b6: eb 89                	jmp	0xffffffff81379041 <do_jit+0x631>
ffffffff813790b8: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff813790bd: 85 d2                	testl	%edx, %edx
ffffffff813790bf: 0f 84 a7 00 00 00    	je	0xffffffff8137916c <do_jit+0x75c>
ffffffff813790c5: b9 00 00 00 00       	movl	$0x0, %ecx
ffffffff813790ca: 83 fa 01             	cmpl	$0x1, %edx
ffffffff813790cd: 0f 84 ab 00 00 00    	je	0xffffffff8137917e <do_jit+0x76e>
ffffffff813790d3: 40 0f be d6          	movsbl	%sil, %edx
ffffffff813790d7: 39 f2                	cmpl	%esi, %edx
ffffffff813790d9: 75 26                	jne	0xffffffff81379101 <do_jit+0x6f1>
ffffffff813790db: 44 89 d1             	movl	%r10d, %ecx
ffffffff813790de: 02 04 8d 10 29 f2 82 	addb	-0x7d0dd6f0(,%rcx,4), %al
ffffffff813790e5: c1 e6 10             	shll	$0x10, %esi
ffffffff813790e8: 0f b6 c0             	movzbl	%al, %eax
ffffffff813790eb: c1 e0 08             	shll	$0x8, %eax
ffffffff813790ee: 8d 84 30 83 00 00 00 	leal	0x83(%rax,%rsi), %eax
ffffffff813790f5: 41 89 01             	movl	%eax, (%r9)
ffffffff813790f8: 49 83 c1 03          	addq	$0x3, %r9
ffffffff813790fc: e9 0f ff ff ff       	jmp	0xffffffff81379010 <do_jit+0x600>
ffffffff81379101: 45 85 d2             	testl	%r10d, %r10d
ffffffff81379104: 74 32                	je	0xffffffff81379138 <do_jit+0x728>
ffffffff81379106: 44 89 d1             	movl	%r10d, %ecx
ffffffff81379109: 02 04 8d 10 29 f2 82 	addb	-0x7d0dd6f0(,%rcx,4), %al
ffffffff81379110: 49 8d 49 02          	leaq	0x2(%r9), %rcx
ffffffff81379114: 0f b6 c0             	movzbl	%al, %eax
ffffffff81379117: c1 e0 08             	shll	$0x8, %eax
ffffffff8137911a: 0d 81 00 00 00       	orl	$0x81, %eax
ffffffff8137911f: 66 41 89 01          	movw	%ax, (%r9)
ffffffff81379123: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137912b: 41 89 71 02          	movl	%esi, 0x2(%r9)
ffffffff8137912f: 49 83 c1 06          	addq	$0x6, %r9
ffffffff81379133: e9 d8 fe ff ff       	jmp	0xffffffff81379010 <do_jit+0x600>
ffffffff81379138: 49 8d 41 01          	leaq	0x1(%r9), %rax
ffffffff8137913c: 41 88 09             	movb	%cl, (%r9)
ffffffff8137913f: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81379147: 41 89 71 01          	movl	%esi, 0x1(%r9)
ffffffff8137914b: e9 bc fe ff ff       	jmp	0xffffffff8137900c <do_jit+0x5fc>
ffffffff81379150: 48 8d 44 10 04       	leaq	0x4(%rax,%rdx), %rax
ffffffff81379155: e9 5a fb ff ff       	jmp	0xffffffff81378cb4 <do_jit+0x2a4>
ffffffff8137915a: b1 0d                	movb	$0xd, %cl
ffffffff8137915c: b0 c8                	movb	$-0x38, %al
ffffffff8137915e: e9 70 ff ff ff       	jmp	0xffffffff813790d3 <do_jit+0x6c3>
ffffffff81379163: b1 25                	movb	$0x25, %cl
ffffffff81379165: b0 e0                	movb	$-0x20, %al
ffffffff81379167: e9 67 ff ff ff       	jmp	0xffffffff813790d3 <do_jit+0x6c3>
ffffffff8137916c: b1 05                	movb	$0x5, %cl
ffffffff8137916e: b0 c0                	movb	$-0x40, %al
ffffffff81379170: e9 5e ff ff ff       	jmp	0xffffffff813790d3 <do_jit+0x6c3>
ffffffff81379175: b1 35                	movb	$0x35, %cl
ffffffff81379177: b0 f0                	movb	$-0x10, %al
ffffffff81379179: e9 55 ff ff ff       	jmp	0xffffffff813790d3 <do_jit+0x6c3>
ffffffff8137917e: b1 2d                	movb	$0x2d, %cl
ffffffff81379180: b0 e8                	movb	$-0x18, %al
ffffffff81379182: e9 4c ff ff ff       	jmp	0xffffffff813790d3 <do_jit+0x6c3>
ffffffff81379187: c6 00 b8             	movb	$-0x48, (%rax)
ffffffff8137918a: c7 40 01 00 00 00 00 	movl	$0x0, 0x1(%rax)
ffffffff81379191: 48 bf 90 90 90 90 90 90 90 90	movabsq	$-0x6f6f6f6f6f6f6f70, %rdi # imm = 0x9090909090909090
ffffffff8137919b: 48 89 78 05          	movq	%rdi, 0x5(%rax)
ffffffff8137919f: c7 40 0c 90 90 90 90 	movl	$0x90909090, 0xc(%rax)  # imm = 0x90909090
ffffffff813791a6: bf 0c f0 e1 05       	movl	$0x5e1f00c, %edi        # imm = 0x5E1F00C
ffffffff813791ab: f7 d7                	notl	%edi
ffffffff813791ad: 89 78 10             	movl	%edi, 0x10(%rax)
ffffffff813791b0: bf 14 00 00 00       	movl	$0x14, %edi
ffffffff813791b5: e9 48 fa ff ff       	jmp	0xffffffff81378c02 <do_jit+0x1f2>
ffffffff813791ba: bf 0c f0 e1 05       	movl	$0x5e1f00c, %edi        # imm = 0x5E1F00C
ffffffff813791bf: f7 d7                	notl	%edi
ffffffff813791c1: 89 38                	movl	%edi, (%rax)
ffffffff813791c3: e9 35 fa ff ff       	jmp	0xffffffff81378bfd <do_jit+0x1ed>
ffffffff813791c8: 8b 84 24 a0 00 00 00 	movl	0xa0(%rsp), %eax
ffffffff813791cf: 41 89 01             	movl	%eax, (%r9)
ffffffff813791d2: 49 83 c1 04          	addq	$0x4, %r9
ffffffff813791d6: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff813791de: e9 de fc ff ff       	jmp	0xffffffff81378ec1 <do_jit+0x4b1>
ffffffff813791e3: 4c 89 db             	movq	%r11, %rbx
ffffffff813791e6: 44 89 54 24 0c       	movl	%r10d, 0xc(%rsp)
ffffffff813791eb: 4c 89 4c 24 18       	movq	%r9, 0x18(%rsp)
ffffffff813791f0: 48 89 f0             	movq	%rsi, %rax
ffffffff813791f3: 81 fe ae 00 00 00    	cmpl	$0xae, %esi
ffffffff813791f9: 0f 8f fa 0d 00 00    	jg	0xffffffff81379ff9 <do_jit+0x15e9>
ffffffff813791ff: 83 f8 78             	cmpl	$0x78, %eax
ffffffff81379202: 0f 8e 3f 0e 00 00    	jle	0xffffffff8137a047 <do_jit+0x1637>
ffffffff81379208: 3d 93 00 00 00       	cmpl	$0x93, %eax
ffffffff8137920d: 0f 8f 7c 0e 00 00    	jg	0xffffffff8137a08f <do_jit+0x167f>
ffffffff81379213: 3d 83 00 00 00       	cmpl	$0x83, %eax
ffffffff81379218: 0f 8e c8 0e 00 00    	jle	0xffffffff8137a0e6 <do_jit+0x16d6>
ffffffff8137921e: 3d 88 00 00 00       	cmpl	$0x88, %eax
ffffffff81379223: 0f 8f 29 0f 00 00    	jg	0xffffffff8137a152 <do_jit+0x1742>
ffffffff81379229: 48 89 c1             	movq	%rax, %rcx
ffffffff8137922c: 81 f9 84 00 00 00    	cmpl	$0x84, %ecx
ffffffff81379232: 0f 85 2b 02 00 00    	jne	0xffffffff81379463 <do_jit+0xa53>
ffffffff81379238: 41 f6 d7             	notb	%r15b
ffffffff8137923b: b0 48                	movb	$0x48, %al
ffffffff8137923d: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff81379241: 0f 85 3a 0f 00 00    	jne	0xffffffff8137a181 <do_jit+0x1771>
ffffffff81379247: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137924b: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff81379250: 0f a3 d1             	btl	%edx, %ecx
ffffffff81379253: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff81379258: 0f 92 c1             	setb	%cl
ffffffff8137925b: 08 c1                	orb	%al, %cl
ffffffff8137925d: 88 0a                	movb	%cl, (%rdx)
ffffffff8137925f: 48 ff c2             	incq	%rdx
ffffffff81379262: 48 89 54 24 18       	movq	%rdx, 0x18(%rsp)
ffffffff81379267: 8b 44 24 0c          	movl	0xc(%rsp), %eax
ffffffff8137926b: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff81379272: c1 e0 08             	shll	$0x8, %eax
ffffffff81379275: 05 f7 d8 ff ff       	addl	$0xffffd8f7, %eax       # imm = 0xFFFFD8F7
ffffffff8137927a: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137927f: 66 89 01             	movw	%ax, (%rcx)
ffffffff81379282: 48 83 c1 02          	addq	$0x2, %rcx
ffffffff81379286: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137928e: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81379293: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137929b: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff813792a0: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff813792a5: e9 6e fd ff ff       	jmp	0xffffffff81379018 <do_jit+0x608>
ffffffff813792aa: 83 fe 3c             	cmpl	$0x3c, %esi
ffffffff813792ad: 0f 8e 09 02 00 00    	jle	0xffffffff813794bc <do_jit+0xaac>
ffffffff813792b3: 83 fe 4c             	cmpl	$0x4c, %esi
ffffffff813792b6: 0f 8e de 0e 00 00    	jle	0xffffffff8137a19a <do_jit+0x178a>
ffffffff813792bc: 83 fe 53             	cmpl	$0x53, %esi
ffffffff813792bf: 0f 8f 44 05 00 00    	jg	0xffffffff81379809 <do_jit+0xdf9>
ffffffff813792c5: 8d 46 b3             	leal	-0x4d(%rsi), %eax
ffffffff813792c8: 83 f8 02             	cmpl	$0x2, %eax
ffffffff813792cb: 0f 83 36 0f 00 00    	jae	0xffffffff8137a207 <do_jit+0x17f7>
ffffffff813792d1: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff813792d6: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff813792db: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff813792e0: 41 80 e7 07          	andb	$0x7, %r15b
ffffffff813792e4: c4 e2 69 f7 c0       	shlxl	%edx, %eax, %eax
ffffffff813792e9: 41 80 ff 05          	cmpb	$0x5, %r15b
ffffffff813792ed: 0f 85 2b 0f 00 00    	jne	0xffffffff8137a21e <do_jit+0x180e>
ffffffff813792f3: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff813792f8: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff813792fd: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff81379302: 0f 95 c0             	setne	%al
ffffffff81379305: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff81379309: 0f 92 c1             	setb	%cl
ffffffff8137930c: c0 e0 02             	shlb	$0x2, %al
ffffffff8137930f: 08 c8                	orb	%cl, %al
ffffffff81379311: 0c 48                	orb	$0x48, %al
ffffffff81379313: 41 88 01             	movb	%al, (%r9)
ffffffff81379316: 49 ff c1             	incq	%r9
ffffffff81379319: 44 89 d0             	movl	%r10d, %eax
ffffffff8137931c: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff81379323: 89 d1                	movl	%edx, %ecx
ffffffff81379325: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137932c: c1 e1 0b             	shll	$0xb, %ecx
ffffffff8137932f: c1 e0 08             	shll	$0x8, %eax
ffffffff81379332: 8d 84 08 85 c0 ff ff 	leal	-0x3f7b(%rax,%rcx), %eax
ffffffff81379339: 66 41 89 01          	movw	%ax, (%r9)
ffffffff8137933d: 49 83 c1 02          	addq	$0x2, %r9
ffffffff81379341: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81379349: bb f2 ff ff ff       	movl	$0xfffffff2, %ebx       # imm = 0xFFFFFFF2
ffffffff8137934e: 0f b6 07             	movzbl	(%rdi), %eax
ffffffff81379351: 83 c0 f0             	addl	$-0x10, %eax
ffffffff81379354: c1 e8 04             	shrl	$0x4, %eax
ffffffff81379357: 83 f8 05             	cmpl	$0x5, %eax
ffffffff8137935a: 0f 8f 73 09 00 00    	jg	0xffffffff81379cd3 <do_jit+0x12c3>
ffffffff81379360: 83 f8 01             	cmpl	$0x1, %eax
ffffffff81379363: 0f 8f 44 0a 00 00    	jg	0xffffffff81379dad <do_jit+0x139d>
ffffffff81379369: 85 c0                	testl	%eax, %eax
ffffffff8137936b: 0f 85 58 0a 00 00    	jne	0xffffffff81379dc9 <do_jit+0x13b9>
ffffffff81379371: b0 74                	movb	$0x74, %al
ffffffff81379373: 0f bf 4f 02          	movswl	0x2(%rdi), %ecx
ffffffff81379377: 49 63 d4             	movslq	%r12d, %rdx
ffffffff8137937a: 41 8b 14 97          	movl	(%r15,%rdx,4), %edx
ffffffff8137937e: 44 01 e1             	addl	%r12d, %ecx
ffffffff81379381: 48 63 c9             	movslq	%ecx, %rcx
ffffffff81379384: 41 8b 0c 8f          	movl	(%r15,%rcx,4), %ecx
ffffffff81379388: 29 d1                	subl	%edx, %ecx
ffffffff8137938a: 8d b1 80 00 00 00    	leal	0x80(%rcx), %esi
ffffffff81379390: 81 fe fb 00 00 00    	cmpl	$0xfb, %esi
ffffffff81379396: 0f 86 ef 05 00 00    	jbe	0xffffffff8137998b <do_jit+0xf7b>
ffffffff8137939c: 04 10                	addb	$0x10, %al
ffffffff8137939e: 49 8d 51 02          	leaq	0x2(%r9), %rdx
ffffffff813793a2: 0f b6 c0             	movzbl	%al, %eax
ffffffff813793a5: c1 e0 08             	shll	$0x8, %eax
ffffffff813793a8: 83 c8 0f             	orl	$0xf, %eax
ffffffff813793ab: 66 41 89 01          	movw	%ax, (%r9)
ffffffff813793af: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff813793b7: 41 89 49 02          	movl	%ecx, 0x2(%r9)
ffffffff813793bb: e9 6f fd ff ff       	jmp	0xffffffff8137912f <do_jit+0x71f>
ffffffff813793c0: 4c 89 db             	movq	%r11, %rbx
ffffffff813793c3: 45 89 d3             	movl	%r10d, %r11d
ffffffff813793c6: 4c 89 ca             	movq	%r9, %rdx
ffffffff813793c9: 48 89 f0             	movq	%rsi, %rax
ffffffff813793cc: 83 fe 20             	cmpl	$0x20, %esi
ffffffff813793cf: 0f 8f 8c 0e 00 00    	jg	0xffffffff8137a261 <do_jit+0x1851>
ffffffff813793d5: 83 f8 16             	cmpl	$0x16, %eax
ffffffff813793d8: 0f 8e af 0e 00 00    	jle	0xffffffff8137a28d <do_jit+0x187d>
ffffffff813793de: 83 f8 1c             	cmpl	$0x1c, %eax
ffffffff813793e1: 0f 8f d2 0e 00 00    	jg	0xffffffff8137a2b9 <do_jit+0x18a9>
ffffffff813793e7: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff813793ec: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff813793f4: 48 89 c1             	movq	%rax, %rcx
ffffffff813793f7: 49 89 d1             	movq	%rdx, %r9
ffffffff813793fa: 45 89 da             	movl	%r11d, %r10d
ffffffff813793fd: 83 f9 17             	cmpl	$0x17, %ecx
ffffffff81379400: 0f 84 1d fb ff ff    	je	0xffffffff81378f23 <do_jit+0x513>
ffffffff81379406: 83 f9 18             	cmpl	$0x18, %ecx
ffffffff81379409: 0f 85 da 0e 00 00    	jne	0xffffffff8137a2e9 <do_jit+0x18d9>
ffffffff8137940f: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff81379414: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137941c: 44 89 de             	movl	%r11d, %esi
ffffffff8137941f: 8b 48 04             	movl	0x4(%rax), %ecx
ffffffff81379422: 8b 50 0c             	movl	0xc(%rax), %edx
ffffffff81379425: 48 8d 58 08          	leaq	0x8(%rax), %rbx
ffffffff81379429: e8 62 a3 26 00       	callq	0xffffffff815e3790 <emit_mov_imm64>
ffffffff8137942e: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379433: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81379438: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff81379440: 48 89 df             	movq	%rbx, %rdi
ffffffff81379443: 41 ff c4             	incl	%r12d
ffffffff81379446: e9 cd fb ff ff       	jmp	0xffffffff81379018 <do_jit+0x608>
ffffffff8137944b: 48 c7 c7 60 94 ef 82 	movq	$-0x7d106ba0, %rdi      # imm = 0x82EF9460
ffffffff81379452: e9 a4 2c 00 00       	jmp	0xffffffff8137c0fb <do_jit+0x36eb>
ffffffff81379457: 48 c7 c7 2b c6 d6 82 	movq	$-0x7d2939d5, %rdi      # imm = 0x82D6C62B
ffffffff8137945e: e9 98 2c 00 00       	jmp	0xffffffff8137c0fb <do_jit+0x36eb>
ffffffff81379463: 81 f9 85 00 00 00    	cmpl	$0x85, %ecx
ffffffff81379469: 0f 84 91 0e 00 00    	je	0xffffffff8137a300 <do_jit+0x18f0>
ffffffff8137946f: 48 89 c6             	movq	%rax, %rsi
ffffffff81379472: 81 fe 87 00 00 00    	cmpl	$0x87, %esi
ffffffff81379478: 0f 84 ba fd ff ff    	je	0xffffffff81379238 <do_jit+0x828>
ffffffff8137947e: 48 c7 c7 09 d5 e9 82 	movq	$-0x7d162af7, %rdi      # imm = 0x82E9D509
ffffffff81379485: e8 b6 4f ee ff       	callq	0xffffffff8125e440 <_printk>
ffffffff8137948a: bb ea ff ff ff       	movl	$0xffffffea, %ebx       # imm = 0xFFFFFFEA
ffffffff8137948f: 65 48 8b 05 81 ab 44 03      	movq	%gs:0x344ab81(%rip), %rax
ffffffff81379497: 48 3b 84 24 90 01 00 00      	cmpq	0x190(%rsp), %rax
ffffffff8137949f: 74 05                	je	0xffffffff813794a6 <do_jit+0xa96>
ffffffff813794a1: e8 5a 60 2a 01       	callq	0xffffffff8261f500 <__stack_chk_fail>
ffffffff813794a6: 89 d8                	movl	%ebx, %eax
ffffffff813794a8: 48 8d 65 d8          	leaq	-0x28(%rbp), %rsp
ffffffff813794ac: 5b                   	popq	%rbx
ffffffff813794ad: 41 5c                	popq	%r12
ffffffff813794af: 41 5d                	popq	%r13
ffffffff813794b1: 41 5e                	popq	%r14
ffffffff813794b3: 41 5f                	popq	%r15
ffffffff813794b5: 5d                   	popq	%rbp
ffffffff813794b6: 2e e9 74 85 2b 01    	jmp	0xffffffff82631a30 <__x86_return_thunk>
ffffffff813794bc: 83 fe 33             	cmpl	$0x33, %esi
ffffffff813794bf: 0f 8f 65 04 00 00    	jg	0xffffffff8137992a <do_jit+0xf1a>
ffffffff813794c5: 83 fe 2c             	cmpl	$0x2c, %esi
ffffffff813794c8: 0f 8e 03 05 00 00    	jle	0xffffffff813799d1 <do_jit+0xfc1>
ffffffff813794ce: 83 fe 31             	cmpl	$0x31, %esi
ffffffff813794d1: 0f 84 16 05 00 00    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff813794d7: 8d 46 d3             	leal	-0x2d(%rsi), %eax
ffffffff813794da: 4c 89 db             	movq	%r11, %rbx
ffffffff813794dd: 83 f8 02             	cmpl	$0x2, %eax
ffffffff813794e0: 0f 83 0d 0f 00 00    	jae	0xffffffff8137a3f3 <do_jit+0x19e3>
ffffffff813794e6: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff813794eb: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff813794f0: 41 80 e7 07          	andb	$0x7, %r15b
ffffffff813794f4: c4 e2 69 f7 c0       	shlxl	%edx, %eax, %eax
ffffffff813794f9: 41 80 ff 05          	cmpb	$0x5, %r15b
ffffffff813794fd: 0f 85 34 0f 00 00    	jne	0xffffffff8137a437 <do_jit+0x1a27>
ffffffff81379503: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff81379508: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137950d: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff81379512: 0f 95 c0             	setne	%al
ffffffff81379515: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff81379519: 0f 92 c1             	setb	%cl
ffffffff8137951c: c0 e0 02             	shlb	$0x2, %al
ffffffff8137951f: 08 c8                	orb	%cl, %al
ffffffff81379521: 0c 48                	orb	$0x48, %al
ffffffff81379523: 41 88 01             	movb	%al, (%r9)
ffffffff81379526: 49 ff c1             	incq	%r9
ffffffff81379529: 49 89 db             	movq	%rbx, %r11
ffffffff8137952c: 44 89 d0             	movl	%r10d, %eax
ffffffff8137952f: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff81379536: 89 d1                	movl	%edx, %ecx
ffffffff81379538: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137953f: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379544: c1 e1 0b             	shll	$0xb, %ecx
ffffffff81379547: c1 e0 08             	shll	$0x8, %eax
ffffffff8137954a: 8d 84 08 39 c0 ff ff 	leal	-0x3fc7(%rax,%rcx), %eax
ffffffff81379551: e9 e3 fd ff ff       	jmp	0xffffffff81379339 <do_jit+0x929>
ffffffff81379556: 8b 57 04             	movl	0x4(%rdi), %edx
ffffffff81379559: 83 fa ff             	cmpl	$-0x1, %edx
ffffffff8137955c: 0f 84 76 0a 00 00    	je	0xffffffff81379fd8 <do_jit+0x15c8>
ffffffff81379562: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379567: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137956c: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81379571: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff81379579: e9 53 fa ff ff       	jmp	0xffffffff81378fd1 <do_jit+0x5c1>
ffffffff8137957e: 48 8b 84 24 90 00 00 00      	movq	0x90(%rsp), %rax
ffffffff81379586: be 01 00 00 00       	movl	$0x1, %esi
ffffffff8137958b: 8d 48 01             	leal	0x1(%rax), %ecx
ffffffff8137958e: b8 02 00 00 00       	movl	$0x2, %eax
ffffffff81379593: 83 f9 03             	cmpl	$0x3, %ecx
ffffffff81379596: 0f 4d c1             	cmovgel	%ecx, %eax
ffffffff81379599: 31 c9                	xorl	%ecx, %ecx
ffffffff8137959b: 31 d2                	xorl	%edx, %edx
ffffffff8137959d: 31 ff                	xorl	%edi, %edi
ffffffff8137959f: 45 31 c0             	xorl	%r8d, %r8d
ffffffff813795a2: 45 31 c9             	xorl	%r9d, %r9d
ffffffff813795a5: 48 ff c8             	decq	%rax
ffffffff813795a8: 44 8a 5c cb 61       	movb	0x61(%rbx,%rcx,8), %r11b
ffffffff813795ad: 45 0f b6 c9          	movzbl	%r9b, %r9d
ffffffff813795b1: 45 0f b6 c0          	movzbl	%r8b, %r8d
ffffffff813795b5: 40 0f b6 ff          	movzbl	%dil, %edi
ffffffff813795b9: 0f b6 d2             	movzbl	%dl, %edx
ffffffff813795bc: 45 89 dc             	movl	%r11d, %r12d
ffffffff813795bf: 45 89 da             	movl	%r11d, %r10d
ffffffff813795c2: 41 80 e4 f0          	andb	$-0x10, %r12b
ffffffff813795c6: 41 80 e2 0f          	andb	$0xf, %r10b
ffffffff813795ca: 41 80 fc 60          	cmpb	$0x60, %r12b
ffffffff813795ce: 44 0f 44 ce          	cmovel	%esi, %r9d
ffffffff813795d2: 41 80 fa 06          	cmpb	$0x6, %r10b
ffffffff813795d6: 44 0f 44 ce          	cmovel	%esi, %r9d
ffffffff813795da: 41 80 fa 07          	cmpb	$0x7, %r10b
ffffffff813795de: 44 0f 44 c6          	cmovel	%esi, %r8d
ffffffff813795e2: 41 80 fc 70          	cmpb	$0x70, %r12b
ffffffff813795e6: 44 0f 44 c6          	cmovel	%esi, %r8d
ffffffff813795ea: 41 80 fb 90          	cmpb	$-0x70, %r11b
ffffffff813795ee: 0f 4c fe             	cmovll	%esi, %edi
ffffffff813795f1: 41 80 fa 08          	cmpb	$0x8, %r10b
ffffffff813795f5: 0f 44 fe             	cmovel	%esi, %edi
ffffffff813795f8: 41 80 fc 90          	cmpb	$-0x70, %r12b
ffffffff813795fc: 0f 44 d6             	cmovel	%esi, %edx
ffffffff813795ff: 41 80 fa 09          	cmpb	$0x9, %r10b
ffffffff81379603: 0f 44 d6             	cmovel	%esi, %edx
ffffffff81379606: 48 ff c1             	incq	%rcx
ffffffff81379609: 39 c8                	cmpl	%ecx, %eax
ffffffff8137960b: 75 9b                	jne	0xffffffff813795a8 <do_jit+0xb98>
ffffffff8137960d: 44 88 8c 24 cc 00 00 00      	movb	%r9b, 0xcc(%rsp)
ffffffff81379615: 44 8a 4c 24 46       	movb	0x46(%rsp), %r9b
ffffffff8137961a: 44 88 84 24 cd 00 00 00      	movb	%r8b, 0xcd(%rsp)
ffffffff81379622: 40 88 bc 24 ce 00 00 00      	movb	%dil, 0xce(%rsp)
ffffffff8137962a: 88 94 24 cf 00 00 00 	movb	%dl, 0xcf(%rsp)
ffffffff81379631: e9 d8 f4 ff ff       	jmp	0xffffffff81378b0e <do_jit+0xfe>
ffffffff81379636: 48 8d 44 38 05       	leaq	0x5(%rax,%rdi), %rax
ffffffff8137963b: e9 fb f5 ff ff       	jmp	0xffffffff81378c3b <do_jit+0x22b>
ffffffff81379640: 85 c9                	testl	%ecx, %ecx
ffffffff81379642: 0f 84 2f 06 00 00    	je	0xffffffff81379c77 <do_jit+0x1267>
ffffffff81379648: b9 02 00 00 00       	movl	$0x2, %ecx
ffffffff8137964d: ba 01 00 00 00       	movl	$0x1, %edx
ffffffff81379652: c6 00 50             	movb	$0x50, (%rax)
ffffffff81379655: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff8137965a: c6 04 10 50          	movb	$0x50, (%rax,%rdx)
ffffffff8137965e: 48 01 c8             	addq	%rcx, %rax
ffffffff81379661: e9 57 f6 ff ff       	jmp	0xffffffff81378cbd <do_jit+0x2ad>
ffffffff81379666: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff8137966e: 48 83 bc 24 80 00 00 00 00   	cmpq	$0x0, 0x80(%rsp)
ffffffff81379677: 74 11                	je	0xffffffff8137968a <do_jit+0xc7a>
ffffffff81379679: 66 c7 00 41 54       	movw	$0x5441, (%rax)         # imm = 0x5441
ffffffff8137967e: 48 83 c0 02          	addq	$0x2, %rax
ffffffff81379682: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137968a: 80 bc 24 cc 00 00 00 01      	cmpb	$0x1, 0xcc(%rsp)
ffffffff81379692: 75 06                	jne	0xffffffff8137969a <do_jit+0xc8a>
ffffffff81379694: c6 00 53             	movb	$0x53, (%rax)
ffffffff81379697: 48 ff c0             	incq	%rax
ffffffff8137969a: 80 bc 24 cd 00 00 00 01      	cmpb	$0x1, 0xcd(%rsp)
ffffffff813796a2: 75 09                	jne	0xffffffff813796ad <do_jit+0xc9d>
ffffffff813796a4: 66 c7 00 41 55       	movw	$0x5541, (%rax)         # imm = 0x5541
ffffffff813796a9: 48 83 c0 02          	addq	$0x2, %rax
ffffffff813796ad: 80 bc 24 ce 00 00 00 01      	cmpb	$0x1, 0xce(%rsp)
ffffffff813796b5: 75 09                	jne	0xffffffff813796c0 <do_jit+0xcb0>
ffffffff813796b7: 66 c7 00 41 56       	movw	$0x5641, (%rax)         # imm = 0x5641
ffffffff813796bc: 48 83 c0 02          	addq	$0x2, %rax
ffffffff813796c0: 80 bc 24 cf 00 00 00 01      	cmpb	$0x1, 0xcf(%rsp)
ffffffff813796c8: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff813796cd: 4c 8d 8c 24 d0 00 00 00      	leaq	0xd0(%rsp), %r9
ffffffff813796d5: 0f 84 2f f6 ff ff    	je	0xffffffff81378d0a <do_jit+0x2fa>
ffffffff813796db: e9 33 f6 ff ff       	jmp	0xffffffff81378d13 <do_jit+0x303>
ffffffff813796e0: 41 83 cc 20          	orl	$0x20, %r12d
ffffffff813796e4: e9 8e f6 ff ff       	jmp	0xffffffff81378d77 <do_jit+0x367>
ffffffff813796e9: 66 89 b9 00 04 00 00 	movw	%di, 0x400(%rcx)
ffffffff813796f0: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff813796f8: e9 9a f6 ff ff       	jmp	0xffffffff81378d97 <do_jit+0x387>
ffffffff813796fd: 0f b7 cf             	movzwl	%di, %ecx
ffffffff81379700: 66 83 ff 7f          	cmpw	$0x7f, %di
ffffffff81379704: 0f 87 9c 02 00 00    	ja	0xffffffff813799a6 <do_jit+0xf96>
ffffffff8137970a: c1 e1 18             	shll	$0x18, %ecx
ffffffff8137970d: 81 c9 48 83 ec 00    	orl	$0xec8348, %ecx         # imm = 0xEC8348
ffffffff81379713: 89 08                	movl	%ecx, (%rax)
ffffffff81379715: b9 04 00 00 00       	movl	$0x4, %ecx
ffffffff8137971a: e9 95 02 00 00       	jmp	0xffffffff813799b4 <do_jit+0xfa4>
ffffffff8137971f: 48 8b 8c 24 80 00 00 00      	movq	0x80(%rsp), %rcx
ffffffff81379727: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137972f: be 10 00 00 00       	movl	$0x10, %esi
ffffffff81379734: 48 89 ca             	movq	%rcx, %rdx
ffffffff81379737: 48 c1 ea 20          	shrq	$0x20, %rdx
ffffffff8137973b: e8 50 a0 26 00       	callq	0xffffffff815e3790 <emit_mov_imm64>
ffffffff81379740: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff81379745: 4c 8d 8c 24 d0 00 00 00      	leaq	0xd0(%rsp), %r9
ffffffff8137974d: e9 66 f6 ff ff       	jmp	0xffffffff81378db8 <do_jit+0x3a8>
ffffffff81379752: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137975a: 48 89 de             	movq	%rbx, %rsi
ffffffff8137975d: e8 0e aa 26 00       	callq	0xffffffff815e4170 <emit_priv_frame_ptr>
ffffffff81379762: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff81379767: 4c 8d 8c 24 d0 00 00 00      	leaq	0xd0(%rsp), %r9
ffffffff8137976f: e9 5c f6 ff ff       	jmp	0xffffffff81378dd0 <do_jit+0x3c0>
ffffffff81379774: 48 63 d3             	movslq	%ebx, %rdx
ffffffff81379777: 48 81 fa c1 00 00 00 	cmpq	$0xc1, %rdx
ffffffff8137977e: 73 29                	jae	0xffffffff813797a9 <do_jit+0xd99>
ffffffff81379780: 48 8b 7c 24 70       	movq	0x70(%rsp), %rdi
ffffffff81379785: 48 8d b4 24 d0 00 00 00      	leaq	0xd0(%rsp), %rsi
ffffffff8137978d: e8 4e ed 29 01       	callq	0xffffffff826184e0 <memcpy>
ffffffff81379792: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81379797: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff8137979c: 4c 8d 8c 24 d0 00 00 00      	leaq	0xd0(%rsp), %r9
ffffffff813797a4: e9 43 f6 ff ff       	jmp	0xffffffff81378dec <do_jit+0x3dc>
ffffffff813797a9: be c0 00 00 00       	movl	$0xc0, %esi
ffffffff813797ae: bf 0e 00 00 00       	movl	$0xe, %edi
ffffffff813797b3: e8 28 76 ee ff       	callq	0xffffffff81260de0 <__fortify_panic>
ffffffff813797b8: 48 c7 44 24 50 00 00 00 00   	movq	$0x0, 0x50(%rsp)
ffffffff813797c1: 48 83 7c 24 78 00    	cmpq	$0x0, 0x78(%rsp)
ffffffff813797c7: 0f 84 c2 fc ff ff    	je	0xffffffff8137948f <do_jit+0xa7f>
ffffffff813797cd: 48 8b 44 24 60       	movq	0x60(%rsp), %rax
ffffffff813797d2: 48 8b 4c 24 50       	movq	0x50(%rsp), %rcx
ffffffff813797d7: 48 8b 40 50          	movq	0x50(%rax), %rax
ffffffff813797db: 3b 88 60 04 00 00    	cmpl	0x460(%rax), %ecx
ffffffff813797e1: 0f 84 a8 fc ff ff    	je	0xffffffff8137948f <do_jit+0xa7f>
ffffffff813797e7: 48 c7 c7 6f 44 e2 82 	movq	$-0x7d1dbb91, %rdi      # imm = 0x82E2446F
ffffffff813797ee: e9 08 29 00 00       	jmp	0xffffffff8137c0fb <do_jit+0x36eb>
ffffffff813797f3: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff813797f8: b0 40                	movb	$0x40, %al
ffffffff813797fa: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff813797fe: 0f 82 2e f7 ff ff    	jb	0xffffffff81378f32 <do_jit+0x522>
ffffffff81379804: e9 3d f7 ff ff       	jmp	0xffffffff81378f46 <do_jit+0x536>
ffffffff81379809: 83 fe 56             	cmpl	$0x56, %esi
ffffffff8137980c: 0f 8e 49 0c 00 00    	jle	0xffffffff8137a45b <do_jit+0x1a4b>
ffffffff81379812: 83 fe 57             	cmpl	$0x57, %esi
ffffffff81379815: 0f 84 08 f7 ff ff    	je	0xffffffff81378f23 <do_jit+0x513>
ffffffff8137981b: 83 fe 5c             	cmpl	$0x5c, %esi
ffffffff8137981e: 0f 85 5a fc ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff81379824: e9 52 12 00 00       	jmp	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff81379829: 49 63 d4             	movslq	%r12d, %rdx
ffffffff8137982c: 4d 89 ca             	movq	%r9, %r10
ffffffff8137982f: 41 8b 14 97          	movl	(%r15,%rdx,4), %edx
ffffffff81379833: 29 ca                	subl	%ecx, %edx
ffffffff81379835: 48 8d 8c 24 d0 00 00 00      	leaq	0xd0(%rsp), %rcx
ffffffff8137983d: 44 29 c9             	subl	%r9d, %ecx
ffffffff81379840: 01 d1                	addl	%edx, %ecx
ffffffff81379842: 89 ce                	movl	%ecx, %esi
ffffffff81379844: 83 ee 02             	subl	$0x2, %esi
ffffffff81379847: 74 05                	je	0xffffffff8137984e <do_jit+0xe3e>
ffffffff81379849: 83 f9 05             	cmpl	$0x5, %ecx
ffffffff8137984c: 75 5a                	jne	0xffffffff813798a8 <do_jit+0xe98>
ffffffff8137984e: 85 f6                	testl	%esi, %esi
ffffffff81379850: 0f 84 22 0c 00 00    	je	0xffffffff8137a478 <do_jit+0x1a68>
ffffffff81379856: 83 fe 0b             	cmpl	$0xb, %esi
ffffffff81379859: bf 0b 00 00 00       	movl	$0xb, %edi
ffffffff8137985e: 4c 89 d1             	movq	%r10, %rcx
ffffffff81379861: 0f 42 fe             	cmovbl	%esi, %edi
ffffffff81379864: 31 d2                	xorl	%edx, %edx
ffffffff81379866: 4c 8b 04 fd 80 f0 f0 82      	movq	-0x7d0f0f80(,%rdi,8), %r8
ffffffff8137986e: 45 8a 0c 10          	movb	(%r8,%rdx), %r9b
ffffffff81379872: 44 88 0c 11          	movb	%r9b, (%rcx,%rdx)
ffffffff81379876: 48 ff c2             	incq	%rdx
ffffffff81379879: 48 39 d7             	cmpq	%rdx, %rdi
ffffffff8137987c: 75 f0                	jne	0xffffffff8137986e <do_jit+0xe5e>
ffffffff8137987e: 4c 8d 14 11          	leaq	(%rcx,%rdx), %r10
ffffffff81379882: 29 fe                	subl	%edi, %esi
ffffffff81379884: 7f d0                	jg	0xffffffff81379856 <do_jit+0xe46>
ffffffff81379886: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137988b: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379890: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81379895: 48 01 d1             	addq	%rdx, %rcx
ffffffff81379898: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff813798a0: 49 89 c9             	movq	%rcx, %r9
ffffffff813798a3: e9 17 f7 ff ff       	jmp	0xffffffff81378fbf <do_jit+0x5af>
ffffffff813798a8: 48 c7 c7 52 cd df 82 	movq	$-0x7d2032ae, %rdi      # imm = 0x82DFCD52
ffffffff813798af: eb 6f                	jmp	0xffffffff81379920 <do_jit+0xf10>
ffffffff813798b1: 80 7d 18 00          	cmpb	$0x0, 0x18(%rbp)
ffffffff813798b5: 0f 84 d3 f9 ff ff    	je	0xffffffff8137928e <do_jit+0x87e>
ffffffff813798bb: 48 8d b4 24 d0 00 00 00      	leaq	0xd0(%rsp), %rsi
ffffffff813798c3: 29 ca                	subl	%ecx, %edx
ffffffff813798c5: 44 29 ce             	subl	%r9d, %esi
ffffffff813798c8: 01 d6                	addl	%edx, %esi
ffffffff813798ca: 74 40                	je	0xffffffff8137990c <do_jit+0xefc>
ffffffff813798cc: 83 fe 05             	cmpl	$0x5, %esi
ffffffff813798cf: 74 05                	je	0xffffffff813798d6 <do_jit+0xec6>
ffffffff813798d1: 83 fe 02             	cmpl	$0x2, %esi
ffffffff813798d4: 75 43                	jne	0xffffffff81379919 <do_jit+0xf09>
ffffffff813798d6: 83 fe 0b             	cmpl	$0xb, %esi
ffffffff813798d9: ba 0b 00 00 00       	movl	$0xb, %edx
ffffffff813798de: 4c 89 c8             	movq	%r9, %rax
ffffffff813798e1: 0f 42 d6             	cmovbl	%esi, %edx
ffffffff813798e4: 31 c9                	xorl	%ecx, %ecx
ffffffff813798e6: 48 8b 3c d5 80 f0 f0 82      	movq	-0x7d0f0f80(,%rdx,8), %rdi
ffffffff813798ee: 44 8a 04 0f          	movb	(%rdi,%rcx), %r8b
ffffffff813798f2: 44 88 04 08          	movb	%r8b, (%rax,%rcx)
ffffffff813798f6: 48 ff c1             	incq	%rcx
ffffffff813798f9: 48 39 ca             	cmpq	%rcx, %rdx
ffffffff813798fc: 75 f0                	jne	0xffffffff813798ee <do_jit+0xede>
ffffffff813798fe: 4c 8d 0c 08          	leaq	(%rax,%rcx), %r9
ffffffff81379902: 29 d6                	subl	%edx, %esi
ffffffff81379904: 7f d0                	jg	0xffffffff813798d6 <do_jit+0xec6>
ffffffff81379906: 48 01 c8             	addq	%rcx, %rax
ffffffff81379909: 49 89 c1             	movq	%rax, %r9
ffffffff8137990c: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81379914: e9 75 f9 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff81379919: 48 c7 c7 a6 99 e5 82 	movq	$-0x7d1a665a, %rdi      # imm = 0x82E599A6
ffffffff81379920: e8 1b 4b ee ff       	callq	0xffffffff8125e440 <_printk>
ffffffff81379925: e9 d6 27 00 00       	jmp	0xffffffff8137c100 <do_jit+0x36f0>
ffffffff8137992a: 83 fe 36             	cmpl	$0x36, %esi
ffffffff8137992d: 0f 8f b1 00 00 00    	jg	0xffffffff813799e4 <do_jit+0xfd4>
ffffffff81379933: 8d 46 cb             	leal	-0x35(%rsi), %eax
ffffffff81379936: 4c 89 db             	movq	%r11, %rbx
ffffffff81379939: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137993c: 0f 83 c8 03 00 00    	jae	0xffffffff81379d0a <do_jit+0x12fa>
ffffffff81379942: 41 80 e7 07          	andb	$0x7, %r15b
ffffffff81379946: 83 7c 24 48 00       	cmpl	$0x0, 0x48(%rsp)
ffffffff8137994b: 0f 85 9c 04 00 00    	jne	0xffffffff81379ded <do_jit+0x13dd>
ffffffff81379951: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff81379956: c4 e2 11 f7 c0       	shlxl	%r13d, %eax, %eax
ffffffff8137995b: 41 80 ff 05          	cmpb	$0x5, %r15b
ffffffff8137995f: 0f 85 02 06 00 00    	jne	0xffffffff81379f67 <do_jit+0x1557>
ffffffff81379965: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137996a: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137996f: 0f 95 c0             	setne	%al
ffffffff81379972: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff81379976: 0f 92 c1             	setb	%cl
ffffffff81379979: c0 e0 02             	shlb	$0x2, %al
ffffffff8137997c: 08 c8                	orb	%cl, %al
ffffffff8137997e: 0c 48                	orb	$0x48, %al
ffffffff81379980: 41 88 01             	movb	%al, (%r9)
ffffffff81379983: 49 ff c1             	incq	%r9
ffffffff81379986: e9 e7 05 00 00       	jmp	0xffffffff81379f72 <do_jit+0x1562>
ffffffff8137998b: 80 7d 18 00          	cmpb	$0x0, 0x18(%rbp)
ffffffff8137998f: 0f 85 02 0b 00 00    	jne	0xffffffff8137a497 <do_jit+0x1a87>
ffffffff81379995: 0f b6 c0             	movzbl	%al, %eax
ffffffff81379998: c1 e1 08             	shll	$0x8, %ecx
ffffffff8137999b: 09 c1                	orl	%eax, %ecx
ffffffff8137999d: 66 41 89 09          	movw	%cx, (%r9)
ffffffff813799a1: e9 25 f6 ff ff       	jmp	0xffffffff81378fcb <do_jit+0x5bb>
ffffffff813799a6: c7 00 48 81 ec 00    	movl	$0xec8148, (%rax)       # imm = 0xEC8148
ffffffff813799ac: 89 48 03             	movl	%ecx, 0x3(%rax)
ffffffff813799af: b9 07 00 00 00       	movl	$0x7, %ecx
ffffffff813799b4: 4c 8b 44 24 58       	movq	0x58(%rsp), %r8
ffffffff813799b9: 48 01 c8             	addq	%rcx, %rax
ffffffff813799bc: 4c 8d 8c 24 d0 00 00 00      	leaq	0xd0(%rsp), %r9
ffffffff813799c4: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff813799cc: e9 d3 f3 ff ff       	jmp	0xffffffff81378da4 <do_jit+0x394>
ffffffff813799d1: 83 fe 29             	cmpl	$0x29, %esi
ffffffff813799d4: 74 17                	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff813799d6: 83 fe 2c             	cmpl	$0x2c, %esi
ffffffff813799d9: 0f 85 9f fa ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff813799df: e9 18 0a 00 00       	jmp	0xffffffff8137a3fc <do_jit+0x19ec>
ffffffff813799e4: 83 fe 39             	cmpl	$0x39, %esi
ffffffff813799e7: 0f 85 37 0b 00 00    	jne	0xffffffff8137a524 <do_jit+0x1b14>
ffffffff813799ed: 44 0f bf 47 02       	movswl	0x2(%rdi), %r8d
ffffffff813799f2: 83 7c 24 38 0b       	cmpl	$0xb, 0x38(%rsp)
ffffffff813799f7: 0f 84 3e 0b 00 00    	je	0xffffffff8137a53b <do_jit+0x1b2b>
ffffffff813799fd: 83 e6 e0             	andl	$-0x20, %esi
ffffffff81379a00: 83 fe 40             	cmpl	$0x40, %esi
ffffffff81379a03: 0f 85 ec 02 00 00    	jne	0xffffffff81379cf5 <do_jit+0x12e5>
ffffffff81379a09: 48 b9 00 f0 ff ff ff 7f 00 00	movabsq	$0x7ffffffff000, %rcx # imm = 0x7FFFFFFFF000
ffffffff81379a13: 48 8b 94 24 c0 00 00 00      	movq	0xc0(%rsp), %rdx
ffffffff81379a1b: c7 02 49 c7 c2 00    	movl	$0xc2c749, (%rdx)       # imm = 0xC2C749
ffffffff81379a21: 48 8d 42 07          	leaq	0x7(%rdx), %rax
ffffffff81379a25: c7 42 03 00 00 60 ff 	movl	$0xff600000, 0x3(%rdx)  # imm = 0xFF600000
ffffffff81379a2c: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81379a34: 83 7c 24 38 0e       	cmpl	$0xe, 0x38(%rsp)
ffffffff81379a39: 0f 85 50 0b 00 00    	jne	0xffffffff8137a58f <do_jit+0x1b7f>
ffffffff81379a3f: 66 83 7f 02 00       	cmpw	$0x0, 0x2(%rdi)
ffffffff81379a44: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379a49: 0f 85 89 0b 00 00    	jne	0xffffffff8137a5d8 <do_jit+0x1bc8>
ffffffff81379a4f: 48 81 c1 00 10 a0 00 	addq	$0xa01000, %rcx         # imm = 0xA01000
ffffffff81379a56: 48 8d 50 03          	leaq	0x3(%rax), %rdx
ffffffff81379a5a: c6 00 4d             	movb	$0x4d, (%rax)
ffffffff81379a5d: 66 c7 40 01 29 d3    	movw	$0xd329, 0x1(%rax)      # imm = 0xD329
ffffffff81379a63: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff81379a6b: 48 89 ca             	movq	%rcx, %rdx
ffffffff81379a6e: 48 c1 ea 20          	shrq	$0x20, %rdx
ffffffff81379a72: 0f 84 ce 01 00 00    	je	0xffffffff81379c46 <do_jit+0x1236>
ffffffff81379a78: 48 89 ce             	movq	%rcx, %rsi
ffffffff81379a7b: 48 81 e6 00 00 00 80 	andq	$-0x80000000, %rsi      # imm = 0x80000000
ffffffff81379a82: 48 81 ee 00 00 00 80 	subq	$-0x80000000, %rsi      # imm = 0x80000000
ffffffff81379a89: 48 c1 ee 20          	shrq	$0x20, %rsi
ffffffff81379a8d: 0f 85 ce 01 00 00    	jne	0xffffffff81379c61 <do_jit+0x1251>
ffffffff81379a93: 85 c9                	testl	%ecx, %ecx
ffffffff81379a95: 0f 88 3e 03 00 00    	js	0xffffffff81379dd9 <do_jit+0x13c9>
ffffffff81379a9b: 0f 85 5c 0b 00 00    	jne	0xffffffff8137a5fd <do_jit+0x1bed>
ffffffff81379aa1: c6 40 03 45          	movb	$0x45, 0x3(%rax)
ffffffff81379aa5: 66 c7 40 04 31 d2    	movw	$0xd231, 0x4(%rax)      # imm = 0xD231
ffffffff81379aab: ba 06 00 00 00       	movl	$0x6, %edx
ffffffff81379ab0: 48 8d 4c 10 05       	leaq	0x5(%rax,%rdx), %rcx
ffffffff81379ab5: 48 01 d0             	addq	%rdx, %rax
ffffffff81379ab8: ba a0 d3 00 00       	movl	$0xd3a0, %edx           # imm = 0xD3A0
ffffffff81379abd: 44 0f a3 d2          	btl	%r10d, %edx
ffffffff81379ac1: c6 41 fb 4d          	movb	$0x4d, -0x5(%rcx)
ffffffff81379ac5: 48 89 cb             	movq	%rcx, %rbx
ffffffff81379ac8: c7 41 fc 39 d3 77 00 	movl	$0x77d339, -0x4(%rcx)   # imm = 0x77D339
ffffffff81379acf: 0f 82 3b 0b 00 00    	jb	0xffffffff8137a610 <do_jit+0x1c00>
ffffffff81379ad5: 44 89 d2             	movl	%r10d, %edx
ffffffff81379ad8: 8b 14 95 10 29 f2 82 	movl	-0x7d0dd6f0(,%rdx,4), %edx
ffffffff81379adf: c1 e2 08             	shll	$0x8, %edx
ffffffff81379ae2: 8d 94 d2 31 c0 ff ff 	leal	-0x3fcf(%rdx,%rdx,8), %edx
ffffffff81379ae9: 66 89 13             	movw	%dx, (%rbx)
ffffffff81379aec: 66 c7 43 02 eb 00    	movw	$0xeb, 0x2(%rbx)
ffffffff81379af2: 48 83 c3 04          	addq	$0x4, %rbx
ffffffff81379af6: 89 da                	movl	%ebx, %edx
ffffffff81379af8: 29 ca                	subl	%ecx, %edx
ffffffff81379afa: 48 89 9c 24 c0 00 00 00      	movq	%rbx, 0xc0(%rsp)
ffffffff81379b02: 88 50 04             	movb	%dl, 0x4(%rax)
ffffffff81379b05: 44 8a 3f             	movb	(%rdi), %r15b
ffffffff81379b08: 44 89 fe             	movl	%r15d, %esi
ffffffff81379b0b: 40 80 e6 e0          	andb	$-0x20, %sil
ffffffff81379b0f: 41 80 e7 18          	andb	$0x18, %r15b
ffffffff81379b13: 41 0f b6 c7          	movzbl	%r15b, %eax
ffffffff81379b17: 40 80 fe 80          	cmpb	$-0x80, %sil
ffffffff81379b1b: 0f 85 86 01 00 00    	jne	0xffffffff81379ca7 <do_jit+0x1297>
ffffffff81379b21: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff81379b29: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff81379b2e: 89 c6                	movl	%eax, %esi
ffffffff81379b30: 45 89 d6             	movl	%r10d, %r14d
ffffffff81379b33: 44 89 d2             	movl	%r10d, %edx
ffffffff81379b36: e8 45 ac 26 00       	callq	0xffffffff815e4780 <emit_ldsx>
ffffffff81379b3b: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81379b40: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81379b45: 48 8b 4c 24 30       	movq	0x30(%rsp), %rcx
ffffffff81379b4a: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff81379b52: 0f b6 07             	movzbl	(%rdi), %eax
ffffffff81379b55: 83 e0 e0             	andl	$-0x20, %eax
ffffffff81379b58: 83 f8 40             	cmpl	$0x40, %eax
ffffffff81379b5b: 74 09                	je	0xffffffff81379b66 <do_jit+0x1156>
ffffffff81379b5d: 83 f8 20             	cmpl	$0x20, %eax
ffffffff81379b60: 0f 85 b7 f4 ff ff    	jne	0xffffffff8137901d <do_jit+0x60d>
ffffffff81379b66: 8b 84 24 c0 00 00 00 	movl	0xc0(%rsp), %eax
ffffffff81379b6d: 48 8b 4c 24 60       	movq	0x60(%rsp), %rcx
ffffffff81379b72: 29 d8                	subl	%ebx, %eax
ffffffff81379b74: 88 43 ff             	movb	%al, -0x1(%rbx)
ffffffff81379b77: 48 8b 49 50          	movq	0x50(%rcx), %rcx
ffffffff81379b7b: 48 8b 81 68 04 00 00 	movq	0x468(%rcx), %rax
ffffffff81379b82: 48 85 c0             	testq	%rax, %rax
ffffffff81379b85: 0f 84 03 f7 ff ff    	je	0xffffffff8137928e <do_jit+0x87e>
ffffffff81379b8b: 48 8b 54 24 50       	movq	0x50(%rsp), %rdx
ffffffff81379b90: 3b 91 60 04 00 00    	cmpl	0x460(%rcx), %edx
ffffffff81379b96: 0f 83 86 00 00 00    	jae	0xffffffff81379c22 <do_jit+0x1212>
ffffffff81379b9c: 48 8d b4 24 d0 00 00 00      	leaq	0xd0(%rsp), %rsi
ffffffff81379ba4: 48 89 d9             	movq	%rbx, %rcx
ffffffff81379ba7: 48 63 54 24 30       	movslq	0x30(%rsp), %rdx
ffffffff81379bac: 48 29 f1             	subq	%rsi, %rcx
ffffffff81379baf: 48 63 74 24 50       	movslq	0x50(%rsp), %rsi
ffffffff81379bb4: 48 03 54 24 78       	addq	0x78(%rsp), %rdx
ffffffff81379bb9: 48 8d 34 76          	leaq	(%rsi,%rsi,2), %rsi
ffffffff81379bbd: 48 01 d1             	addq	%rdx, %rcx
ffffffff81379bc0: 48 8d 04 b0          	leaq	(%rax,%rsi,4), %rax
ffffffff81379bc4: 48 29 c1             	subq	%rax, %rcx
ffffffff81379bc7: 48 63 d1             	movslq	%ecx, %rdx
ffffffff81379bca: 48 39 ca             	cmpq	%rcx, %rdx
ffffffff81379bcd: 75 5f                	jne	0xffffffff81379c2e <do_jit+0x121e>
ffffffff81379bcf: 48 2b 44 24 78       	subq	0x78(%rsp), %rax
ffffffff81379bd4: 48 8b 54 24 70       	movq	0x70(%rsp), %rdx
ffffffff81379bd9: 89 0c 02             	movl	%ecx, (%rdx,%rax)
ffffffff81379bdc: c7 44 02 08 07 00 00 00      	movl	$0x7, 0x8(%rdx,%rax)
ffffffff81379be4: 41 80 fd 0a          	cmpb	$0xa, %r13b
ffffffff81379be8: 73 50                	jae	0xffffffff81379c3a <do_jit+0x122a>
ffffffff81379bea: 48 8b 4c 24 50       	movq	0x50(%rsp), %rcx
ffffffff81379bef: 44 89 f2             	movl	%r14d, %edx
ffffffff81379bf2: 8b 14 95 30 78 f1 82 	movl	-0x7d0e87d0(,%rdx,4), %edx
ffffffff81379bf9: 48 8b 74 24 70       	movq	0x70(%rsp), %rsi
ffffffff81379bfe: ff c1                	incl	%ecx
ffffffff81379c00: c1 e2 08             	shll	$0x8, %edx
ffffffff81379c03: 48 89 4c 24 50       	movq	%rcx, 0x50(%rsp)
ffffffff81379c08: 8b 8c 24 c0 00 00 00 	movl	0xc0(%rsp), %ecx
ffffffff81379c0f: 0f b7 d2             	movzwl	%dx, %edx
ffffffff81379c12: 29 d9                	subl	%ebx, %ecx
ffffffff81379c14: 0f b6 c9             	movzbl	%cl, %ecx
ffffffff81379c17: 09 ca                	orl	%ecx, %edx
ffffffff81379c19: 89 54 06 04          	movl	%edx, 0x4(%rsi,%rax)
ffffffff81379c1d: e9 6c f6 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff81379c22: 48 c7 c7 f1 bc ee 82 	movq	$-0x7d11430f, %rdi      # imm = 0x82EEBCF1
ffffffff81379c29: e9 cd 24 00 00       	jmp	0xffffffff8137c0fb <do_jit+0x36eb>
ffffffff81379c2e: 48 c7 c7 39 3f d9 82 	movq	$-0x7d26c0c7, %rdi      # imm = 0x82D93F39
ffffffff81379c35: e9 c1 24 00 00       	jmp	0xffffffff8137c0fb <do_jit+0x36eb>
ffffffff81379c3a: 48 c7 c7 54 1b e3 82 	movq	$-0x7d1ce4ac, %rdi      # imm = 0x82E31B54
ffffffff81379c41: e9 b5 24 00 00       	jmp	0xffffffff8137c0fb <do_jit+0x36eb>
ffffffff81379c46: 85 c9                	testl	%ecx, %ecx
ffffffff81379c48: 0f 84 53 fe ff ff    	je	0xffffffff81379aa1 <do_jit+0x1091>
ffffffff81379c4e: 66 c7 40 03 41 ba    	movw	$0xba41, 0x3(%rax)      # imm = 0xBA41
ffffffff81379c54: 89 48 05             	movl	%ecx, 0x5(%rax)
ffffffff81379c57: ba 09 00 00 00       	movl	$0x9, %edx
ffffffff81379c5c: e9 4f fe ff ff       	jmp	0xffffffff81379ab0 <do_jit+0x10a0>
ffffffff81379c61: 66 c7 40 03 49 ba    	movw	$0xba49, 0x3(%rax)      # imm = 0xBA49
ffffffff81379c67: 89 48 05             	movl	%ecx, 0x5(%rax)
ffffffff81379c6a: 89 50 09             	movl	%edx, 0x9(%rax)
ffffffff81379c6d: ba 0d 00 00 00       	movl	$0xd, %edx
ffffffff81379c72: e9 39 fe ff ff       	jmp	0xffffffff81379ab0 <do_jit+0x10a0>
ffffffff81379c77: c7 00 48 83 f8 21    	movl	$0x21f88348, (%rax)     # imm = 0x21F88348
ffffffff81379c7d: b1 50                	movb	$0x50, %cl
ffffffff81379c7f: ba 0d 00 00 00       	movl	$0xd, %edx
ffffffff81379c84: 66 c7 40 04 77 06    	movw	$0x677, 0x4(%rax)       # imm = 0x677
ffffffff81379c8a: 88 48 06             	movb	%cl, 0x6(%rax)
ffffffff81379c8d: c7 40 07 48 89 e0 00 	movl	$0xe08948, 0x7(%rax)    # imm = 0xE08948
ffffffff81379c94: 66 c7 40 0a eb 01    	movw	$0x1eb, 0xa(%rax)       # imm = 0x1EB
ffffffff81379c9a: 88 48 0c             	movb	%cl, 0xc(%rax)
ffffffff81379c9d: b9 0e 00 00 00       	movl	$0xe, %ecx
ffffffff81379ca2: e9 ae f9 ff ff       	jmp	0xffffffff81379655 <do_jit+0xc45>
ffffffff81379ca7: 40 0f b6 ce          	movzbl	%sil, %ecx
ffffffff81379cab: 83 f9 40             	cmpl	$0x40, %ecx
ffffffff81379cae: 0f 84 6d fe ff ff    	je	0xffffffff81379b21 <do_jit+0x1111>
ffffffff81379cb4: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff81379cbc: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff81379cc1: 89 c6                	movl	%eax, %esi
ffffffff81379cc3: 45 89 d6             	movl	%r10d, %r14d
ffffffff81379cc6: 44 89 d2             	movl	%r10d, %edx
ffffffff81379cc9: e8 02 02 0e 00       	callq	0xffffffff81459ed0 <emit_ldx>
ffffffff81379cce: e9 68 fe ff ff       	jmp	0xffffffff81379b3b <do_jit+0x112b>
ffffffff81379cd3: 83 f8 09             	cmpl	$0x9, %eax
ffffffff81379cd6: 0f 8f 7b 02 00 00    	jg	0xffffffff81379f57 <do_jit+0x1547>
ffffffff81379cdc: 83 f8 06             	cmpl	$0x6, %eax
ffffffff81379cdf: 0f 84 46 09 00 00    	je	0xffffffff8137a62b <do_jit+0x1c1b>
ffffffff81379ce5: 83 f8 09             	cmpl	$0x9, %eax
ffffffff81379ce8: 0f 85 a1 f7 ff ff    	jne	0xffffffff8137948f <do_jit+0xa7f>
ffffffff81379cee: b0 72                	movb	$0x72, %al
ffffffff81379cf0: e9 7e f6 ff ff       	jmp	0xffffffff81379373 <do_jit+0x963>
ffffffff81379cf5: 83 fe 20             	cmpl	$0x20, %esi
ffffffff81379cf8: 0f 84 0b fd ff ff    	je	0xffffffff81379a09 <do_jit+0xff9>
ffffffff81379cfe: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379d03: 31 db                	xorl	%ebx, %ebx
ffffffff81379d05: e9 05 fe ff ff       	jmp	0xffffffff81379b0f <do_jit+0x10ff>
ffffffff81379d0a: 83 fe 34             	cmpl	$0x34, %esi
ffffffff81379d0d: 0f 85 6b f7 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff81379d13: 45 85 d2             	testl	%r10d, %r10d
ffffffff81379d16: 0f 85 16 09 00 00    	jne	0xffffffff8137a632 <do_jit+0x1c22>
ffffffff81379d1c: 4c 8b 6c 24 38       	movq	0x38(%rsp), %r13
ffffffff81379d21: 41 c6 01 52          	movb	$0x52, (%r9)
ffffffff81379d25: 49 ff c1             	incq	%r9
ffffffff81379d28: b3 01                	movb	$0x1, %bl
ffffffff81379d2a: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81379d32: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379d37: f6 07 08             	testb	$0x8, (%rdi)
ffffffff81379d3a: 0f 85 15 01 00 00    	jne	0xffffffff81379e55 <do_jit+0x1445>
ffffffff81379d40: 41 c7 01 49 c7 c3 00 	movl	$0xc3c749, (%r9)        # imm = 0xC3C749
ffffffff81379d47: 49 8d 41 03          	leaq	0x3(%r9), %rax
ffffffff81379d4b: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81379d53: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff81379d58: 41 89 41 03          	movl	%eax, 0x3(%r9)
ffffffff81379d5c: b8 07 00 00 00       	movl	$0x7, %eax
ffffffff81379d61: 49 01 c1             	addq	%rax, %r9
ffffffff81379d64: 41 bd 0e 00 00 00    	movl	$0xe, %r13d
ffffffff81379d6a: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81379d72: 41 80 e7 07          	andb	$0x7, %r15b
ffffffff81379d76: 45 85 d2             	testl	%r10d, %r10d
ffffffff81379d79: 0f 85 d8 08 00 00    	jne	0xffffffff8137a657 <do_jit+0x1c47>
ffffffff81379d7f: 66 83 7f 02 00       	cmpw	$0x0, 0x2(%rdi)
ffffffff81379d84: 0f 84 f9 08 00 00    	je	0xffffffff8137a683 <do_jit+0x1c73>
ffffffff81379d8a: 8a 0f                	movb	(%rdi), %cl
ffffffff81379d8c: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff81379d94: 80 e1 07             	andb	$0x7, %cl
ffffffff81379d97: 80 f9 04             	cmpb	$0x4, %cl
ffffffff81379d9a: 0f 85 ed 00 00 00    	jne	0xffffffff81379e8d <do_jit+0x147d>
ffffffff81379da0: c6 00 99             	movb	$-0x67, (%rax)
ffffffff81379da3: b9 01 00 00 00       	movl	$0x1, %ecx
ffffffff81379da8: e9 ea 00 00 00       	jmp	0xffffffff81379e97 <do_jit+0x1487>
ffffffff81379dad: 83 f8 02             	cmpl	$0x2, %eax
ffffffff81379db0: 0f 84 1b 02 00 00    	je	0xffffffff81379fd1 <do_jit+0x15c1>
ffffffff81379db6: 8d 48 fd             	leal	-0x3(%rax), %ecx
ffffffff81379db9: 83 f9 02             	cmpl	$0x2, %ecx
ffffffff81379dbc: 0f 83 01 09 00 00    	jae	0xffffffff8137a6c3 <do_jit+0x1cb3>
ffffffff81379dc2: b0 75                	movb	$0x75, %al
ffffffff81379dc4: e9 aa f5 ff ff       	jmp	0xffffffff81379373 <do_jit+0x963>
ffffffff81379dc9: 83 f8 01             	cmpl	$0x1, %eax
ffffffff81379dcc: 0f 85 bd f6 ff ff    	jne	0xffffffff8137948f <do_jit+0xa7f>
ffffffff81379dd2: b0 77                	movb	$0x77, %al
ffffffff81379dd4: e9 9a f5 ff ff       	jmp	0xffffffff81379373 <do_jit+0x963>
ffffffff81379dd9: c7 40 03 49 c7 c2 00 	movl	$0xc2c749, 0x3(%rax)    # imm = 0xC2C749
ffffffff81379de0: ba 0a 00 00 00       	movl	$0xa, %edx
ffffffff81379de5: 89 48 06             	movl	%ecx, 0x6(%rax)
ffffffff81379de8: e9 c3 fc ff ff       	jmp	0xffffffff81379ab0 <do_jit+0x10a0>
ffffffff81379ded: b0 48                	movb	$0x48, %al
ffffffff81379def: 41 80 ff 05          	cmpb	$0x5, %r15b
ffffffff81379df3: 0f 85 da 08 00 00    	jne	0xffffffff8137a6d3 <do_jit+0x1cc3>
ffffffff81379df9: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff81379dfe: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff81379e02: 0f 92 c1             	setb	%cl
ffffffff81379e05: 08 c1                	orb	%al, %cl
ffffffff81379e07: 41 88 09             	movb	%cl, (%r9)
ffffffff81379e0a: 49 ff c1             	incq	%r9
ffffffff81379e0d: 44 89 d0             	movl	%r10d, %eax
ffffffff81379e10: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff81379e17: 48 8b 54 24 48       	movq	0x48(%rsp), %rdx
ffffffff81379e1c: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff81379e24: 0f be ca             	movsbl	%dl, %ecx
ffffffff81379e27: c1 e0 08             	shll	$0x8, %eax
ffffffff81379e2a: 39 d1                	cmpl	%edx, %ecx
ffffffff81379e2c: 0f 85 7b 01 00 00    	jne	0xffffffff81379fad <do_jit+0x159d>
ffffffff81379e32: 48 8b 4c 24 48       	movq	0x48(%rsp), %rcx
ffffffff81379e37: 05 00 f8 00 00       	addl	$0xf800, %eax           # imm = 0xF800
ffffffff81379e3c: 0f b7 c0             	movzwl	%ax, %eax
ffffffff81379e3f: c1 e1 10             	shll	$0x10, %ecx
ffffffff81379e42: 8d 84 08 83 00 00 00 	leal	0x83(%rax,%rcx), %eax
ffffffff81379e49: 41 89 01             	movl	%eax, (%r9)
ffffffff81379e4c: 49 83 c1 03          	addq	$0x3, %r9
ffffffff81379e50: e9 39 01 00 00       	jmp	0xffffffff81379f8e <do_jit+0x157e>
ffffffff81379e55: 41 83 fd 03          	cmpl	$0x3, %r13d
ffffffff81379e59: 74 09                	je	0xffffffff81379e64 <do_jit+0x1454>
ffffffff81379e5b: 45 85 ed             	testl	%r13d, %r13d
ffffffff81379e5e: 0f 85 0e ff ff ff    	jne	0xffffffff81379d72 <do_jit+0x1362>
ffffffff81379e64: 44 89 e8             	movl	%r13d, %eax
ffffffff81379e67: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff81379e6e: c1 e0 13             	shll	$0x13, %eax
ffffffff81379e71: 05 00 00 c3 00       	addl	$0xc30000, %eax         # imm = 0xC30000
ffffffff81379e76: 25 00 00 fb 00       	andl	$0xfb0000, %eax         # imm = 0xFB0000
ffffffff81379e7b: 0d 49 89 00 00       	orl	$0x8949, %eax           # imm = 0x8949
ffffffff81379e80: 41 89 01             	movl	%eax, (%r9)
ffffffff81379e83: b8 03 00 00 00       	movl	$0x3, %eax
ffffffff81379e88: e9 d4 fe ff ff       	jmp	0xffffffff81379d61 <do_jit+0x1351>
ffffffff81379e8d: b9 02 00 00 00       	movl	$0x2, %ecx
ffffffff81379e92: 66 c7 00 48 99       	movw	$0x9948, (%rax)         # imm = 0x9948
ffffffff81379e97: 48 01 c8             	addq	%rcx, %rax
ffffffff81379e9a: b1 48                	movb	$0x48, %cl
ffffffff81379e9c: 41 80 ff 07          	cmpb	$0x7, %r15b
ffffffff81379ea0: 0f 85 43 08 00 00    	jne	0xffffffff8137a6e9 <do_jit+0x1cd9>
ffffffff81379ea6: ba a0 d3 01 00       	movl	$0x1d3a0, %edx          # imm = 0x1D3A0
ffffffff81379eab: 44 0f a3 ea          	btl	%r13d, %edx
ffffffff81379eaf: 0f 92 c2             	setb	%dl
ffffffff81379eb2: 08 ca                	orb	%cl, %dl
ffffffff81379eb4: 88 10                	movb	%dl, (%rax)
ffffffff81379eb6: 48 ff c0             	incq	%rax
ffffffff81379eb9: 66 b9 f7 f8          	movw	$0xf8f7, %cx            # imm = 0xF8F7
ffffffff81379ebd: 44 89 ea             	movl	%r13d, %edx
ffffffff81379ec0: 8b 14 95 10 29 f2 82 	movl	-0x7d0dd6f0(,%rdx,4), %edx
ffffffff81379ec7: 0f bf c9             	movswl	%cx, %ecx
ffffffff81379eca: c1 e2 08             	shll	$0x8, %edx
ffffffff81379ecd: 01 d1                	addl	%edx, %ecx
ffffffff81379ecf: 66 89 08             	movw	%cx, (%rax)
ffffffff81379ed2: 48 83 c0 02          	addq	$0x2, %rax
ffffffff81379ed6: b9 03 00 00 00       	movl	$0x3, %ecx
ffffffff81379edb: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81379ee3: 8a 07                	movb	(%rdi), %al
ffffffff81379ee5: 24 f0                	andb	$-0x10, %al
ffffffff81379ee7: 3c 90                	cmpb	$-0x70, %al
ffffffff81379ee9: 0f 94 c2             	sete	%dl
ffffffff81379eec: 84 d3                	testb	%dl, %bl
ffffffff81379eee: 0f 84 0b 08 00 00    	je	0xffffffff8137a6ff <do_jit+0x1cef>
ffffffff81379ef4: 31 f6                	xorl	%esi, %esi
ffffffff81379ef6: 41 80 ff 07          	cmpb	$0x7, %r15b
ffffffff81379efa: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff81379f02: 44 89 d2             	movl	%r10d, %edx
ffffffff81379f05: 45 89 d6             	movl	%r10d, %r14d
ffffffff81379f08: 40 0f 94 c6          	sete	%sil
ffffffff81379f0c: e8 ef 9f 26 00       	callq	0xffffffff815e3f00 <emit_mov_reg>
ffffffff81379f11: 45 89 f2             	movl	%r14d, %r10d
ffffffff81379f14: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81379f19: 84 db                	testb	%bl, %bl
ffffffff81379f1b: 0f 85 f6 07 00 00    	jne	0xffffffff8137a717 <do_jit+0x1d07>
ffffffff81379f21: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81379f26: 48 8b 4c 24 30       	movq	0x30(%rsp), %rcx
ffffffff81379f2b: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff81379f33: 45 85 d2             	testl	%r10d, %r10d
ffffffff81379f36: 0f 84 e1 f0 ff ff    	je	0xffffffff8137901d <do_jit+0x60d>
ffffffff81379f3c: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff81379f44: c6 00 58             	movb	$0x58, (%rax)
ffffffff81379f47: 48 ff c0             	incq	%rax
ffffffff81379f4a: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff81379f52: e9 c6 f0 ff ff       	jmp	0xffffffff8137901d <do_jit+0x60d>
ffffffff81379f57: 83 f8 0a             	cmpl	$0xa, %eax
ffffffff81379f5a: 0f 85 d2 07 00 00    	jne	0xffffffff8137a732 <do_jit+0x1d22>
ffffffff81379f60: b0 76                	movb	$0x76, %al
ffffffff81379f62: e9 0c f4 ff ff       	jmp	0xffffffff81379373 <do_jit+0x963>
ffffffff81379f67: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff81379f6c: 0f 85 d0 07 00 00    	jne	0xffffffff8137a742 <do_jit+0x1d32>
ffffffff81379f72: 44 89 d0             	movl	%r10d, %eax
ffffffff81379f75: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff81379f7c: c1 e0 08             	shll	$0x8, %eax
ffffffff81379f7f: 8d 84 c0 85 c0 ff ff 	leal	-0x3f7b(%rax,%rax,8), %eax
ffffffff81379f86: 66 41 89 01          	movw	%ax, (%r9)
ffffffff81379f8a: 49 83 c1 02          	addq	$0x2, %r9
ffffffff81379f8e: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81379f93: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379f98: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81379f9d: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff81379fa5: 49 89 db             	movq	%rbx, %r11
ffffffff81379fa8: e9 94 f3 ff ff       	jmp	0xffffffff81379341 <do_jit+0x931>
ffffffff81379fad: 05 81 f8 ff ff       	addl	$0xfffff881, %eax       # imm = 0xFFFFF881
ffffffff81379fb2: 49 8d 49 02          	leaq	0x2(%r9), %rcx
ffffffff81379fb6: 66 41 89 01          	movw	%ax, (%r9)
ffffffff81379fba: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff81379fbf: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff81379fc7: 41 89 41 02          	movl	%eax, 0x2(%r9)
ffffffff81379fcb: 49 83 c1 06          	addq	$0x6, %r9
ffffffff81379fcf: eb bd                	jmp	0xffffffff81379f8e <do_jit+0x157e>
ffffffff81379fd1: b0 73                	movb	$0x73, %al
ffffffff81379fd3: e9 9b f3 ff ff       	jmp	0xffffffff81379373 <do_jit+0x963>
ffffffff81379fd8: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff81379fdd: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff81379fe2: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81379fe7: b8 fe ff ff ff       	movl	$0xfffffffe, %eax       # imm = 0xFFFFFFFE
ffffffff81379fec: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff81379ff4: e9 bc ef ff ff       	jmp	0xffffffff81378fb5 <do_jit+0x5a5>
ffffffff81379ff9: 3d b6 00 00 00       	cmpl	$0xb6, %eax
ffffffff81379ffe: 0f 8f 51 07 00 00    	jg	0xffffffff8137a755 <do_jit+0x1d45>
ffffffff8137a004: 3d b2 00 00 00       	cmpl	$0xb2, %eax
ffffffff8137a009: 0f 8e da 07 00 00    	jle	0xffffffff8137a7e9 <do_jit+0x1dd9>
ffffffff8137a00f: 3d b4 00 00 00       	cmpl	$0xb4, %eax
ffffffff8137a014: 0f 84 51 07 00 00    	je	0xffffffff8137a76b <do_jit+0x1d5b>
ffffffff8137a01a: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a01f: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a024: 8d 88 4b ff ff ff    	leal	-0xb5(%rax), %ecx
ffffffff8137a02a: 83 f9 02             	cmpl	$0x2, %ecx
ffffffff8137a02d: 0f 82 0f f9 ff ff    	jb	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137a033: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a036: 81 fe b3 00 00 00    	cmpl	$0xb3, %esi
ffffffff8137a03c: 0f 85 3c f4 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a042: e9 79 1c 00 00       	jmp	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137a047: 83 f8 68             	cmpl	$0x68, %eax
ffffffff8137a04a: 0f 8f d4 07 00 00    	jg	0xffffffff8137a824 <do_jit+0x1e14>
ffffffff8137a050: 83 f8 61             	cmpl	$0x61, %eax
ffffffff8137a053: 0f 8e 35 08 00 00    	jle	0xffffffff8137a88e <do_jit+0x1e7e>
ffffffff8137a059: 83 f8 64             	cmpl	$0x64, %eax
ffffffff8137a05c: 0f 8f 66 08 00 00    	jg	0xffffffff8137a8c8 <do_jit+0x1eb8>
ffffffff8137a062: 83 f8 62             	cmpl	$0x62, %eax
ffffffff8137a065: 0f 84 84 08 00 00    	je	0xffffffff8137a8ef <do_jit+0x1edf>
ffffffff8137a06b: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a070: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a075: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a078: 83 fe 63             	cmpl	$0x63, %esi
ffffffff8137a07b: 0f 84 29 15 00 00    	je	0xffffffff8137b5aa <do_jit+0x2b9a>
ffffffff8137a081: 83 fe 64             	cmpl	$0x64, %esi
ffffffff8137a084: 0f 85 f4 f3 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a08a: e9 41 19 00 00       	jmp	0xffffffff8137b9d0 <do_jit+0x2fc0>
ffffffff8137a08f: 3d a4 00 00 00       	cmpl	$0xa4, %eax
ffffffff8137a094: 0f 8e 76 08 00 00    	jle	0xffffffff8137a910 <do_jit+0x1f00>
ffffffff8137a09a: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a09d: 3d a8 00 00 00       	cmpl	$0xa8, %eax
ffffffff8137a0a2: 0f 8e b9 08 00 00    	jle	0xffffffff8137a961 <do_jit+0x1f51>
ffffffff8137a0a8: 3d ab 00 00 00       	cmpl	$0xab, %eax
ffffffff8137a0ad: 0f 8f e4 08 00 00    	jg	0xffffffff8137a997 <do_jit+0x1f87>
ffffffff8137a0b3: 48 8b 54 24 10       	movq	0x10(%rsp), %rdx
ffffffff8137a0b8: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a0bd: 81 fe a9 00 00 00    	cmpl	$0xa9, %esi
ffffffff8137a0c3: 0f 84 f7 1b 00 00    	je	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137a0c9: 81 fe aa 00 00 00    	cmpl	$0xaa, %esi
ffffffff8137a0cf: 0f 84 ff 0d 00 00    	je	0xffffffff8137aed4 <do_jit+0x24c4>
ffffffff8137a0d5: 81 fe ab 00 00 00    	cmpl	$0xab, %esi
ffffffff8137a0db: 0f 85 9d f3 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a0e1: e9 da 1b 00 00       	jmp	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137a0e6: 83 f8 7a             	cmpl	$0x7a, %eax
ffffffff8137a0e9: 0f 8f de 08 00 00    	jg	0xffffffff8137a9cd <do_jit+0x1fbd>
ffffffff8137a0ef: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a0f4: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a0f9: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a0fe: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a101: 83 fe 79             	cmpl	$0x79, %esi
ffffffff8137a104: 0f 84 e3 f8 ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137a10a: 83 fe 7a             	cmpl	$0x7a, %esi
ffffffff8137a10d: 0f 85 6b f3 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a113: 41 83 fa 0b          	cmpl	$0xb, %r10d
ffffffff8137a117: 0f 85 e5 08 00 00    	jne	0xffffffff8137aa02 <do_jit+0x1ff2>
ffffffff8137a11d: 48 8b 4c 24 10       	movq	0x10(%rsp), %rcx
ffffffff8137a122: 66 b8 48 c7          	movw	$0xc748, %ax            # imm = 0xC748
ffffffff8137a126: 66 83 79 02 f8       	cmpw	$-0x8, 0x2(%rcx)
ffffffff8137a12b: 0f 85 e4 08 00 00    	jne	0xffffffff8137aa15 <do_jit+0x2005>
ffffffff8137a131: 48 8b 4c 24 48       	movq	0x48(%rsp), %rcx
ffffffff8137a136: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137a13e: be 0f 00 00 00       	movl	$0xf, %esi
ffffffff8137a143: 89 ca                	movl	%ecx, %edx
ffffffff8137a145: c1 fa 1f             	sarl	$0x1f, %edx
ffffffff8137a148: e8 43 96 26 00       	callq	0xffffffff815e3790 <emit_mov_imm64>
ffffffff8137a14d: e9 3c f1 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137a152: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a157: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a15c: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a161: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a164: 81 fe 89 00 00 00    	cmpl	$0x89, %esi
ffffffff8137a16a: 0f 84 7d f8 ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137a170: 81 fe 91 00 00 00    	cmpl	$0x91, %esi
ffffffff8137a176: 0f 85 02 f3 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a17c: e9 6c f8 ff ff       	jmp	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137a181: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137a185: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137a18a: b0 40                	movb	$0x40, %al
ffffffff8137a18c: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137a18f: 0f 82 b2 f0 ff ff    	jb	0xffffffff81379247 <do_jit+0x837>
ffffffff8137a195: e9 cd f0 ff ff       	jmp	0xffffffff81379267 <do_jit+0x857>
ffffffff8137a19a: 4c 89 db             	movq	%r11, %rbx
ffffffff8137a19d: 45 89 d3             	movl	%r10d, %r11d
ffffffff8137a1a0: 4c 89 ca             	movq	%r9, %rdx
ffffffff8137a1a3: 48 89 f0             	movq	%rsi, %rax
ffffffff8137a1a6: 83 fe 43             	cmpl	$0x43, %esi
ffffffff8137a1a9: 0f 8e 73 08 00 00    	jle	0xffffffff8137aa22 <do_jit+0x2012>
ffffffff8137a1af: 83 f8 48             	cmpl	$0x48, %eax
ffffffff8137a1b2: 0f 8f a3 08 00 00    	jg	0xffffffff8137aa5b <do_jit+0x204b>
ffffffff8137a1b8: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a1bd: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a1c5: 48 89 c1             	movq	%rax, %rcx
ffffffff8137a1c8: 49 89 d1             	movq	%rdx, %r9
ffffffff8137a1cb: 45 89 da             	movl	%r11d, %r10d
ffffffff8137a1ce: 83 f9 44             	cmpl	$0x44, %ecx
ffffffff8137a1d1: 0f 84 4c ed ff ff    	je	0xffffffff81378f23 <do_jit+0x513>
ffffffff8137a1d7: 83 c1 bb             	addl	$-0x45, %ecx
ffffffff8137a1da: 83 f9 02             	cmpl	$0x2, %ecx
ffffffff8137a1dd: 0f 82 d4 08 00 00    	jb	0xffffffff8137aab7 <do_jit+0x20a7>
ffffffff8137a1e3: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a1e8: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a1f0: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a1f3: 49 89 d1             	movq	%rdx, %r9
ffffffff8137a1f6: 45 89 da             	movl	%r11d, %r10d
ffffffff8137a1f9: 83 fe 47             	cmpl	$0x47, %esi
ffffffff8137a1fc: 0f 85 7c f2 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a202: e9 1c ed ff ff       	jmp	0xffffffff81378f23 <do_jit+0x513>
ffffffff8137a207: 83 fe 51             	cmpl	$0x51, %esi
ffffffff8137a20a: 0f 84 dd f7 ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137a210: 83 fe 4f             	cmpl	$0x4f, %esi
ffffffff8137a213: 0f 85 65 f2 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a219: e9 5d 08 00 00       	jmp	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff8137a21e: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137a223: 44 89 d2             	movl	%r10d, %edx
ffffffff8137a226: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff8137a22a: 0f 82 e4 08 00 00    	jb	0xffffffff8137ab14 <do_jit+0x2104>
ffffffff8137a230: b1 44                	movb	$0x44, %cl
ffffffff8137a232: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137a237: 0f 85 e5 08 00 00    	jne	0xffffffff8137ab22 <do_jit+0x2112>
ffffffff8137a23d: 41 89 d2             	movl	%edx, %r10d
ffffffff8137a240: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137a245: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137a24a: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a24f: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137a254: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a25c: e9 b8 f0 ff ff       	jmp	0xffffffff81379319 <do_jit+0x909>
ffffffff8137a261: 83 f8 24             	cmpl	$0x24, %eax
ffffffff8137a264: 0f 8e e9 08 00 00    	jle	0xffffffff8137ab53 <do_jit+0x2143>
ffffffff8137a26a: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a26d: 83 c0 db             	addl	$-0x25, %eax
ffffffff8137a270: 49 89 d1             	movq	%rdx, %r9
ffffffff8137a273: 45 89 da             	movl	%r11d, %r10d
ffffffff8137a276: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137a279: 0f 82 c3 f6 ff ff    	jb	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137a27f: 83 fe 27             	cmpl	$0x27, %esi
ffffffff8137a282: 0f 85 f6 f1 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a288: e9 e6 08 00 00       	jmp	0xffffffff8137ab73 <do_jit+0x2163>
ffffffff8137a28d: 83 f8 13             	cmpl	$0x13, %eax
ffffffff8137a290: 0f 8f 14 09 00 00    	jg	0xffffffff8137abaa <do_jit+0x219a>
ffffffff8137a296: 48 89 c1             	movq	%rax, %rcx
ffffffff8137a299: 49 89 d1             	movq	%rdx, %r9
ffffffff8137a29c: 45 89 da             	movl	%r11d, %r10d
ffffffff8137a29f: 83 f9 0c             	cmpl	$0xc, %ecx
ffffffff8137a2a2: 0f 84 d3 07 00 00    	je	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff8137a2a8: 83 f9 0d             	cmpl	$0xd, %ecx
ffffffff8137a2ab: 0f 84 29 09 00 00    	je	0xffffffff8137abda <do_jit+0x21ca>
ffffffff8137a2b1: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a2b4: 83 fe 0f             	cmpl	$0xf, %esi
ffffffff8137a2b7: eb 36                	jmp	0xffffffff8137a2ef <do_jit+0x18df>
ffffffff8137a2b9: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a2be: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a2c1: 83 c0 e3             	addl	$-0x1d, %eax
ffffffff8137a2c4: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a2cc: 49 89 d1             	movq	%rdx, %r9
ffffffff8137a2cf: 45 89 da             	movl	%r11d, %r10d
ffffffff8137a2d2: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137a2d5: 0f 82 0b f2 ff ff    	jb	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137a2db: 83 fe 1f             	cmpl	$0x1f, %esi
ffffffff8137a2de: 0f 85 9a f1 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a2e4: e9 92 07 00 00       	jmp	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff8137a2e9: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a2ec: 83 fe 1c             	cmpl	$0x1c, %esi
ffffffff8137a2ef: 49 89 d1             	movq	%rdx, %r9
ffffffff8137a2f2: 45 89 da             	movl	%r11d, %r10d
ffffffff8137a2f5: 0f 85 83 f1 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a2fb: e9 7b 07 00 00       	jmp	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff8137a300: 83 7c 24 38 01       	cmpl	$0x1, 0x38(%rsp)
ffffffff8137a305: 0f 94 c0             	sete	%al
ffffffff8137a308: 22 44 24 46          	andb	0x46(%rsp), %al
ffffffff8137a30c: 3c 01                	cmpb	$0x1, %al
ffffffff8137a30e: 75 36                	jne	0xffffffff8137a346 <do_jit+0x1936>
ffffffff8137a310: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137a315: 49 83 c4 07          	addq	$0x7, %r12
ffffffff8137a319: c7 01 48 8b 85 00    	movl	$0x858b48, (%rcx)       # imm = 0x858B48
ffffffff8137a31f: 48 8d 41 03          	leaq	0x3(%rcx), %rax
ffffffff8137a323: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137a32b: 8b 84 24 9c 00 00 00 	movl	0x9c(%rsp), %eax
ffffffff8137a332: 89 41 03             	movl	%eax, 0x3(%rcx)
ffffffff8137a335: 48 83 c1 07          	addq	$0x7, %rcx
ffffffff8137a339: 48 89 4c 24 18       	movq	%rcx, 0x18(%rsp)
ffffffff8137a33e: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137a346: 83 7c 24 48 00       	cmpl	$0x0, 0x48(%rsp)
ffffffff8137a34b: bb ea ff ff ff       	movl	$0xffffffea, %ebx       # imm = 0xFFFFFFEA
ffffffff8137a350: 0f 84 39 f1 ff ff    	je	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137a356: 80 7c 24 47 00       	cmpb	$0x0, 0x47(%rsp)
ffffffff8137a35b: 75 1a                	jne	0xffffffff8137a377 <do_jit+0x1967>
ffffffff8137a35d: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137a362: 49 83 c4 02          	addq	$0x2, %r12
ffffffff8137a366: 66 c7 00 41 51       	movw	$0x5141, (%rax)         # imm = 0x5141
ffffffff8137a36b: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137a36f: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137a377: 48 63 44 24 48       	movslq	0x48(%rsp), %rax
ffffffff8137a37c: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137a384: 4c 89 e2             	movq	%r12, %rdx
ffffffff8137a387: 4c 8d b0 b0 de 7c 81 	leaq	-0x7e832150(%rax), %r14
ffffffff8137a38e: 4c 89 f6             	movq	%r14, %rsi
ffffffff8137a391: e8 aa 1a 25 00       	callq	0xffffffff815cbe40 <x86_call_depth_emit_accounting>
ffffffff8137a396: 48 98                	cltq
ffffffff8137a398: 4c 01 e0             	addq	%r12, %rax
ffffffff8137a39b: 48 f7 d8             	negq	%rax
ffffffff8137a39e: 49 8d 4c 06 fb       	leaq	-0x5(%r14,%rax), %rcx
ffffffff8137a3a3: 48 63 c1             	movslq	%ecx, %rax
ffffffff8137a3a6: 48 39 c8             	cmpq	%rcx, %rax
ffffffff8137a3a9: 75 34                	jne	0xffffffff8137a3df <do_jit+0x19cf>
ffffffff8137a3ab: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff8137a3b3: c6 00 e8             	movb	$-0x18, (%rax)
ffffffff8137a3b6: 89 48 01             	movl	%ecx, 0x1(%rax)
ffffffff8137a3b9: 48 8d 48 05          	leaq	0x5(%rax), %rcx
ffffffff8137a3bd: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137a3c5: 80 7c 24 47 00       	cmpb	$0x0, 0x47(%rsp)
ffffffff8137a3ca: 0f 85 be ee ff ff    	jne	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137a3d0: 66 c7 40 05 41 59    	movw	$0x5941, 0x5(%rax)      # imm = 0x5941
ffffffff8137a3d6: 48 83 c0 07          	addq	$0x7, %rax
ffffffff8137a3da: e9 80 1e 00 00       	jmp	0xffffffff8137c25f <do_jit+0x384f>
ffffffff8137a3df: 48 c7 c7 34 04 df 82 	movq	$-0x7d20fbcc, %rdi      # imm = 0x82DF0434
ffffffff8137a3e6: 4c 89 f6             	movq	%r14, %rsi
ffffffff8137a3e9: e8 52 40 ee ff       	callq	0xffffffff8125e440 <_printk>
ffffffff8137a3ee: e9 9c f0 ff ff       	jmp	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137a3f3: 83 fe 2f             	cmpl	$0x2f, %esi
ffffffff8137a3f6: 0f 85 82 f0 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a3fc: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137a401: 41 f6 d7             	notb	%r15b
ffffffff8137a404: c4 e2 11 f7 c0       	shlxl	%r13d, %eax, %eax
ffffffff8137a409: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137a40d: 0f 85 eb 07 00 00    	jne	0xffffffff8137abfe <do_jit+0x21ee>
ffffffff8137a413: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137a418: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137a41d: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137a422: 0f 95 c0             	setne	%al
ffffffff8137a425: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137a428: 0f 92 c1             	setb	%cl
ffffffff8137a42b: c0 e0 02             	shlb	$0x2, %al
ffffffff8137a42e: 08 c8                	orb	%cl, %al
ffffffff8137a430: 0c 48                	orb	$0x48, %al
ffffffff8137a432: e9 8d 0b 00 00       	jmp	0xffffffff8137afc4 <do_jit+0x25b4>
ffffffff8137a437: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137a43c: 44 89 d2             	movl	%r10d, %edx
ffffffff8137a43f: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff8137a443: 0f 82 db 07 00 00    	jb	0xffffffff8137ac24 <do_jit+0x2214>
ffffffff8137a449: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137a44e: 0f 84 0a 08 00 00    	je	0xffffffff8137ac5e <do_jit+0x224e>
ffffffff8137a454: b1 44                	movb	$0x44, %cl
ffffffff8137a456: e9 d7 07 00 00       	jmp	0xffffffff8137ac32 <do_jit+0x2222>
ffffffff8137a45b: 8d 46 ab             	leal	-0x55(%rsi), %eax
ffffffff8137a45e: 4c 89 db             	movq	%r11, %rbx
ffffffff8137a461: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137a464: 0f 82 d8 f4 ff ff    	jb	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137a46a: 83 fe 54             	cmpl	$0x54, %esi
ffffffff8137a46d: 0f 85 0b f0 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a473: e9 ab ea ff ff       	jmp	0xffffffff81378f23 <do_jit+0x513>
ffffffff8137a478: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137a47d: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137a482: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a487: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a48f: 4d 89 d1             	movq	%r10, %r9
ffffffff8137a492: e9 28 eb ff ff       	jmp	0xffffffff81378fbf <do_jit+0x5af>
ffffffff8137a497: 48 8d b4 24 d0 00 00 00      	leaq	0xd0(%rsp), %rsi
ffffffff8137a49f: 44 29 ce             	subl	%r9d, %esi
ffffffff8137a4a2: 01 d6                	addl	%edx, %esi
ffffffff8137a4a4: 43 2b 34 9f          	subl	(%r15,%r11,4), %esi
ffffffff8137a4a8: 83 c6 fe             	addl	$-0x2, %esi
ffffffff8137a4ab: f7 c6 fb ff ff ff    	testl	$0xfffffffb, %esi       # imm = 0xFFFFFFFB
ffffffff8137a4b1: 75 60                	jne	0xffffffff8137a513 <do_jit+0x1b03>
ffffffff8137a4b3: 4d 89 ca             	movq	%r9, %r10
ffffffff8137a4b6: 85 f6                	testl	%esi, %esi
ffffffff8137a4b8: 0f 84 bf 07 00 00    	je	0xffffffff8137ac7d <do_jit+0x226d>
ffffffff8137a4be: 83 fe 0b             	cmpl	$0xb, %esi
ffffffff8137a4c1: 41 b8 0b 00 00 00    	movl	$0xb, %r8d
ffffffff8137a4c7: 4c 89 d2             	movq	%r10, %rdx
ffffffff8137a4ca: 44 0f 42 c6          	cmovbl	%esi, %r8d
ffffffff8137a4ce: 31 ff                	xorl	%edi, %edi
ffffffff8137a4d0: 4e 8b 0c c5 80 f0 f0 82      	movq	-0x7d0f0f80(,%r8,8), %r9
ffffffff8137a4d8: 45 8a 14 39          	movb	(%r9,%rdi), %r10b
ffffffff8137a4dc: 44 88 14 3a          	movb	%r10b, (%rdx,%rdi)
ffffffff8137a4e0: 48 ff c7             	incq	%rdi
ffffffff8137a4e3: 49 39 f8             	cmpq	%rdi, %r8
ffffffff8137a4e6: 75 f0                	jne	0xffffffff8137a4d8 <do_jit+0x1ac8>
ffffffff8137a4e8: 4c 8d 14 3a          	leaq	(%rdx,%rdi), %r10
ffffffff8137a4ec: 44 29 c6             	subl	%r8d, %esi
ffffffff8137a4ef: 7f cd                	jg	0xffffffff8137a4be <do_jit+0x1aae>
ffffffff8137a4f1: 48 01 fa             	addq	%rdi, %rdx
ffffffff8137a4f4: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137a4f9: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137a4fe: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a503: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a50b: 49 89 d1             	movq	%rdx, %r9
ffffffff8137a50e: e9 82 f4 ff ff       	jmp	0xffffffff81379995 <do_jit+0xf85>
ffffffff8137a513: 48 c7 c7 29 cd df 82 	movq	$-0x7d2032d7, %rdi      # imm = 0x82DFCD29
ffffffff8137a51a: e8 21 3f ee ff       	callq	0xffffffff8125e440 <_printk>
ffffffff8137a51f: e9 6b ef ff ff       	jmp	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137a524: 83 fe 37             	cmpl	$0x37, %esi
ffffffff8137a527: 0f 84 e6 f7 ff ff    	je	0xffffffff81379d13 <do_jit+0x1303>
ffffffff8137a52d: 83 fe 3c             	cmpl	$0x3c, %esi
ffffffff8137a530: 0f 85 48 ef ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a536: e9 d8 f7 ff ff       	jmp	0xffffffff81379d13 <do_jit+0x1303>
ffffffff8137a53b: b8 0a 00 00 00       	movl	$0xa, %eax
ffffffff8137a540: 48 89 44 24 38       	movq	%rax, 0x38(%rsp)
ffffffff8137a545: 66 41 83 f8 08       	cmpw	$0x8, %r8w
ffffffff8137a54a: 0f 85 ad f4 ff ff    	jne	0xffffffff813799fd <do_jit+0xfed>
ffffffff8137a550: 41 83 fa 0f          	cmpl	$0xf, %r10d
ffffffff8137a554: 0f 84 34 ed ff ff    	je	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137a55a: 44 89 d1             	movl	%r10d, %ecx
ffffffff8137a55d: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137a564: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137a569: c4 e2 13 f7 c0       	shrxl	%r13d, %eax, %eax
ffffffff8137a56e: 83 e0 01             	andl	$0x1, %eax
ffffffff8137a571: c1 e1 10             	shll	$0x10, %ecx
ffffffff8137a574: 81 c1 00 00 c8 00    	addl	$0xc80000, %ecx         # imm = 0xC80000
ffffffff8137a57a: 81 e1 00 00 ff 00    	andl	$0xff0000, %ecx         # imm = 0xFF0000
ffffffff8137a580: 8d 84 08 4c 89 00 00 	leal	0x894c(%rax,%rcx), %eax
ffffffff8137a587: 41 89 01             	movl	%eax, (%r9)
ffffffff8137a58a: e9 72 0a 00 00       	jmp	0xffffffff8137b001 <do_jit+0x25f1>
ffffffff8137a58f: 4c 8b 4c 24 38       	movq	0x38(%rsp), %r9
ffffffff8137a594: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137a599: 31 f6                	xorl	%esi, %esi
ffffffff8137a59b: 44 0f a3 c8          	btl	%r9d, %eax
ffffffff8137a59f: 44 89 c8             	movl	%r9d, %eax
ffffffff8137a5a2: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137a5a9: 40 0f 92 c6          	setb	%sil
ffffffff8137a5ad: c1 e0 13             	shll	$0x13, %eax
ffffffff8137a5b0: 05 00 00 c3 00       	addl	$0xc30000, %eax         # imm = 0xC30000
ffffffff8137a5b5: 25 00 00 fb 00       	andl	$0xfb0000, %eax         # imm = 0xFB0000
ffffffff8137a5ba: 8d 84 b0 49 89 00 00 	leal	0x8949(%rax,%rsi,4), %eax
ffffffff8137a5c1: 89 42 07             	movl	%eax, 0x7(%rdx)
ffffffff8137a5c4: 48 83 c2 0a          	addq	$0xa, %rdx
ffffffff8137a5c8: 48 89 d0             	movq	%rdx, %rax
ffffffff8137a5cb: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137a5d3: e9 67 f4 ff ff       	jmp	0xffffffff81379a3f <do_jit+0x102f>
ffffffff8137a5d8: 48 8d 50 03          	leaq	0x3(%rax), %rdx
ffffffff8137a5dc: c6 00 49             	movb	$0x49, (%rax)
ffffffff8137a5df: 66 c7 40 01 81 c3    	movw	$0xc381, 0x1(%rax)      # imm = 0xC381
ffffffff8137a5e5: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137a5ed: 0f bf 57 02          	movswl	0x2(%rdi), %edx
ffffffff8137a5f1: 89 50 03             	movl	%edx, 0x3(%rax)
ffffffff8137a5f4: 48 83 c0 07          	addq	$0x7, %rax
ffffffff8137a5f8: e9 52 f4 ff ff       	jmp	0xffffffff81379a4f <do_jit+0x103f>
ffffffff8137a5fd: 66 c7 40 03 41 ba    	movw	$0xba41, 0x3(%rax)      # imm = 0xBA41
ffffffff8137a603: 89 48 05             	movl	%ecx, 0x5(%rax)
ffffffff8137a606: ba 09 00 00 00       	movl	$0x9, %edx
ffffffff8137a60b: e9 a0 f4 ff ff       	jmp	0xffffffff81379ab0 <do_jit+0x10a0>
ffffffff8137a610: ba a0 d3 01 00       	movl	$0x1d3a0, %edx          # imm = 0x1D3A0
ffffffff8137a615: 48 8d 58 06          	leaq	0x6(%rax), %rbx
ffffffff8137a619: 44 0f a3 d2          	btl	%r10d, %edx
ffffffff8137a61d: 0f 92 c2             	setb	%dl
ffffffff8137a620: 80 ca 44             	orb	$0x44, %dl
ffffffff8137a623: 88 50 05             	movb	%dl, 0x5(%rax)
ffffffff8137a626: e9 aa f4 ff ff       	jmp	0xffffffff81379ad5 <do_jit+0x10c5>
ffffffff8137a62b: b0 7d                	movb	$0x7d, %al
ffffffff8137a62d: e9 41 ed ff ff       	jmp	0xffffffff81379373 <do_jit+0x963>
ffffffff8137a632: 4c 8b 6c 24 38       	movq	0x38(%rsp), %r13
ffffffff8137a637: 41 c6 01 50          	movb	$0x50, (%r9)
ffffffff8137a63b: 49 ff c1             	incq	%r9
ffffffff8137a63e: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff8137a646: 41 83 fa 03          	cmpl	$0x3, %r10d
ffffffff8137a64a: 0f 85 d1 f6 ff ff    	jne	0xffffffff81379d21 <do_jit+0x1311>
ffffffff8137a650: 31 db                	xorl	%ebx, %ebx
ffffffff8137a652: e9 db f6 ff ff       	jmp	0xffffffff81379d32 <do_jit+0x1322>
ffffffff8137a657: 31 f6                	xorl	%esi, %esi
ffffffff8137a659: 41 80 ff 07          	cmpb	$0x7, %r15b
ffffffff8137a65d: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137a665: 44 89 d1             	movl	%r10d, %ecx
ffffffff8137a668: 45 89 d6             	movl	%r10d, %r14d
ffffffff8137a66b: 40 0f 94 c6          	sete	%sil
ffffffff8137a66f: 31 d2                	xorl	%edx, %edx
ffffffff8137a671: e8 8a 98 26 00       	callq	0xffffffff815e3f00 <emit_mov_reg>
ffffffff8137a676: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a67b: 45 89 f2             	movl	%r14d, %r10d
ffffffff8137a67e: e9 fc f6 ff ff       	jmp	0xffffffff81379d7f <do_jit+0x136f>
ffffffff8137a683: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff8137a68b: b1 48                	movb	$0x48, %cl
ffffffff8137a68d: 66 c7 00 31 d2       	movw	$0xd231, (%rax)         # imm = 0xD231
ffffffff8137a692: 41 80 ff 07          	cmpb	$0x7, %r15b
ffffffff8137a696: 74 11                	je	0xffffffff8137a6a9 <do_jit+0x1c99>
ffffffff8137a698: ba a0 d3 00 00       	movl	$0xd3a0, %edx           # imm = 0xD3A0
ffffffff8137a69d: b1 40                	movb	$0x40, %cl
ffffffff8137a69f: 44 0f a3 ea          	btl	%r13d, %edx
ffffffff8137a6a3: 0f 83 f3 05 00 00    	jae	0xffffffff8137ac9c <do_jit+0x228c>
ffffffff8137a6a9: ba a0 d3 01 00       	movl	$0x1d3a0, %edx          # imm = 0x1D3A0
ffffffff8137a6ae: 44 0f a3 ea          	btl	%r13d, %edx
ffffffff8137a6b2: 0f 92 c2             	setb	%dl
ffffffff8137a6b5: 08 ca                	orb	%cl, %dl
ffffffff8137a6b7: 88 50 02             	movb	%dl, 0x2(%rax)
ffffffff8137a6ba: 48 83 c0 03          	addq	$0x3, %rax
ffffffff8137a6be: e9 dd 05 00 00       	jmp	0xffffffff8137aca0 <do_jit+0x2290>
ffffffff8137a6c3: 83 f8 05             	cmpl	$0x5, %eax
ffffffff8137a6c6: 0f 85 c3 ed ff ff    	jne	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137a6cc: b0 7f                	movb	$0x7f, %al
ffffffff8137a6ce: e9 eb 05 00 00       	jmp	0xffffffff8137acbe <do_jit+0x22ae>
ffffffff8137a6d3: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137a6d8: b0 40                	movb	$0x40, %al
ffffffff8137a6da: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff8137a6de: 0f 82 15 f7 ff ff    	jb	0xffffffff81379df9 <do_jit+0x13e9>
ffffffff8137a6e4: e9 24 f7 ff ff       	jmp	0xffffffff81379e0d <do_jit+0x13fd>
ffffffff8137a6e9: ba a0 d3 00 00       	movl	$0xd3a0, %edx           # imm = 0xD3A0
ffffffff8137a6ee: b1 40                	movb	$0x40, %cl
ffffffff8137a6f0: 44 0f a3 ea          	btl	%r13d, %edx
ffffffff8137a6f4: 0f 82 ac f7 ff ff    	jb	0xffffffff81379ea6 <do_jit+0x1496>
ffffffff8137a6fa: e9 ba f7 ff ff       	jmp	0xffffffff81379eb9 <do_jit+0x14a9>
ffffffff8137a6ff: 45 85 d2             	testl	%r10d, %r10d
ffffffff8137a702: 0f 84 0c f8 ff ff    	je	0xffffffff81379f14 <do_jit+0x1504>
ffffffff8137a708: 31 c9                	xorl	%ecx, %ecx
ffffffff8137a70a: 3c 30                	cmpb	$0x30, %al
ffffffff8137a70c: 0f 84 e2 f7 ff ff    	je	0xffffffff81379ef4 <do_jit+0x14e4>
ffffffff8137a712: e9 fd f7 ff ff       	jmp	0xffffffff81379f14 <do_jit+0x1504>
ffffffff8137a717: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff8137a71f: c6 00 5a             	movb	$0x5a, (%rax)
ffffffff8137a722: 48 ff c0             	incq	%rax
ffffffff8137a725: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137a72d: e9 ef f7 ff ff       	jmp	0xffffffff81379f21 <do_jit+0x1511>
ffffffff8137a732: 83 f8 0b             	cmpl	$0xb, %eax
ffffffff8137a735: 0f 85 78 05 00 00    	jne	0xffffffff8137acb3 <do_jit+0x22a3>
ffffffff8137a73b: b0 7c                	movb	$0x7c, %al
ffffffff8137a73d: e9 7c 05 00 00       	jmp	0xffffffff8137acbe <do_jit+0x22ae>
ffffffff8137a742: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137a747: 44 0f a3 d0          	btl	%r10d, %eax
ffffffff8137a74b: 0f 92 c0             	setb	%al
ffffffff8137a74e: 0c 44                	orb	$0x44, %al
ffffffff8137a750: e9 2b f2 ff ff       	jmp	0xffffffff81379980 <do_jit+0xf70>
ffffffff8137a755: 3d ba 00 00 00       	cmpl	$0xba, %eax
ffffffff8137a75a: 0f 8f 7a 05 00 00    	jg	0xffffffff8137acda <do_jit+0x22ca>
ffffffff8137a760: 3d b7 00 00 00       	cmpl	$0xb7, %eax
ffffffff8137a765: 0f 85 b9 05 00 00    	jne	0xffffffff8137ad24 <do_jit+0x2314>
ffffffff8137a76b: 41 f6 d7             	notb	%r15b
ffffffff8137a76e: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137a772: 0f 94 c0             	sete	%al
ffffffff8137a775: 83 7c 24 48 00       	cmpl	$0x0, 0x48(%rsp)
ffffffff8137a77a: 0f 98 c1             	sets	%cl
ffffffff8137a77d: 20 c1                	andb	%al, %cl
ffffffff8137a77f: 80 f9 01             	cmpb	$0x1, %cl
ffffffff8137a782: 0f 84 c6 05 00 00    	je	0xffffffff8137ad4e <do_jit+0x233e>
ffffffff8137a788: 83 7c 24 48 00       	cmpl	$0x0, 0x48(%rsp)
ffffffff8137a78d: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137a792: c4 e2 11 f7 c0       	shlxl	%r13d, %eax, %eax
ffffffff8137a797: 0f 84 f4 05 00 00    	je	0xffffffff8137ad91 <do_jit+0x2381>
ffffffff8137a79d: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137a7a2: 74 20                	je	0xffffffff8137a7c4 <do_jit+0x1db4>
ffffffff8137a7a4: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137a7a8: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137a7ad: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137a7b2: 0f a3 c8             	btl	%ecx, %eax
ffffffff8137a7b5: 0f 92 c0             	setb	%al
ffffffff8137a7b8: 0c 40                	orb	$0x40, %al
ffffffff8137a7ba: 88 02                	movb	%al, (%rdx)
ffffffff8137a7bc: 48 ff c2             	incq	%rdx
ffffffff8137a7bf: 48 89 54 24 18       	movq	%rdx, 0x18(%rsp)
ffffffff8137a7c4: 8b 44 24 0c          	movl	0xc(%rsp), %eax
ffffffff8137a7c8: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137a7cd: 8a 04 85 10 29 f2 82 	movb	-0x7d0dd6f0(,%rax,4), %al
ffffffff8137a7d4: 04 b8                	addb	$-0x48, %al
ffffffff8137a7d6: 88 01                	movb	%al, (%rcx)
ffffffff8137a7d8: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff8137a7dd: 89 41 01             	movl	%eax, 0x1(%rcx)
ffffffff8137a7e0: 48 83 c1 05          	addq	$0x5, %rcx
ffffffff8137a7e4: e9 f0 05 00 00       	jmp	0xffffffff8137add9 <do_jit+0x23c9>
ffffffff8137a7e9: 48 8b 54 24 10       	movq	0x10(%rsp), %rdx
ffffffff8137a7ee: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a7f3: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a7f8: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a7fb: 81 fe af 00 00 00    	cmpl	$0xaf, %esi
ffffffff8137a801: 0f 84 74 02 00 00    	je	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff8137a807: 81 fe b1 00 00 00    	cmpl	$0xb1, %esi
ffffffff8137a80d: 0f 84 ad 14 00 00    	je	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137a813: 81 fe b2 00 00 00    	cmpl	$0xb2, %esi
ffffffff8137a819: 0f 85 5f ec ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a81f: e9 b0 06 00 00       	jmp	0xffffffff8137aed4 <do_jit+0x24c4>
ffffffff8137a824: 83 f8 70             	cmpl	$0x70, %eax
ffffffff8137a827: 0f 8f b4 05 00 00    	jg	0xffffffff8137ade1 <do_jit+0x23d1>
ffffffff8137a82d: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a832: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a837: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a83c: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a83f: 83 fe 6a             	cmpl	$0x6a, %esi
ffffffff8137a842: 0f 8c a5 f1 ff ff    	jl	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137a848: 83 fe 6b             	cmpl	$0x6b, %esi
ffffffff8137a84b: 0f 8e db 05 00 00    	jle	0xffffffff8137ae2c <do_jit+0x241c>
ffffffff8137a851: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a856: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a85b: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a860: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a868: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a86b: 83 fe 6c             	cmpl	$0x6c, %esi
ffffffff8137a86e: 0f 84 b9 0b 00 00    	je	0xffffffff8137b42d <do_jit+0x2a1d>
ffffffff8137a874: 8d 4e 93             	leal	-0x6d(%rsi), %ecx
ffffffff8137a877: 83 f9 02             	cmpl	$0x2, %ecx
ffffffff8137a87a: 0f 82 66 ec ff ff    	jb	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137a880: 83 fe 6f             	cmpl	$0x6f, %esi
ffffffff8137a883: 0f 85 f5 eb ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a889: e9 9f 0b 00 00       	jmp	0xffffffff8137b42d <do_jit+0x2a1d>
ffffffff8137a88e: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a893: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a898: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a89d: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a8a5: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a8a8: 0f 84 3f f1 ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137a8ae: 8d 46 a3             	leal	-0x5d(%rsi), %eax
ffffffff8137a8b1: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137a8b4: 0f 82 2c ec ff ff    	jb	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137a8ba: 83 fe 5f             	cmpl	$0x5f, %esi
ffffffff8137a8bd: 0f 85 bb eb ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a8c3: e9 b3 01 00 00       	jmp	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff8137a8c8: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a8cd: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a8d2: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a8d5: 83 c0 9b             	addl	$-0x65, %eax
ffffffff8137a8d8: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137a8db: 0f 82 61 f0 ff ff    	jb	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137a8e1: 83 fe 67             	cmpl	$0x67, %esi
ffffffff8137a8e4: 0f 85 94 eb ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a8ea: e9 e1 10 00 00       	jmp	0xffffffff8137b9d0 <do_jit+0x2fc0>
ffffffff8137a8ef: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137a8f3: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137a8f8: 0f a3 c8             	btl	%ecx, %eax
ffffffff8137a8fb: 0f 83 4f 05 00 00    	jae	0xffffffff8137ae50 <do_jit+0x2440>
ffffffff8137a901: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137a906: 66 c7 00 41 c7       	movw	$0xc741, (%rax)         # imm = 0xC741
ffffffff8137a90b: e9 0a 0d 00 00       	jmp	0xffffffff8137b61a <do_jit+0x2c0a>
ffffffff8137a910: 3d 96 00 00 00       	cmpl	$0x96, %eax
ffffffff8137a915: 0f 8e 42 05 00 00    	jle	0xffffffff8137ae5d <do_jit+0x244d>
ffffffff8137a91b: 3d a0 00 00 00       	cmpl	$0xa0, %eax
ffffffff8137a920: 0f 8f 7e 05 00 00    	jg	0xffffffff8137aea4 <do_jit+0x2494>
ffffffff8137a926: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a92b: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a930: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a935: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a938: 81 fe 97 00 00 00    	cmpl	$0x97, %esi
ffffffff8137a93e: 0f 84 cf f3 ff ff    	je	0xffffffff81379d13 <do_jit+0x1303>
ffffffff8137a944: 81 fe 9c 00 00 00    	cmpl	$0x9c, %esi
ffffffff8137a94a: 0f 84 c3 f3 ff ff    	je	0xffffffff81379d13 <do_jit+0x1303>
ffffffff8137a950: 81 fe 9f 00 00 00    	cmpl	$0x9f, %esi
ffffffff8137a956: 0f 85 22 eb ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a95c: e9 b2 f3 ff ff       	jmp	0xffffffff81379d13 <do_jit+0x1303>
ffffffff8137a961: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a966: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a96b: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a970: 05 5b ff ff ff       	addl	$0xffffff5b, %eax       # imm = 0xFFFFFF5B
ffffffff8137a975: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a97d: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137a980: 0f 82 bc ef ff ff    	jb	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137a986: 81 fe a7 00 00 00    	cmpl	$0xa7, %esi
ffffffff8137a98c: 0f 85 ec ea ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a992: e9 8c e5 ff ff       	jmp	0xffffffff81378f23 <do_jit+0x513>
ffffffff8137a997: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a99c: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a9a1: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a9a6: 05 53 ff ff ff       	addl	$0xffffff53, %eax       # imm = 0xFFFFFF53
ffffffff8137a9ab: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137a9b3: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137a9b6: 0f 82 2a eb ff ff    	jb	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137a9bc: 81 fe ac 00 00 00    	cmpl	$0xac, %esi
ffffffff8137a9c2: 0f 85 b6 ea ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a9c8: e9 ae 00 00 00       	jmp	0xffffffff8137aa7b <do_jit+0x206b>
ffffffff8137a9cd: 48 89 c6             	movq	%rax, %rsi
ffffffff8137a9d0: 83 f8 7e             	cmpl	$0x7e, %eax
ffffffff8137a9d3: 0f 8e 1b 05 00 00    	jle	0xffffffff8137aef4 <do_jit+0x24e4>
ffffffff8137a9d9: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137a9de: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137a9e3: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137a9e8: 81 fe 81 00 00 00    	cmpl	$0x81, %esi
ffffffff8137a9ee: 0f 84 f9 ef ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137a9f4: 83 fe 7f             	cmpl	$0x7f, %esi
ffffffff8137a9f7: 0f 85 81 ea ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137a9fd: e9 2b 0a 00 00       	jmp	0xffffffff8137b42d <do_jit+0x2a1d>
ffffffff8137aa02: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137aa06: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137aa0b: 31 c0                	xorl	%eax, %eax
ffffffff8137aa0d: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137aa10: 15 48 c7 00 00       	adcl	$0xc748, %eax           # imm = 0xC748
ffffffff8137aa15: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137aa1a: 66 89 01             	movw	%ax, (%rcx)
ffffffff8137aa1d: e9 f8 0b 00 00       	jmp	0xffffffff8137b61a <do_jit+0x2c0a>
ffffffff8137aa22: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137aa27: 48 89 c6             	movq	%rax, %rsi
ffffffff8137aa2a: 83 c0 c3             	addl	$-0x3d, %eax
ffffffff8137aa2d: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137aa35: 49 89 d1             	movq	%rdx, %r9
ffffffff8137aa38: 45 89 da             	movl	%r11d, %r10d
ffffffff8137aa3b: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137aa3e: 0f 82 a2 ea ff ff    	jb	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137aa44: 83 fe 41             	cmpl	$0x41, %esi
ffffffff8137aa47: 0f 84 a0 ef ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137aa4d: 83 fe 3f             	cmpl	$0x3f, %esi
ffffffff8137aa50: 0f 85 28 ea ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137aa56: e9 b8 f2 ff ff       	jmp	0xffffffff81379d13 <do_jit+0x1303>
ffffffff8137aa5b: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137aa60: 48 89 c6             	movq	%rax, %rsi
ffffffff8137aa63: 49 89 d1             	movq	%rdx, %r9
ffffffff8137aa66: 45 89 da             	movl	%r11d, %r10d
ffffffff8137aa69: 83 fe 49             	cmpl	$0x49, %esi
ffffffff8137aa6c: 0f 84 7b ef ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137aa72: 83 fe 4c             	cmpl	$0x4c, %esi
ffffffff8137aa75: 0f 85 03 ea ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137aa7b: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137aa80: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137aa85: 41 f6 d7             	notb	%r15b
ffffffff8137aa88: c4 e2 71 f7 c0       	shlxl	%ecx, %eax, %eax
ffffffff8137aa8d: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137aa91: 0f 85 8e 04 00 00    	jne	0xffffffff8137af25 <do_jit+0x2515>
ffffffff8137aa97: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137aa9c: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137aaa1: 0f 95 c0             	setne	%al
ffffffff8137aaa4: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff8137aaa8: 0f 92 c1             	setb	%cl
ffffffff8137aaab: c0 e0 02             	shlb	$0x2, %al
ffffffff8137aaae: 08 c8                	orb	%cl, %al
ffffffff8137aab0: 0c 48                	orb	$0x48, %al
ffffffff8137aab2: e9 43 08 00 00       	jmp	0xffffffff8137b2fa <do_jit+0x28ea>
ffffffff8137aab7: 41 80 e7 07          	andb	$0x7, %r15b
ffffffff8137aabb: b0 48                	movb	$0x48, %al
ffffffff8137aabd: 41 80 ff 05          	cmpb	$0x5, %r15b
ffffffff8137aac1: 74 0d                	je	0xffffffff8137aad0 <do_jit+0x20c0>
ffffffff8137aac3: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137aac8: b0 40                	movb	$0x40, %al
ffffffff8137aaca: 44 0f a3 d9          	btl	%r11d, %ecx
ffffffff8137aace: 73 13                	jae	0xffffffff8137aae3 <do_jit+0x20d3>
ffffffff8137aad0: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137aad5: 44 0f a3 d9          	btl	%r11d, %ecx
ffffffff8137aad9: 0f 92 c1             	setb	%cl
ffffffff8137aadc: 08 c1                	orb	%al, %cl
ffffffff8137aade: 88 0a                	movb	%cl, (%rdx)
ffffffff8137aae0: 48 ff c2             	incq	%rdx
ffffffff8137aae3: 44 89 d8             	movl	%r11d, %eax
ffffffff8137aae6: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137aaed: 48 8d 4a 02          	leaq	0x2(%rdx), %rcx
ffffffff8137aaf1: 49 89 d1             	movq	%rdx, %r9
ffffffff8137aaf4: c1 e0 08             	shll	$0x8, %eax
ffffffff8137aaf7: 05 f7 c0 ff ff       	addl	$0xffffc0f7, %eax       # imm = 0xFFFFC0F7
ffffffff8137aafc: 66 89 02             	movw	%ax, (%rdx)
ffffffff8137aaff: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff8137ab04: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137ab0c: 89 42 02             	movl	%eax, 0x2(%rdx)
ffffffff8137ab0f: e9 b7 f4 ff ff       	jmp	0xffffffff81379fcb <do_jit+0x15bb>
ffffffff8137ab14: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137ab19: 0f 95 c1             	setne	%cl
ffffffff8137ab1c: c0 e1 02             	shlb	$0x2, %cl
ffffffff8137ab1f: 80 c9 40             	orb	$0x40, %cl
ffffffff8137ab22: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137ab27: 41 89 d2             	movl	%edx, %r10d
ffffffff8137ab2a: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137ab2f: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137ab34: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137ab39: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137ab41: 0f a3 d0             	btl	%edx, %eax
ffffffff8137ab44: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137ab49: 0f 92 c0             	setb	%al
ffffffff8137ab4c: 08 c8                	orb	%cl, %al
ffffffff8137ab4e: e9 c0 e7 ff ff       	jmp	0xffffffff81379313 <do_jit+0x903>
ffffffff8137ab53: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137ab58: 48 89 c6             	movq	%rax, %rsi
ffffffff8137ab5b: 49 89 d1             	movq	%rdx, %r9
ffffffff8137ab5e: 45 89 da             	movl	%r11d, %r10d
ffffffff8137ab61: 83 fe 21             	cmpl	$0x21, %esi
ffffffff8137ab64: 0f 84 83 ee ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137ab6a: 83 fe 24             	cmpl	$0x24, %esi
ffffffff8137ab6d: 0f 85 0b e9 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137ab73: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137ab78: 41 f6 d7             	notb	%r15b
ffffffff8137ab7b: c4 e2 11 f7 c0       	shlxl	%r13d, %eax, %eax
ffffffff8137ab80: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137ab84: 0f 85 bd 03 00 00    	jne	0xffffffff8137af47 <do_jit+0x2537>
ffffffff8137ab8a: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137ab8f: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137ab94: 0f 95 c0             	setne	%al
ffffffff8137ab97: 44 0f a3 d9          	btl	%r11d, %ecx
ffffffff8137ab9b: 0f 92 c1             	setb	%cl
ffffffff8137ab9e: c0 e0 02             	shlb	$0x2, %al
ffffffff8137aba1: 08 c8                	orb	%cl, %al
ffffffff8137aba3: 0c 48                	orb	$0x48, %al
ffffffff8137aba5: e9 b2 03 00 00       	jmp	0xffffffff8137af5c <do_jit+0x254c>
ffffffff8137abaa: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137abaf: 48 89 c6             	movq	%rax, %rsi
ffffffff8137abb2: 83 c0 eb             	addl	$-0x15, %eax
ffffffff8137abb5: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137abbd: 49 89 d1             	movq	%rdx, %r9
ffffffff8137abc0: 45 89 da             	movl	%r11d, %r10d
ffffffff8137abc3: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137abc6: 0f 82 76 ed ff ff    	jb	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137abcc: 83 fe 14             	cmpl	$0x14, %esi
ffffffff8137abcf: 0f 85 a9 e8 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137abd5: e9 49 e3 ff ff       	jmp	0xffffffff81378f23 <do_jit+0x513>
ffffffff8137abda: 48 8b 5c 24 10       	movq	0x10(%rsp), %rbx
ffffffff8137abdf: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137abe7: 4c 89 e2             	movq	%r12, %rdx
ffffffff8137abea: 0f b6 73 01          	movzbl	0x1(%rbx), %esi
ffffffff8137abee: 83 e6 0f             	andl	$0xf, %esi
ffffffff8137abf1: e8 0a 94 26 00       	callq	0xffffffff815e4000 <emit_indirect_jump>
ffffffff8137abf6: 48 89 df             	movq	%rbx, %rdi
ffffffff8137abf9: e9 5b 17 00 00       	jmp	0xffffffff8137c359 <do_jit+0x3949>
ffffffff8137abfe: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137ac03: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137ac08: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137ac0b: 0f 83 98 03 00 00    	jae	0xffffffff8137afa9 <do_jit+0x2599>
ffffffff8137ac11: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137ac16: 0f 95 c1             	setne	%cl
ffffffff8137ac19: c0 e1 02             	shlb	$0x2, %cl
ffffffff8137ac1c: 80 c9 40             	orb	$0x40, %cl
ffffffff8137ac1f: e9 8e 03 00 00       	jmp	0xffffffff8137afb2 <do_jit+0x25a2>
ffffffff8137ac24: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137ac29: 0f 95 c1             	setne	%cl
ffffffff8137ac2c: c0 e1 02             	shlb	$0x2, %cl
ffffffff8137ac2f: 80 c9 40             	orb	$0x40, %cl
ffffffff8137ac32: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137ac37: 41 89 d2             	movl	%edx, %r10d
ffffffff8137ac3a: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137ac3f: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137ac44: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137ac4c: 0f a3 d0             	btl	%edx, %eax
ffffffff8137ac4f: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137ac54: 0f 92 c0             	setb	%al
ffffffff8137ac57: 08 c8                	orb	%cl, %al
ffffffff8137ac59: e9 c5 e8 ff ff       	jmp	0xffffffff81379523 <do_jit+0xb13>
ffffffff8137ac5e: 41 89 d2             	movl	%edx, %r10d
ffffffff8137ac61: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137ac66: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137ac6b: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137ac70: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137ac78: e9 ac e8 ff ff       	jmp	0xffffffff81379529 <do_jit+0xb19>
ffffffff8137ac7d: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137ac82: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137ac87: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137ac8c: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137ac94: 4d 89 d1             	movq	%r10, %r9
ffffffff8137ac97: e9 f9 ec ff ff       	jmp	0xffffffff81379995 <do_jit+0xf85>
ffffffff8137ac9c: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137aca0: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137aca5: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137acaa: 66 b9 f7 f0          	movw	$0xf0f7, %cx            # imm = 0xF0F7
ffffffff8137acae: e9 0a f2 ff ff       	jmp	0xffffffff81379ebd <do_jit+0x14ad>
ffffffff8137acb3: 83 f8 0c             	cmpl	$0xc, %eax
ffffffff8137acb6: 0f 85 d3 e7 ff ff    	jne	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137acbc: b0 7e                	movb	$0x7e, %al
ffffffff8137acbe: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137acc3: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137acc8: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137accd: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137acd5: e9 99 e6 ff ff       	jmp	0xffffffff81379373 <do_jit+0x963>
ffffffff8137acda: 3d c6 00 00 00       	cmpl	$0xc6, %eax
ffffffff8137acdf: 0f 8f 25 03 00 00    	jg	0xffffffff8137b00a <do_jit+0x25fa>
ffffffff8137ace5: 3d c1 00 00 00       	cmpl	$0xc1, %eax
ffffffff8137acea: 0f 8f 5b 03 00 00    	jg	0xffffffff8137b04b <do_jit+0x263b>
ffffffff8137acf0: 3d bc 00 00 00       	cmpl	$0xbc, %eax
ffffffff8137acf5: 0f 8f 85 03 00 00    	jg	0xffffffff8137b080 <do_jit+0x2670>
ffffffff8137acfb: 48 8b 4c 24 10       	movq	0x10(%rsp), %rcx
ffffffff8137ad00: 48 89 c6             	movq	%rax, %rsi
ffffffff8137ad03: 81 fe bb 00 00 00    	cmpl	$0xbb, %esi
ffffffff8137ad09: 0f 84 b1 0f 00 00    	je	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137ad0f: 81 fe bc 00 00 00    	cmpl	$0xbc, %esi
ffffffff8137ad15: 0f 85 63 e7 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137ad1b: 0f b7 41 02          	movzwl	0x2(%rcx), %eax
ffffffff8137ad1f: e9 8b 07 00 00       	jmp	0xffffffff8137b4af <do_jit+0x2a9f>
ffffffff8137ad24: 48 8b 54 24 10       	movq	0x10(%rsp), %rdx
ffffffff8137ad29: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137ad2e: 48 89 c6             	movq	%rax, %rsi
ffffffff8137ad31: 81 fe b9 00 00 00    	cmpl	$0xb9, %esi
ffffffff8137ad37: 0f 84 83 0f 00 00    	je	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137ad3d: 81 fe ba 00 00 00    	cmpl	$0xba, %esi
ffffffff8137ad43: 0f 85 35 e7 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137ad49: e9 86 01 00 00       	jmp	0xffffffff8137aed4 <do_jit+0x24c4>
ffffffff8137ad4e: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137ad52: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137ad57: c4 e2 13 f7 c0       	shrxl	%r13d, %eax, %eax
ffffffff8137ad5c: 83 e0 01             	andl	$0x1, %eax
ffffffff8137ad5f: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137ad66: c1 e1 10             	shll	$0x10, %ecx
ffffffff8137ad69: 81 c1 00 00 c0 00    	addl	$0xc00000, %ecx         # imm = 0xC00000
ffffffff8137ad6f: 81 e1 00 00 ff 00    	andl	$0xff0000, %ecx         # imm = 0xFF0000
ffffffff8137ad75: 8d 84 08 48 c7 00 00 	leal	0xc748(%rax,%rcx), %eax
ffffffff8137ad7c: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137ad81: 89 01                	movl	%eax, (%rcx)
ffffffff8137ad83: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff8137ad88: 89 41 03             	movl	%eax, 0x3(%rcx)
ffffffff8137ad8b: 48 83 c1 07          	addq	$0x7, %rcx
ffffffff8137ad8f: eb 48                	jmp	0xffffffff8137add9 <do_jit+0x23c9>
ffffffff8137ad91: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137ad96: 74 20                	je	0xffffffff8137adb8 <do_jit+0x23a8>
ffffffff8137ad98: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137ad9c: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137ada1: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137ada6: 0f a3 c8             	btl	%ecx, %eax
ffffffff8137ada9: 0f 92 c0             	setb	%al
ffffffff8137adac: 0c 44                	orb	$0x44, %al
ffffffff8137adae: 88 02                	movb	%al, (%rdx)
ffffffff8137adb0: 48 ff c2             	incq	%rdx
ffffffff8137adb3: 48 89 54 24 18       	movq	%rdx, 0x18(%rsp)
ffffffff8137adb8: 8b 44 24 0c          	movl	0xc(%rsp), %eax
ffffffff8137adbc: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137adc1: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137adc8: c1 e0 08             	shll	$0x8, %eax
ffffffff8137adcb: 8d 84 c0 31 c0 ff ff 	leal	-0x3fcf(%rax,%rax,8), %eax
ffffffff8137add2: 66 89 01             	movw	%ax, (%rcx)
ffffffff8137add5: 48 83 c1 02          	addq	$0x2, %rcx
ffffffff8137add9: 48 89 c8             	movq	%rcx, %rax
ffffffff8137addc: e9 7e 14 00 00       	jmp	0xffffffff8137c25f <do_jit+0x384f>
ffffffff8137ade1: 83 f8 72             	cmpl	$0x72, %eax
ffffffff8137ade4: 0f 8f bc 03 00 00    	jg	0xffffffff8137b1a6 <do_jit+0x2796>
ffffffff8137adea: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137adef: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137adf4: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137adf9: 48 89 c6             	movq	%rax, %rsi
ffffffff8137adfc: 83 fe 71             	cmpl	$0x71, %esi
ffffffff8137adff: 0f 84 e8 eb ff ff    	je	0xffffffff813799ed <do_jit+0xfdd>
ffffffff8137ae05: 83 fe 72             	cmpl	$0x72, %esi
ffffffff8137ae08: 0f 85 70 e6 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137ae0e: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137ae13: 44 0f a3 d0          	btl	%r10d, %eax
ffffffff8137ae17: 0f 83 b9 03 00 00    	jae	0xffffffff8137b1d6 <do_jit+0x27c6>
ffffffff8137ae1d: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137ae22: 66 c7 00 41 c6       	movw	$0xc641, (%rax)         # imm = 0xC641
ffffffff8137ae27: e9 ee 07 00 00       	jmp	0xffffffff8137b61a <do_jit+0x2c0a>
ffffffff8137ae2c: 83 f8 6a             	cmpl	$0x6a, %eax
ffffffff8137ae2f: 0f 84 b3 03 00 00    	je	0xffffffff8137b1e8 <do_jit+0x27d8>
ffffffff8137ae35: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137ae3a: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137ae3f: 48 89 c6             	movq	%rax, %rsi
ffffffff8137ae42: 83 fe 6b             	cmpl	$0x6b, %esi
ffffffff8137ae45: 0f 85 33 e6 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137ae4b: e9 5a 07 00 00       	jmp	0xffffffff8137b5aa <do_jit+0x2b9a>
ffffffff8137ae50: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137ae55: c6 00 c7             	movb	$-0x39, (%rax)
ffffffff8137ae58: e9 81 03 00 00       	jmp	0xffffffff8137b1de <do_jit+0x27ce>
ffffffff8137ae5d: 3d 95 00 00 00       	cmpl	$0x95, %eax
ffffffff8137ae62: 0f 85 a7 03 00 00    	jne	0xffffffff8137b20f <do_jit+0x27ff>
ffffffff8137ae68: f6 84 24 a8 00 00 00 01      	testb	$0x1, 0xa8(%rsp)
ffffffff8137ae70: 0f 84 bc 03 00 00    	je	0xffffffff8137b232 <do_jit+0x2822>
ffffffff8137ae76: 48 8b 45 10          	movq	0x10(%rbp), %rax
ffffffff8137ae7a: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137ae7f: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137ae84: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137ae89: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137ae8e: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137ae96: 8b 00                	movl	(%rax), %eax
ffffffff8137ae98: 49 63 d4             	movslq	%r12d, %rdx
ffffffff8137ae9b: 41 2b 04 97          	subl	(%r15,%rdx,4), %eax
ffffffff8137ae9f: e9 46 e1 ff ff       	jmp	0xffffffff81378fea <do_jit+0x5da>
ffffffff8137aea4: 48 89 c6             	movq	%rax, %rsi
ffffffff8137aea7: 3d a2 00 00 00       	cmpl	$0xa2, %eax
ffffffff8137aeac: 0f 8f fd 03 00 00    	jg	0xffffffff8137b2af <do_jit+0x289f>
ffffffff8137aeb2: 48 8b 54 24 10       	movq	0x10(%rsp), %rdx
ffffffff8137aeb7: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137aebc: 81 fe a1 00 00 00    	cmpl	$0xa1, %esi
ffffffff8137aec2: 0f 84 f8 0d 00 00    	je	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137aec8: 81 fe a2 00 00 00    	cmpl	$0xa2, %esi
ffffffff8137aece: 0f 85 aa e5 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137aed4: 0f bf 4a 02          	movswl	0x2(%rdx), %ecx
ffffffff8137aed8: 44 8b 42 04          	movl	0x4(%rdx), %r8d
ffffffff8137aedc: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137aee4: 83 e6 18             	andl	$0x18, %esi
ffffffff8137aee7: 44 89 d2             	movl	%r10d, %edx
ffffffff8137aeea: e8 e1 95 26 00       	callq	0xffffffff815e44d0 <emit_st_r12>
ffffffff8137aeef: e9 54 11 00 00       	jmp	0xffffffff8137c048 <do_jit+0x3638>
ffffffff8137aef4: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137aef9: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137aefe: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137af03: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137af0b: 83 fe 7b             	cmpl	$0x7b, %esi
ffffffff8137af0e: 0f 84 96 06 00 00    	je	0xffffffff8137b5aa <do_jit+0x2b9a>
ffffffff8137af14: 83 fe 7c             	cmpl	$0x7c, %esi
ffffffff8137af17: 0f 84 10 05 00 00    	je	0xffffffff8137b42d <do_jit+0x2a1d>
ffffffff8137af1d: 8d 46 83             	leal	-0x7d(%rsi), %eax
ffffffff8137af20: e9 45 0d 00 00       	jmp	0xffffffff8137bc6a <do_jit+0x325a>
ffffffff8137af25: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137af2a: 44 0f a3 d1          	btl	%r10d, %ecx
ffffffff8137af2e: 0f 83 af 03 00 00    	jae	0xffffffff8137b2e3 <do_jit+0x28d3>
ffffffff8137af34: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137af39: 0f 95 c1             	setne	%cl
ffffffff8137af3c: c0 e1 02             	shlb	$0x2, %cl
ffffffff8137af3f: 80 c9 40             	orb	$0x40, %cl
ffffffff8137af42: e9 a5 03 00 00       	jmp	0xffffffff8137b2ec <do_jit+0x28dc>
ffffffff8137af47: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137af4c: 74 13                	je	0xffffffff8137af61 <do_jit+0x2551>
ffffffff8137af4e: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137af53: 44 0f a3 d8          	btl	%r11d, %eax
ffffffff8137af57: 0f 92 c0             	setb	%al
ffffffff8137af5a: 0c 44                	orb	$0x44, %al
ffffffff8137af5c: 88 02                	movb	%al, (%rdx)
ffffffff8137af5e: 48 ff c2             	incq	%rdx
ffffffff8137af61: 48 8b 74 24 48       	movq	0x48(%rsp), %rsi
ffffffff8137af66: 44 89 d8             	movl	%r11d, %eax
ffffffff8137af69: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137af70: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137af78: 40 0f be ce          	movsbl	%sil, %ecx
ffffffff8137af7c: 39 f1                	cmpl	%esi, %ecx
ffffffff8137af7e: 0f 85 cf 03 00 00    	jne	0xffffffff8137b353 <do_jit+0x2943>
ffffffff8137af84: 48 8b 4c 24 48       	movq	0x48(%rsp), %rcx
ffffffff8137af89: 8d 04 c0             	leal	(%rax,%rax,8), %eax
ffffffff8137af8c: c1 e0 08             	shll	$0x8, %eax
ffffffff8137af8f: 05 00 c0 00 00       	addl	$0xc000, %eax           # imm = 0xC000
ffffffff8137af94: 0f b7 c0             	movzwl	%ax, %eax
ffffffff8137af97: c1 e1 10             	shll	$0x10, %ecx
ffffffff8137af9a: 8d 44 08 6b          	leal	0x6b(%rax,%rcx), %eax
ffffffff8137af9e: 89 02                	movl	%eax, (%rdx)
ffffffff8137afa0: 48 83 c2 03          	addq	$0x3, %rdx
ffffffff8137afa4: e9 d2 12 00 00       	jmp	0xffffffff8137c27b <do_jit+0x386b>
ffffffff8137afa9: b1 44                	movb	$0x44, %cl
ffffffff8137afab: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137afb0: 74 18                	je	0xffffffff8137afca <do_jit+0x25ba>
ffffffff8137afb2: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137afb7: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137afbc: 0f a3 d0             	btl	%edx, %eax
ffffffff8137afbf: 0f 92 c0             	setb	%al
ffffffff8137afc2: 08 c8                	orb	%cl, %al
ffffffff8137afc4: 41 88 01             	movb	%al, (%r9)
ffffffff8137afc7: 49 ff c1             	incq	%r9
ffffffff8137afca: 8b 44 24 38          	movl	0x38(%rsp), %eax
ffffffff8137afce: 44 89 d1             	movl	%r10d, %ecx
ffffffff8137afd1: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137afd8: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff8137afe0: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137afe7: c1 e1 13             	shll	$0x13, %ecx
ffffffff8137afea: c1 e0 10             	shll	$0x10, %eax
ffffffff8137afed: 8d 84 08 00 00 c0 00 	leal	0xc00000(%rax,%rcx), %eax
ffffffff8137aff4: 25 00 00 ff 00       	andl	$0xff0000, %eax         # imm = 0xFF0000
ffffffff8137aff9: 0d 0f af 00 00       	orl	$0xaf0f, %eax           # imm = 0xAF0F
ffffffff8137affe: 41 89 01             	movl	%eax, (%r9)
ffffffff8137b001: 49 83 c1 03          	addq	$0x3, %r9
ffffffff8137b005: e9 02 e9 ff ff       	jmp	0xffffffff8137990c <do_jit+0xefc>
ffffffff8137b00a: 3d d4 00 00 00       	cmpl	$0xd4, %eax
ffffffff8137b00f: 0f 8f 68 03 00 00    	jg	0xffffffff8137b37d <do_jit+0x296d>
ffffffff8137b015: 3d cc 00 00 00       	cmpl	$0xcc, %eax
ffffffff8137b01a: 0f 8f b1 03 00 00    	jg	0xffffffff8137b3d1 <do_jit+0x29c1>
ffffffff8137b020: 3d ca 00 00 00       	cmpl	$0xca, %eax
ffffffff8137b025: 0f 8f e8 03 00 00    	jg	0xffffffff8137b413 <do_jit+0x2a03>
ffffffff8137b02b: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b02e: 81 fe c7 00 00 00    	cmpl	$0xc7, %esi
ffffffff8137b034: 0f 84 96 09 00 00    	je	0xffffffff8137b9d0 <do_jit+0x2fc0>
ffffffff8137b03a: 81 fe c9 00 00 00    	cmpl	$0xc9, %esi
ffffffff8137b040: 0f 85 38 e4 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b046: e9 75 0c 00 00       	jmp	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137b04b: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b050: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b055: 48 89 c1             	movq	%rax, %rcx
ffffffff8137b058: 81 f9 c4 00 00 00    	cmpl	$0xc4, %ecx
ffffffff8137b05e: 0f 8f de e8 ff ff    	jg	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137b064: 81 f9 c2 00 00 00    	cmpl	$0xc2, %ecx
ffffffff8137b06a: 0f 85 f0 03 00 00    	jne	0xffffffff8137b460 <do_jit+0x2a50>
ffffffff8137b070: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b075: c7 00 0f ae e8 00    	movl	$0xe8ae0f, (%rax)       # imm = 0xE8AE0F
ffffffff8137b07b: e9 db 11 00 00       	jmp	0xffffffff8137c25b <do_jit+0x384b>
ffffffff8137b080: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137b085: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b08a: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b08f: 8d 90 43 ff ff ff    	leal	-0xbd(%rax), %edx
ffffffff8137b095: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137b09d: 83 fa 02             	cmpl	$0x2, %edx
ffffffff8137b0a0: 0f 82 40 e4 ff ff    	jb	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137b0a6: 48 89 c1             	movq	%rax, %rcx
ffffffff8137b0a9: 81 f9 bf 00 00 00    	cmpl	$0xbf, %ecx
ffffffff8137b0af: 0f 85 c7 03 00 00    	jne	0xffffffff8137b47c <do_jit+0x2a6c>
ffffffff8137b0b5: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137b0ba: 0f b7 40 02          	movzwl	0x2(%rax), %eax
ffffffff8137b0be: 3d ff ff 00 00       	cmpl	$0xffff, %eax           # imm = 0xFFFF
ffffffff8137b0c3: 0f 84 c7 03 00 00    	je	0xffffffff8137b490 <do_jit+0x2a80>
ffffffff8137b0c9: 83 f8 01             	cmpl	$0x1, %eax
ffffffff8137b0cc: 0f 85 dd 03 00 00    	jne	0xffffffff8137b4af <do_jit+0x2a9f>
ffffffff8137b0d2: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137b0d7: 81 78 04 00 00 01 00 	cmpl	$0x10000, 0x4(%rax)     # imm = 0x10000
ffffffff8137b0de: 0f 85 f8 03 00 00    	jne	0xffffffff8137b4dc <do_jit+0x2acc>
ffffffff8137b0e4: 48 8b 44 24 38       	movq	0x38(%rsp), %rax
ffffffff8137b0e9: 3b 44 24 0c          	cmpl	0xc(%rsp), %eax
ffffffff8137b0ed: 74 23                	je	0xffffffff8137b112 <do_jit+0x2702>
ffffffff8137b0ef: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137b0f3: 48 8d 9c 24 c0 00 00 00      	leaq	0xc0(%rsp), %rbx
ffffffff8137b0fb: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137b100: 31 f6                	xorl	%esi, %esi
ffffffff8137b102: 48 89 df             	movq	%rbx, %rdi
ffffffff8137b105: e8 f6 8d 26 00       	callq	0xffffffff815e3f00 <emit_mov_reg>
ffffffff8137b10a: 48 8b 03             	movq	(%rbx), %rax
ffffffff8137b10d: 48 89 44 24 18       	movq	%rax, 0x18(%rsp)
ffffffff8137b112: 48 8b bc 24 b0 00 00 00      	movq	0xb0(%rsp), %rdi
ffffffff8137b11a: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b11f: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b124: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137b129: 48 c1 ef 20          	shrq	$0x20, %rdi
ffffffff8137b12d: 44 0f a3 d0          	btl	%r10d, %eax
ffffffff8137b131: 49 8d 41 01          	leaq	0x1(%r9), %rax
ffffffff8137b135: 0f 92 c1             	setb	%cl
ffffffff8137b138: 8d 51 48             	leal	0x48(%rcx), %edx
ffffffff8137b13b: 41 88 11             	movb	%dl, (%r9)
ffffffff8137b13e: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137b146: 44 89 d0             	movl	%r10d, %eax
ffffffff8137b149: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137b150: 89 c6                	movl	%eax, %esi
ffffffff8137b152: c1 e6 08             	shll	$0x8, %esi
ffffffff8137b155: 44 8d 86 00 e0 00 00 	leal	0xe000(%rsi), %r8d
ffffffff8137b15c: 41 81 c8 c1 00 20 00 	orl	$0x2000c1, %r8d         # imm = 0x2000C1
ffffffff8137b163: 41 81 e0 c1 ff 20 00 	andl	$0x20ffc1, %r8d         # imm = 0x20FFC1
ffffffff8137b16a: 45 89 41 01          	movl	%r8d, 0x1(%r9)
ffffffff8137b16e: 41 88 51 04          	movb	%dl, 0x4(%r9)
ffffffff8137b172: 45 85 d2             	testl	%r10d, %r10d
ffffffff8137b175: 0f 84 8f 03 00 00    	je	0xffffffff8137b50a <do_jit+0x2afa>
ffffffff8137b17b: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b180: 44 8d 86 81 c8 ff ff 	leal	-0x377f(%rsi), %r8d
ffffffff8137b187: 4d 8d 51 07          	leaq	0x7(%r9), %r10
ffffffff8137b18b: 66 45 89 41 05       	movw	%r8w, 0x5(%r9)
ffffffff8137b190: 4c 89 94 24 c0 00 00 00      	movq	%r10, 0xc0(%rsp)
ffffffff8137b198: 41 89 79 07          	movl	%edi, 0x7(%r9)
ffffffff8137b19c: bf 0b 00 00 00       	movl	$0xb, %edi
ffffffff8137b1a1: e9 83 03 00 00       	jmp	0xffffffff8137b529 <do_jit+0x2b19>
ffffffff8137b1a6: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b1a9: 83 f8 74             	cmpl	$0x74, %eax
ffffffff8137b1ac: 0f 8e e5 03 00 00    	jle	0xffffffff8137b597 <do_jit+0x2b87>
ffffffff8137b1b2: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b1b7: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b1bc: 83 c0 8b             	addl	$-0x75, %eax
ffffffff8137b1bf: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137b1c2: 0f 82 7a e7 ff ff    	jb	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137b1c8: 83 fe 77             	cmpl	$0x77, %esi
ffffffff8137b1cb: 0f 85 ad e2 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b1d1: e9 fa 07 00 00       	jmp	0xffffffff8137b9d0 <do_jit+0x2fc0>
ffffffff8137b1d6: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b1db: c6 00 c6             	movb	$-0x3a, (%rax)
ffffffff8137b1de: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137b1e3: e9 37 04 00 00       	jmp	0xffffffff8137b61f <do_jit+0x2c0f>
ffffffff8137b1e8: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137b1ec: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137b1f1: 0f a3 c8             	btl	%ecx, %eax
ffffffff8137b1f4: 0f 83 16 04 00 00    	jae	0xffffffff8137b610 <do_jit+0x2c00>
ffffffff8137b1fa: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b1ff: c7 00 66 41 c7 00    	movl	$0xc74166, (%rax)       # imm = 0xC74166
ffffffff8137b205: b8 03 00 00 00       	movl	$0x3, %eax
ffffffff8137b20a: e9 10 04 00 00       	jmp	0xffffffff8137b61f <do_jit+0x2c0f>
ffffffff8137b20f: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137b214: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b219: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b21e: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b221: 81 fe 94 00 00 00    	cmpl	$0x94, %esi
ffffffff8137b227: 0f 85 51 e2 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b22d: e9 e1 ea ff ff       	jmp	0xffffffff81379d13 <do_jit+0x1303>
ffffffff8137b232: 48 8b 45 10          	movq	0x10(%rbp), %rax
ffffffff8137b236: 48 8b 4c 24 30       	movq	0x30(%rsp), %rcx
ffffffff8137b23b: 89 08                	movl	%ecx, (%rax)
ffffffff8137b23d: 48 8b 4c 24 60       	movq	0x60(%rsp), %rcx
ffffffff8137b242: 83 79 08 00          	cmpl	$0x0, 0x8(%rcx)
ffffffff8137b246: 75 2d                	jne	0xffffffff8137b275 <do_jit+0x2865>
ffffffff8137b248: 48 c7 c7 00 94 a4 83 	movq	$-0x7c5b6c00, %rdi      # imm = 0x83A49400
ffffffff8137b24f: be 15 00 00 00       	movl	$0x15, %esi
ffffffff8137b254: e8 c7 3c 06 00       	callq	0xffffffff813def20 <ns_capable_noaudit>
ffffffff8137b259: 84 c0                	testb	%al, %al
ffffffff8137b25b: 75 18                	jne	0xffffffff8137b275 <do_jit+0x2865>
ffffffff8137b25d: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137b265: 4c 89 e6             	movq	%r12, %rsi
ffffffff8137b268: e8 03 9e 26 00       	callq	0xffffffff815e5070 <emit_spectre_bhb_barrier>
ffffffff8137b26d: 85 c0                	testl	%eax, %eax
ffffffff8137b26f: 0f 85 15 e2 ff ff    	jne	0xffffffff8137948a <do_jit+0xa7a>
ffffffff8137b275: 48 8b 84 24 c0 00 00 00      	movq	0xc0(%rsp), %rax
ffffffff8137b27d: 66 83 7c 24 6c 00    	cmpw	$0x0, 0x6c(%rsp)
ffffffff8137b283: 0f 84 1a 04 00 00    	je	0xffffffff8137b6a3 <do_jit+0x2c93>
ffffffff8137b289: 8b 54 24 6c          	movl	0x6c(%rsp), %edx
ffffffff8137b28d: 0f b7 ca             	movzwl	%dx, %ecx
ffffffff8137b290: 66 83 fa 7f          	cmpw	$0x7f, %dx
ffffffff8137b294: 0f 87 f0 03 00 00    	ja	0xffffffff8137b68a <do_jit+0x2c7a>
ffffffff8137b29a: c1 e1 18             	shll	$0x18, %ecx
ffffffff8137b29d: 81 c9 48 83 c4 00    	orl	$0xc48348, %ecx         # imm = 0xC48348
ffffffff8137b2a3: 89 08                	movl	%ecx, (%rax)
ffffffff8137b2a5: b9 04 00 00 00       	movl	$0x4, %ecx
ffffffff8137b2aa: e9 e9 03 00 00       	jmp	0xffffffff8137b698 <do_jit+0x2c88>
ffffffff8137b2af: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137b2b4: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b2b9: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b2be: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137b2c6: 81 fe a3 00 00 00    	cmpl	$0xa3, %esi
ffffffff8137b2cc: 0f 84 ee 09 00 00    	je	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137b2d2: 81 fe a4 00 00 00    	cmpl	$0xa4, %esi
ffffffff8137b2d8: 0f 85 a0 e1 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b2de: e9 40 dc ff ff       	jmp	0xffffffff81378f23 <do_jit+0x513>
ffffffff8137b2e3: b1 44                	movb	$0x44, %cl
ffffffff8137b2e5: a9 a0 d3 00 00       	testl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137b2ea: 74 14                	je	0xffffffff8137b300 <do_jit+0x28f0>
ffffffff8137b2ec: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137b2f1: 44 0f a3 d0          	btl	%r10d, %eax
ffffffff8137b2f5: 0f 92 c0             	setb	%al
ffffffff8137b2f8: 08 c8                	orb	%cl, %al
ffffffff8137b2fa: 41 88 01             	movb	%al, (%r9)
ffffffff8137b2fd: 49 ff c1             	incq	%r9
ffffffff8137b300: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137b305: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff8137b30d: 8b 54 24 38          	movl	0x38(%rsp), %edx
ffffffff8137b311: 44 89 d1             	movl	%r10d, %ecx
ffffffff8137b314: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137b31b: 0f b6 07             	movzbl	(%rdi), %eax
ffffffff8137b31e: 8b 14 95 10 29 f2 82 	movl	-0x7d0dd6f0(,%rdx,4), %edx
ffffffff8137b325: c1 e1 08             	shll	$0x8, %ecx
ffffffff8137b328: 83 e0 f0             	andl	$-0x10, %eax
ffffffff8137b32b: c1 e2 0b             	shll	$0xb, %edx
ffffffff8137b32e: 0f b6 80 80 29 f2 82 	movzbl	-0x7d0dd680(%rax), %eax
ffffffff8137b335: 09 c1                	orl	%eax, %ecx
ffffffff8137b337: 8d 84 0a 00 c0 ff ff 	leal	-0x4000(%rdx,%rcx), %eax
ffffffff8137b33e: 66 41 89 01          	movw	%ax, (%r9)
ffffffff8137b342: 49 83 c1 02          	addq	$0x2, %r9
ffffffff8137b346: 4c 89 8c 24 c0 00 00 00      	movq	%r9, 0xc0(%rsp)
ffffffff8137b34e: e9 06 10 00 00       	jmp	0xffffffff8137c359 <do_jit+0x3949>
ffffffff8137b353: c1 e0 08             	shll	$0x8, %eax
ffffffff8137b356: 48 8d 4a 02          	leaq	0x2(%rdx), %rcx
ffffffff8137b35a: 8d 84 c0 69 c0 ff ff 	leal	-0x3f97(%rax,%rax,8), %eax
ffffffff8137b361: 66 89 02             	movw	%ax, (%rdx)
ffffffff8137b364: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff8137b369: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137b371: 89 42 02             	movl	%eax, 0x2(%rdx)
ffffffff8137b374: 48 83 c2 06          	addq	$0x6, %rdx
ffffffff8137b378: e9 fe 0e 00 00       	jmp	0xffffffff8137c27b <do_jit+0x386b>
ffffffff8137b37d: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b382: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b387: 48 89 c1             	movq	%rax, %rcx
ffffffff8137b38a: 81 f9 d7 00 00 00    	cmpl	$0xd7, %ecx
ffffffff8137b390: 0f 8c ac e5 ff ff    	jl	0xffffffff81379942 <do_jit+0xf32>
ffffffff8137b396: 81 f9 e2 00 00 00    	cmpl	$0xe2, %ecx
ffffffff8137b39c: 0f 8f 30 03 00 00    	jg	0xffffffff8137b6d2 <do_jit+0x2cc2>
ffffffff8137b3a2: 3d db 00 00 00       	cmpl	$0xdb, %eax
ffffffff8137b3a7: 0f 8f a2 03 00 00    	jg	0xffffffff8137b74f <do_jit+0x2d3f>
ffffffff8137b3ad: 3d d7 00 00 00       	cmpl	$0xd7, %eax
ffffffff8137b3b2: 0f 84 a2 03 00 00    	je	0xffffffff8137b75a <do_jit+0x2d4a>
ffffffff8137b3b8: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b3bb: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137b3c0: 81 fe db 00 00 00    	cmpl	$0xdb, %esi
ffffffff8137b3c6: 0f 85 b2 e0 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b3cc: e9 a3 00 00 00       	jmp	0xffffffff8137b474 <do_jit+0x2a64>
ffffffff8137b3d1: 3d d0 00 00 00       	cmpl	$0xd0, %eax
ffffffff8137b3d6: 0f 8f 17 04 00 00    	jg	0xffffffff8137b7f3 <do_jit+0x2de3>
ffffffff8137b3dc: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137b3e1: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b3e6: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b3eb: 8d 88 33 ff ff ff    	leal	-0xcd(%rax), %ecx
ffffffff8137b3f1: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137b3f9: 83 f9 02             	cmpl	$0x2, %ecx
ffffffff8137b3fc: 0f 82 e4 e0 ff ff    	jb	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137b402: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b405: 81 fe cf 00 00 00    	cmpl	$0xcf, %esi
ffffffff8137b40b: 0f 85 6d e0 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b411: eb 1a                	jmp	0xffffffff8137b42d <do_jit+0x2a1d>
ffffffff8137b413: 3d cb 00 00 00       	cmpl	$0xcb, %eax
ffffffff8137b418: 0f 84 ec 08 00 00    	je	0xffffffff8137bd0a <do_jit+0x32fa>
ffffffff8137b41e: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b421: 81 fe cc 00 00 00    	cmpl	$0xcc, %esi
ffffffff8137b427: 0f 85 51 e0 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b42d: 48 0f ba 25 12 c3 95 02 28   	btq	$0x28, 0x295c312(%rip) # 0xffffffff83cd7748 <boot_cpu_data+0x50>
ffffffff8137b436: 0f 83 13 04 00 00    	jae	0xffffffff8137b84f <do_jit+0x2e3f>
ffffffff8137b43c: 83 7c 24 38 04       	cmpl	$0x4, 0x38(%rsp)
ffffffff8137b441: 0f 84 08 04 00 00    	je	0xffffffff8137b84f <do_jit+0x2e3f>
ffffffff8137b447: 48 89 c1             	movq	%rax, %rcx
ffffffff8137b44a: 83 e1 f0             	andl	$-0x10, %ecx
ffffffff8137b44d: 81 f9 c0 00 00 00    	cmpl	$0xc0, %ecx
ffffffff8137b453: 0f 85 29 04 00 00    	jne	0xffffffff8137b882 <do_jit+0x2e72>
ffffffff8137b459: b0 02                	movb	$0x2, %al
ffffffff8137b45b: e9 bc 0a 00 00       	jmp	0xffffffff8137bf1c <do_jit+0x350c>
ffffffff8137b460: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b463: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137b468: 81 fe c3 00 00 00    	cmpl	$0xc3, %esi
ffffffff8137b46e: 0f 85 2a 04 00 00    	jne	0xffffffff8137b89e <do_jit+0x2e8e>
ffffffff8137b474: 8b 70 04             	movl	0x4(%rax), %esi
ffffffff8137b477: e9 a2 08 00 00       	jmp	0xffffffff8137bd1e <do_jit+0x330e>
ffffffff8137b47c: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b47f: 81 fe c1 00 00 00    	cmpl	$0xc1, %esi
ffffffff8137b485: 0f 85 f3 df ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b48b: e9 30 08 00 00       	jmp	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137b490: 48 8b 44 24 38       	movq	0x38(%rsp), %rax
ffffffff8137b495: 3b 44 24 0c          	cmpl	0xc(%rsp), %eax
ffffffff8137b499: 0f 85 10 04 00 00    	jne	0xffffffff8137b8af <do_jit+0x2e9f>
ffffffff8137b49f: 8b 44 24 0c          	movl	0xc(%rsp), %eax
ffffffff8137b4a3: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137b4aa: e9 64 04 00 00       	jmp	0xffffffff8137b913 <do_jit+0x2f03>
ffffffff8137b4af: 66 85 c0             	testw	%ax, %ax
ffffffff8137b4b2: 75 2c                	jne	0xffffffff8137b4e0 <do_jit+0x2ad0>
ffffffff8137b4b4: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137b4b8: 41 f6 d7             	notb	%r15b
ffffffff8137b4bb: 31 f6                	xorl	%esi, %esi
ffffffff8137b4bd: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137b4c5: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137b4ca: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137b4ce: 40 0f 94 c6          	sete	%sil
ffffffff8137b4d2: e8 29 8a 26 00       	callq	0xffffffff815e3f00 <emit_mov_reg>
ffffffff8137b4d7: e9 b2 dd ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137b4dc: 66 b8 01 00          	movw	$0x1, %ax
ffffffff8137b4e0: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137b4e4: 41 f6 d7             	notb	%r15b
ffffffff8137b4e7: 31 d2                	xorl	%edx, %edx
ffffffff8137b4e9: 0f bf f0             	movswl	%ax, %esi
ffffffff8137b4ec: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137b4f4: 4c 8b 44 24 38       	movq	0x38(%rsp), %r8
ffffffff8137b4f9: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137b4fd: 0f 94 c2             	sete	%dl
ffffffff8137b500: e8 2b 8d 26 00       	callq	0xffffffff815e4230 <emit_movsx_reg>
ffffffff8137b505: e9 84 dd ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137b50a: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b50f: 4d 8d 41 06          	leaq	0x6(%r9), %r8
ffffffff8137b513: 41 c6 41 05 0d       	movb	$0xd, 0x5(%r9)
ffffffff8137b518: 4c 89 84 24 c0 00 00 00      	movq	%r8, 0xc0(%rsp)
ffffffff8137b520: 41 89 79 06          	movl	%edi, 0x6(%r9)
ffffffff8137b524: bf 0a 00 00 00       	movl	$0xa, %edi
ffffffff8137b529: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137b52e: 81 c6 00 c0 00 00    	addl	$0xc000, %esi           # imm = 0xC000
ffffffff8137b534: 81 e6 00 ff 00 00    	andl	$0xff00, %esi           # imm = 0xFF00
ffffffff8137b53a: 81 ce c1 00 20 00    	orl	$0x2000c1, %esi         # imm = 0x2000C1
ffffffff8137b540: 4d 8d 44 39 01       	leaq	0x1(%r9,%rdi), %r8
ffffffff8137b545: 41 88 50 ff          	movb	%dl, -0x1(%r8)
ffffffff8137b549: 49 8d 54 39 04       	leaq	0x4(%r9,%rdi), %rdx
ffffffff8137b54e: 4c 89 84 24 c0 00 00 00      	movq	%r8, 0xc0(%rsp)
ffffffff8137b556: 41 89 30             	movl	%esi, (%r8)
ffffffff8137b559: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137b561: c7 02 4d 31 db 00    	movl	$0xdb314d, (%rdx)       # imm = 0xDB314D
ffffffff8137b567: ba a0 d3 00 00       	movl	$0xd3a0, %edx           # imm = 0xD3A0
ffffffff8137b56c: 8b 74 24 0c          	movl	0xc(%rsp), %esi
ffffffff8137b570: 0f a3 f2             	btl	%esi, %edx
ffffffff8137b573: 0f 83 f4 03 00 00    	jae	0xffffffff8137b96d <do_jit+0x2f5d>
ffffffff8137b579: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137b57e: 80 c9 44             	orb	$0x44, %cl
ffffffff8137b581: 48 01 fa             	addq	%rdi, %rdx
ffffffff8137b584: 88 4a 07             	movb	%cl, 0x7(%rdx)
ffffffff8137b587: 48 83 c2 08          	addq	$0x8, %rdx
ffffffff8137b58b: b1 4d                	movb	$0x4d, %cl
ffffffff8137b58d: 48 89 54 24 18       	movq	%rdx, 0x18(%rsp)
ffffffff8137b592: e9 e7 03 00 00       	jmp	0xffffffff8137b97e <do_jit+0x2f6e>
ffffffff8137b597: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137b59c: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137b5a1: 83 fe 73             	cmpl	$0x73, %esi
ffffffff8137b5a4: 0f 85 1d 04 00 00    	jne	0xffffffff8137b9c7 <do_jit+0x2fb7>
ffffffff8137b5aa: 0f bf 4f 02          	movswl	0x2(%rdi), %ecx
ffffffff8137b5ae: 44 89 d2             	movl	%r10d, %edx
ffffffff8137b5b1: 41 83 fa 0b          	cmpl	$0xb, %r10d
ffffffff8137b5b5: 0f 85 9c 04 00 00    	jne	0xffffffff8137ba57 <do_jit+0x3047>
ffffffff8137b5bb: ba 0a 00 00 00       	movl	$0xa, %edx
ffffffff8137b5c0: 66 83 f9 f8          	cmpw	$-0x8, %cx
ffffffff8137b5c4: 0f 85 8d 04 00 00    	jne	0xffffffff8137ba57 <do_jit+0x3047>
ffffffff8137b5ca: 83 7c 24 38 0f       	cmpl	$0xf, 0x38(%rsp)
ffffffff8137b5cf: 0f 84 b9 dc ff ff    	je	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137b5d5: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137b5da: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137b5df: 31 c9                	xorl	%ecx, %ecx
ffffffff8137b5e1: 0f a3 d0             	btl	%edx, %eax
ffffffff8137b5e4: 89 d0                	movl	%edx, %eax
ffffffff8137b5e6: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137b5ed: 0f 92 c1             	setb	%cl
ffffffff8137b5f0: c1 e0 13             	shll	$0x13, %eax
ffffffff8137b5f3: 05 00 00 c1 00       	addl	$0xc10000, %eax         # imm = 0xC10000
ffffffff8137b5f8: 25 00 00 f9 00       	andl	$0xf90000, %eax         # imm = 0xF90000
ffffffff8137b5fd: 8d 84 88 49 89 00 00 	leal	0x8949(%rax,%rcx,4), %eax
ffffffff8137b604: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137b609: 89 01                	movl	%eax, (%rcx)
ffffffff8137b60b: e9 cc 09 00 00       	jmp	0xffffffff8137bfdc <do_jit+0x35cc>
ffffffff8137b610: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b615: 66 c7 00 66 c7       	movw	$0xc766, (%rax)         # imm = 0xC766
ffffffff8137b61a: b8 02 00 00 00       	movl	$0x2, %eax
ffffffff8137b61f: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137b624: 0f b7 4c 24 6c       	movzwl	0x6c(%rsp), %ecx
ffffffff8137b629: 8b 7c 24 0c          	movl	0xc(%rsp), %edi
ffffffff8137b62d: 48 01 c2             	addq	%rax, %rdx
ffffffff8137b630: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137b635: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137b63d: 48 89 d6             	movq	%rdx, %rsi
ffffffff8137b640: 0f bf 50 02          	movswl	0x2(%rax), %edx
ffffffff8137b644: 8b 84 24 8c 00 00 00 	movl	0x8c(%rsp), %eax
ffffffff8137b64b: 01 d1                	addl	%edx, %ecx
ffffffff8137b64d: 29 c8                	subl	%ecx, %eax
ffffffff8137b64f: b9 0a 00 00 00       	movl	$0xa, %ecx
ffffffff8137b654: 83 c0 f0             	addl	$-0x10, %eax
ffffffff8137b657: 83 ff 0b             	cmpl	$0xb, %edi
ffffffff8137b65a: 0f 45 cf             	cmovnel	%edi, %ecx
ffffffff8137b65d: 0f 45 c2             	cmovnel	%edx, %eax
ffffffff8137b660: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137b667: 0f be d0             	movsbl	%al, %edx
ffffffff8137b66a: 39 c2                	cmpl	%eax, %edx
ffffffff8137b66c: 0f 85 21 04 00 00    	jne	0xffffffff8137ba93 <do_jit+0x3083>
ffffffff8137b672: 83 c1 40             	addl	$0x40, %ecx
ffffffff8137b675: c1 e0 08             	shll	$0x8, %eax
ffffffff8137b678: 0f b6 c9             	movzbl	%cl, %ecx
ffffffff8137b67b: 09 c8                	orl	%ecx, %eax
ffffffff8137b67d: 66 89 06             	movw	%ax, (%rsi)
ffffffff8137b680: b8 02 00 00 00       	movl	$0x2, %eax
ffffffff8137b685: e9 22 04 00 00       	jmp	0xffffffff8137baac <do_jit+0x309c>
ffffffff8137b68a: c7 00 48 81 c4 00    	movl	$0xc48148, (%rax)       # imm = 0xC48148
ffffffff8137b690: 89 48 03             	movl	%ecx, 0x3(%rax)
ffffffff8137b693: b9 07 00 00 00       	movl	$0x7, %ecx
ffffffff8137b698: 48 01 c8             	addq	%rcx, %rax
ffffffff8137b69b: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137b6a3: 48 8b 4c 24 60       	movq	0x60(%rsp), %rcx
ffffffff8137b6a8: 48 8b 49 50          	movq	0x50(%rcx), %rcx
ffffffff8137b6ac: 80 b9 99 00 00 00 01 	cmpb	$0x1, 0x99(%rcx)
ffffffff8137b6b3: 0f 85 33 04 00 00    	jne	0xffffffff8137baec <do_jit+0x30dc>
ffffffff8137b6b9: c7 00 41 5f 41 5e    	movl	$0x5e415f41, (%rax)     # imm = 0x5E415F41
ffffffff8137b6bf: 66 c7 40 04 41 5d    	movw	$0x5d41, 0x4(%rax)      # imm = 0x5D41
ffffffff8137b6c5: c6 40 06 5b          	movb	$0x5b, 0x6(%rax)
ffffffff8137b6c9: 48 83 c0 07          	addq	$0x7, %rax
ffffffff8137b6cd: e9 6e 04 00 00       	jmp	0xffffffff8137bb40 <do_jit+0x3130>
ffffffff8137b6d2: 3d f2 00 00 00       	cmpl	$0xf2, %eax
ffffffff8137b6d7: 0f 8e c5 04 00 00    	jle	0xffffffff8137bba2 <do_jit+0x3192>
ffffffff8137b6dd: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137b6e2: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b6e5: 81 fe f3 00 00 00    	cmpl	$0xf3, %esi
ffffffff8137b6eb: 0f 84 cd 04 00 00    	je	0xffffffff8137bbbe <do_jit+0x31ae>
ffffffff8137b6f1: 81 fe f5 00 00 00    	cmpl	$0xf5, %esi
ffffffff8137b6f7: 0f 85 d3 04 00 00    	jne	0xffffffff8137bbd0 <do_jit+0x31c0>
ffffffff8137b6fd: 83 7c 24 48 00       	cmpl	$0x0, 0x48(%rsp)
ffffffff8137b702: 0f 84 18 05 00 00    	je	0xffffffff8137bc20 <do_jit+0x3210>
ffffffff8137b708: 48 8b 7c 24 60       	movq	0x60(%rsp), %rdi
ffffffff8137b70d: 48 8b 4c 24 48       	movq	0x48(%rsp), %rcx
ffffffff8137b712: 4c 8b 4c 24 58       	movq	0x58(%rsp), %r9
ffffffff8137b717: 48 8d 94 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdx
ffffffff8137b71f: 4c 8d 84 24 cc 00 00 00      	leaq	0xcc(%rsp), %r8
ffffffff8137b727: 48 8b 47 50          	movq	0x50(%rdi), %rax
ffffffff8137b72b: ff c9                	decl	%ecx
ffffffff8137b72d: 48 63 c9             	movslq	%ecx, %rcx
ffffffff8137b730: 48 6b f1 38          	imulq	$0x38, %rcx, %rsi
ffffffff8137b734: 4c 89 e1             	movq	%r12, %rcx
ffffffff8137b737: 48 03 b0 00 01 00 00 	addq	0x100(%rax), %rsi
ffffffff8137b73e: ff 75 10             	pushq	0x10(%rbp)
ffffffff8137b741: e8 3a 95 26 00       	callq	0xffffffff815e4c80 <emit_bpf_tail_call_direct>
ffffffff8137b746: 48 83 c4 08          	addq	$0x8, %rsp
ffffffff8137b74a: e9 3f db ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137b74f: 3d dc 00 00 00       	cmpl	$0xdc, %eax
ffffffff8137b754: 0f 85 f1 04 00 00    	jne	0xffffffff8137bc4b <do_jit+0x323b>
ffffffff8137b75a: 83 7c 24 48 10       	cmpl	$0x10, 0x48(%rsp)
ffffffff8137b75f: 0f 85 13 05 00 00    	jne	0xffffffff8137bc78 <do_jit+0x3268>
ffffffff8137b765: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b76a: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137b76e: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137b773: c6 00 66             	movb	$0x66, (%rax)
ffffffff8137b776: 48 ff c0             	incq	%rax
ffffffff8137b779: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137b77c: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137b784: 73 15                	jae	0xffffffff8137b79b <do_jit+0x2d8b>
ffffffff8137b786: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b78b: c6 40 01 41          	movb	$0x41, 0x1(%rax)
ffffffff8137b78f: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137b793: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137b79b: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137b79f: b9 01 00 00 00       	movl	$0x1, %ecx
ffffffff8137b7a4: c4 e2 69 f7 f1       	shlxl	%edx, %ecx, %esi
ffffffff8137b7a9: 89 d1                	movl	%edx, %ecx
ffffffff8137b7ab: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137b7b2: 89 ca                	movl	%ecx, %edx
ffffffff8137b7b4: c1 e2 08             	shll	$0x8, %edx
ffffffff8137b7b7: 81 c2 00 c8 00 00    	addl	$0xc800, %edx           # imm = 0xC800
ffffffff8137b7bd: 81 ca c1 00 08 00    	orl	$0x800c1, %edx          # imm = 0x800C1
ffffffff8137b7c3: 81 e2 c1 ff 08 00    	andl	$0x8ffc1, %edx          # imm = 0x8FFC1
ffffffff8137b7c9: 89 10                	movl	%edx, (%rax)
ffffffff8137b7cb: 48 8d 50 03          	leaq	0x3(%rax), %rdx
ffffffff8137b7cf: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137b7d7: f7 c6 a0 d3 00 00    	testl	$0xd3a0, %esi           # imm = 0xD3A0
ffffffff8137b7dd: 0f 84 c6 04 00 00    	je	0xffffffff8137bca9 <do_jit+0x3299>
ffffffff8137b7e3: c7 02 45 0f b7 00    	movl	$0xb70f45, (%rdx)       # imm = 0xB70F45
ffffffff8137b7e9: ba 06 00 00 00       	movl	$0x6, %edx
ffffffff8137b7ee: e9 c0 04 00 00       	jmp	0xffffffff8137bcb3 <do_jit+0x32a3>
ffffffff8137b7f3: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b7f6: 81 fe d1 00 00 00    	cmpl	$0xd1, %esi
ffffffff8137b7fc: 0f 84 be 04 00 00    	je	0xffffffff8137bcc0 <do_jit+0x32b0>
ffffffff8137b802: 81 fe d3 00 00 00    	cmpl	$0xd3, %esi
ffffffff8137b808: 0f 84 fc 04 00 00    	je	0xffffffff8137bd0a <do_jit+0x32fa>
ffffffff8137b80e: 48 89 c6             	movq	%rax, %rsi
ffffffff8137b811: 81 fe d4 00 00 00    	cmpl	$0xd4, %esi
ffffffff8137b817: 0f 85 61 dc ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b81d: 83 7c 24 48 10       	cmpl	$0x10, 0x48(%rsp)
ffffffff8137b822: 0f 85 5d 05 00 00    	jne	0xffffffff8137bd85 <do_jit+0x3375>
ffffffff8137b828: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137b82c: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137b831: 0f a3 c8             	btl	%ecx, %eax
ffffffff8137b834: 0f 83 8e 05 00 00    	jae	0xffffffff8137bdc8 <do_jit+0x33b8>
ffffffff8137b83a: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b83f: c7 00 45 0f b7 00    	movl	$0xb70f45, (%rax)       # imm = 0xB70F45
ffffffff8137b845: b8 03 00 00 00       	movl	$0x3, %eax
ffffffff8137b84a: e9 88 05 00 00       	jmp	0xffffffff8137bdd7 <do_jit+0x33c7>
ffffffff8137b84f: 83 7c 24 38 04       	cmpl	$0x4, 0x38(%rsp)
ffffffff8137b854: 0f 84 0c 06 00 00    	je	0xffffffff8137be66 <do_jit+0x3456>
ffffffff8137b85a: 83 7c 24 0c 04       	cmpl	$0x4, 0xc(%rsp)
ffffffff8137b85f: 0f 85 95 05 00 00    	jne	0xffffffff8137bdfa <do_jit+0x33ea>
ffffffff8137b865: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137b86a: c7 00 49 89 cb 00    	movl	$0xcb8949, (%rax)       # imm = 0xCB8949
ffffffff8137b870: b8 03 00 00 00       	movl	$0x3, %eax
ffffffff8137b875: c7 44 24 0c 0e 00 00 00      	movl	$0xe, 0xc(%rsp)
ffffffff8137b87d: e9 85 05 00 00       	jmp	0xffffffff8137be07 <do_jit+0x33f7>
ffffffff8137b882: 48 89 c8             	movq	%rcx, %rax
ffffffff8137b885: 83 f8 70             	cmpl	$0x70, %eax
ffffffff8137b888: 0f 84 88 06 00 00    	je	0xffffffff8137bf16 <do_jit+0x3506>
ffffffff8137b88e: 83 f8 60             	cmpl	$0x60, %eax
ffffffff8137b891: 0f 85 83 06 00 00    	jne	0xffffffff8137bf1a <do_jit+0x350a>
ffffffff8137b897: b0 01                	movb	$0x1, %al
ffffffff8137b899: e9 7e 06 00 00       	jmp	0xffffffff8137bf1c <do_jit+0x350c>
ffffffff8137b89e: 81 fe c4 00 00 00    	cmpl	$0xc4, %esi
ffffffff8137b8a4: 0f 85 d4 db ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b8aa: e9 21 01 00 00       	jmp	0xffffffff8137b9d0 <do_jit+0x2fc0>
ffffffff8137b8af: 8b 74 24 0c          	movl	0xc(%rsp), %esi
ffffffff8137b8b3: 48 8b 7c 24 38       	movq	0x38(%rsp), %rdi
ffffffff8137b8b8: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137b8bd: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137b8c2: 31 d2                	xorl	%edx, %edx
ffffffff8137b8c4: c4 e2 4b f7 c0       	shrxl	%esi, %eax, %eax
ffffffff8137b8c9: 83 e0 01             	andl	$0x1, %eax
ffffffff8137b8cc: 0f a3 f9             	btl	%edi, %ecx
ffffffff8137b8cf: 0f 92 c2             	setb	%dl
ffffffff8137b8d2: 8d 0c 90             	leal	(%rax,%rdx,4), %ecx
ffffffff8137b8d5: 89 f0                	movl	%esi, %eax
ffffffff8137b8d7: 89 fa                	movl	%edi, %edx
ffffffff8137b8d9: 8b 14 95 10 29 f2 82 	movl	-0x7d0dd6f0(,%rdx,4), %edx
ffffffff8137b8e0: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137b8e7: 89 c6                	movl	%eax, %esi
ffffffff8137b8e9: c1 e2 13             	shll	$0x13, %edx
ffffffff8137b8ec: c1 e6 10             	shll	$0x10, %esi
ffffffff8137b8ef: 8d 94 16 00 00 c0 00 	leal	0xc00000(%rsi,%rdx), %edx
ffffffff8137b8f6: 48 8b 74 24 18       	movq	0x18(%rsp), %rsi
ffffffff8137b8fb: 81 e2 00 00 ff 00    	andl	$0xff0000, %edx         # imm = 0xFF0000
ffffffff8137b901: 8d 8c 0a 48 89 00 00 	leal	0x8948(%rdx,%rcx), %ecx
ffffffff8137b908: 89 0e                	movl	%ecx, (%rsi)
ffffffff8137b90a: 48 83 c6 03          	addq	$0x3, %rsi
ffffffff8137b90e: 48 89 74 24 18       	movq	%rsi, 0x18(%rsp)
ffffffff8137b913: 8b 74 24 0c          	movl	0xc(%rsp), %esi
ffffffff8137b917: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137b91c: 31 d2                	xorl	%edx, %edx
ffffffff8137b91e: 0f a3 f1             	btl	%esi, %ecx
ffffffff8137b921: 48 8b 74 24 18       	movq	0x18(%rsp), %rsi
ffffffff8137b926: 0f 92 c2             	setb	%dl
ffffffff8137b929: c1 e0 0b             	shll	$0xb, %eax
ffffffff8137b92c: c1 e2 0a             	shll	$0xa, %edx
ffffffff8137b92f: 0d 03 04 25 00       	orl	$0x250403, %eax         # imm = 0x250403
ffffffff8137b934: 81 ca 65 48 00 00    	orl	$0x4865, %edx           # imm = 0x4865
ffffffff8137b93a: 25 03 fc 25 00       	andl	$0x25fc03, %eax         # imm = 0x25FC03
ffffffff8137b93f: 48 8d 4e 02          	leaq	0x2(%rsi), %rcx
ffffffff8137b943: 66 89 16             	movw	%dx, (%rsi)
ffffffff8137b946: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137b94e: 89 46 02             	movl	%eax, 0x2(%rsi)
ffffffff8137b951: 48 8d 4e 05          	leaq	0x5(%rsi), %rcx
ffffffff8137b955: 48 c7 c0 28 40 7c 84 	movq	$-0x7b83bfd8, %rax      # imm = 0x847C4028
ffffffff8137b95c: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137b964: 89 46 05             	movl	%eax, 0x5(%rsi)
ffffffff8137b967: 48 83 c6 09          	addq	$0x9, %rsi
ffffffff8137b96b: eb 4d                	jmp	0xffffffff8137b9ba <do_jit+0x2faa>
ffffffff8137b96d: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137b972: 48 8d 4c 39 07       	leaq	0x7(%rcx,%rdi), %rcx
ffffffff8137b977: 48 89 4c 24 18       	movq	%rcx, 0x18(%rsp)
ffffffff8137b97c: b1 49                	movb	$0x49, %cl
ffffffff8137b97e: 48 8b 74 24 18       	movq	0x18(%rsp), %rsi
ffffffff8137b983: 8d 14 c0             	leal	(%rax,%rax,8), %edx
ffffffff8137b986: c1 e0 13             	shll	$0x13, %eax
ffffffff8137b989: 05 00 00 c3 00       	addl	$0xc30000, %eax         # imm = 0xC30000
ffffffff8137b98e: c1 e2 08             	shll	$0x8, %edx
ffffffff8137b991: 25 00 00 fb 00       	andl	$0xfb0000, %eax         # imm = 0xFB0000
ffffffff8137b996: 81 c2 85 c0 ff ff    	addl	$0xffffc085, %edx       # imm = 0xFFFFC085
ffffffff8137b99c: 0d 0f 44 00 00       	orl	$0x440f, %eax           # imm = 0x440F
ffffffff8137b9a1: 66 89 16             	movw	%dx, (%rsi)
ffffffff8137b9a4: 48 8d 56 03          	leaq	0x3(%rsi), %rdx
ffffffff8137b9a8: 88 4e 02             	movb	%cl, 0x2(%rsi)
ffffffff8137b9ab: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137b9b3: 89 46 03             	movl	%eax, 0x3(%rsi)
ffffffff8137b9b6: 48 83 c6 06          	addq	$0x6, %rsi
ffffffff8137b9ba: 48 89 b4 24 c0 00 00 00      	movq	%rsi, 0xc0(%rsp)
ffffffff8137b9c2: e9 c7 d8 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137b9c7: 83 fe 74             	cmpl	$0x74, %esi
ffffffff8137b9ca: 0f 85 ae da ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137b9d0: 41 f6 d7             	notb	%r15b
ffffffff8137b9d3: b0 48                	movb	$0x48, %al
ffffffff8137b9d5: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137b9d9: 74 10                	je	0xffffffff8137b9eb <do_jit+0x2fdb>
ffffffff8137b9db: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137b9df: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137b9e4: b0 40                	movb	$0x40, %al
ffffffff8137b9e6: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137b9e9: 73 20                	jae	0xffffffff8137ba0b <do_jit+0x2ffb>
ffffffff8137b9eb: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137b9ef: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137b9f4: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137b9f7: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137b9fc: 0f 92 c1             	setb	%cl
ffffffff8137b9ff: 08 c1                	orb	%al, %cl
ffffffff8137ba01: 88 0a                	movb	%cl, (%rdx)
ffffffff8137ba03: 48 ff c2             	incq	%rdx
ffffffff8137ba06: 48 89 54 24 18       	movq	%rdx, 0x18(%rsp)
ffffffff8137ba0b: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137ba10: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137ba14: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137ba1c: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137ba21: 0f b6 00             	movzbl	(%rax), %eax
ffffffff8137ba24: 83 e0 f0             	andl	$-0x10, %eax
ffffffff8137ba27: 8a 80 80 29 f2 82    	movb	-0x7d0dd680(%rax), %al
ffffffff8137ba2d: 02 04 8d 10 29 f2 82 	addb	-0x7d0dd6f0(,%rcx,4), %al
ffffffff8137ba34: 83 7c 24 48 01       	cmpl	$0x1, 0x48(%rsp)
ffffffff8137ba39: 0f b6 c0             	movzbl	%al, %eax
ffffffff8137ba3c: 0f 85 06 05 00 00    	jne	0xffffffff8137bf48 <do_jit+0x3538>
ffffffff8137ba42: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137ba47: c1 e0 08             	shll	$0x8, %eax
ffffffff8137ba4a: 0d d1 00 00 00       	orl	$0xd1, %eax
ffffffff8137ba4f: 66 89 01             	movw	%ax, (%rcx)
ffffffff8137ba52: e9 2b d8 ff ff       	jmp	0xffffffff81379282 <do_jit+0x872>
ffffffff8137ba57: 0f b7 74 24 6c       	movzwl	0x6c(%rsp), %esi
ffffffff8137ba5c: 44 8b 84 24 8c 00 00 00      	movl	0x8c(%rsp), %r8d
ffffffff8137ba64: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137ba6c: 01 ce                	addl	%ecx, %esi
ffffffff8137ba6e: 41 29 f0             	subl	%esi, %r8d
ffffffff8137ba71: 48 89 c6             	movq	%rax, %rsi
ffffffff8137ba74: 41 83 c0 f0          	addl	$-0x10, %r8d
ffffffff8137ba78: 83 7c 24 0c 0b       	cmpl	$0xb, 0xc(%rsp)
ffffffff8137ba7d: 44 0f 45 c1          	cmovnel	%ecx, %r8d
ffffffff8137ba81: 83 e6 18             	andl	$0x18, %esi
ffffffff8137ba84: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137ba89: e8 02 78 26 00       	callq	0xffffffff815e3290 <emit_stx>
ffffffff8137ba8e: e9 fb d7 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137ba93: 80 c1 80             	addb	$-0x80, %cl
ffffffff8137ba96: 48 8d 56 01          	leaq	0x1(%rsi), %rdx
ffffffff8137ba9a: 88 0e                	movb	%cl, (%rsi)
ffffffff8137ba9c: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137baa4: 89 46 01             	movl	%eax, 0x1(%rsi)
ffffffff8137baa7: b8 05 00 00 00       	movl	$0x5, %eax
ffffffff8137baac: 48 8b 4c 24 10       	movq	0x10(%rsp), %rcx
ffffffff8137bab1: 48 01 c6             	addq	%rax, %rsi
ffffffff8137bab4: b8 03 02 00 00       	movl	$0x203, %eax            # imm = 0x203
ffffffff8137bab9: 48 89 b4 24 c0 00 00 00      	movq	%rsi, 0xc0(%rsp)
ffffffff8137bac1: 48 89 f2             	movq	%rsi, %rdx
ffffffff8137bac4: c4 e2 78 f7 01       	bextrl	%eax, (%rcx), %eax
ffffffff8137bac9: 83 f8 01             	cmpl	$0x1, %eax
ffffffff8137bacc: 0f 8f 91 04 00 00    	jg	0xffffffff8137bf63 <do_jit+0x3553>
ffffffff8137bad2: 85 c0                	testl	%eax, %eax
ffffffff8137bad4: 0f 84 92 07 00 00    	je	0xffffffff8137c26c <do_jit+0x385c>
ffffffff8137bada: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff8137badf: 66 89 02             	movw	%ax, (%rdx)
ffffffff8137bae2: b8 02 00 00 00       	movl	$0x2, %eax
ffffffff8137bae7: e9 8c 07 00 00       	jmp	0xffffffff8137c278 <do_jit+0x3868>
ffffffff8137baec: 80 bc 24 cf 00 00 00 01      	cmpb	$0x1, 0xcf(%rsp)
ffffffff8137baf4: 75 09                	jne	0xffffffff8137baff <do_jit+0x30ef>
ffffffff8137baf6: 66 c7 00 41 5f       	movw	$0x5f41, (%rax)         # imm = 0x5F41
ffffffff8137bafb: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137baff: 80 bc 24 ce 00 00 00 01      	cmpb	$0x1, 0xce(%rsp)
ffffffff8137bb07: 75 09                	jne	0xffffffff8137bb12 <do_jit+0x3102>
ffffffff8137bb09: 66 c7 00 41 5e       	movw	$0x5e41, (%rax)         # imm = 0x5E41
ffffffff8137bb0e: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137bb12: 80 bc 24 cd 00 00 00 01      	cmpb	$0x1, 0xcd(%rsp)
ffffffff8137bb1a: 75 09                	jne	0xffffffff8137bb25 <do_jit+0x3115>
ffffffff8137bb1c: 66 c7 00 41 5d       	movw	$0x5d41, (%rax)         # imm = 0x5D41
ffffffff8137bb21: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137bb25: 80 bc 24 cc 00 00 00 01      	cmpb	$0x1, 0xcc(%rsp)
ffffffff8137bb2d: 75 06                	jne	0xffffffff8137bb35 <do_jit+0x3125>
ffffffff8137bb2f: c6 00 5b             	movb	$0x5b, (%rax)
ffffffff8137bb32: 48 ff c0             	incq	%rax
ffffffff8137bb35: 48 83 bc 24 80 00 00 00 00   	cmpq	$0x0, 0x80(%rsp)
ffffffff8137bb3e: 74 09                	je	0xffffffff8137bb49 <do_jit+0x3139>
ffffffff8137bb40: 66 c7 00 41 5c       	movw	$0x5c41, (%rax)         # imm = 0x5C41
ffffffff8137bb45: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137bb49: 48 8b 4c 24 60       	movq	0x60(%rsp), %rcx
ffffffff8137bb4e: c6 00 c9             	movb	$-0x37, (%rax)
ffffffff8137bb51: 48 ff c0             	incq	%rax
ffffffff8137bb54: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137bb5c: 4c 8d b4 24 d0 00 00 00      	leaq	0xd0(%rsp), %r14
ffffffff8137bb64: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137bb69: 48 89 07             	movq	%rax, (%rdi)
ffffffff8137bb6c: 44 29 f0             	subl	%r14d, %eax
ffffffff8137bb6f: 48 8b 49 50          	movq	0x50(%rcx), %rcx
ffffffff8137bb73: 89 81 78 03 00 00    	movl	%eax, 0x378(%rcx)
ffffffff8137bb79: 48 8b 37             	movq	(%rdi), %rsi
ffffffff8137bb7c: 49 63 04 9f          	movslq	(%r15,%rbx,4), %rax
ffffffff8137bb80: 4c 29 f6             	subq	%r14, %rsi
ffffffff8137bb83: 48 03 74 24 78       	addq	0x78(%rsp), %rsi
ffffffff8137bb88: 48 01 c6             	addq	%rax, %rsi
ffffffff8137bb8b: e8 90 7d 26 00       	callq	0xffffffff815e3920 <emit_return>
ffffffff8137bb90: b0 01                	movb	$0x1, %al
ffffffff8137bb92: 4d 89 f0             	movq	%r14, %r8
ffffffff8137bb95: 48 89 84 24 a8 00 00 00      	movq	%rax, 0xa8(%rsp)
ffffffff8137bb9d: e9 f9 d6 ff ff       	jmp	0xffffffff8137929b <do_jit+0x88b>
ffffffff8137bba2: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137bba7: 48 89 c6             	movq	%rax, %rsi
ffffffff8137bbaa: 81 fe e3 00 00 00    	cmpl	$0xe3, %esi
ffffffff8137bbb0: 74 32                	je	0xffffffff8137bbe4 <do_jit+0x31d4>
ffffffff8137bbb2: 81 fe eb 00 00 00    	cmpl	$0xeb, %esi
ffffffff8137bbb8: 0f 85 c0 d8 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137bbbe: 8b 47 04             	movl	0x4(%rdi), %eax
ffffffff8137bbc1: 83 e0 ef             	andl	$-0x11, %eax
ffffffff8137bbc4: 3d 00 01 00 00       	cmpl	$0x100, %eax            # imm = 0x100
ffffffff8137bbc9: 74 19                	je	0xffffffff8137bbe4 <do_jit+0x31d4>
ffffffff8137bbcb: e9 a9 01 00 00       	jmp	0xffffffff8137bd79 <do_jit+0x3369>
ffffffff8137bbd0: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137bbd5: 48 89 c6             	movq	%rax, %rsi
ffffffff8137bbd8: 81 fe fb 00 00 00    	cmpl	$0xfb, %esi
ffffffff8137bbde: 0f 85 9a d8 ff ff    	jne	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137bbe4: 8b 47 04             	movl	0x4(%rdi), %eax
ffffffff8137bbe7: 44 0f bf 4f 02       	movswl	0x2(%rdi), %r9d
ffffffff8137bbec: 83 e6 18             	andl	$0x18, %esi
ffffffff8137bbef: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137bbf7: 48 89 f2             	movq	%rsi, %rdx
ffffffff8137bbfa: 89 c1                	movl	%eax, %ecx
ffffffff8137bbfc: 83 e1 ef             	andl	$-0x11, %ecx
ffffffff8137bbff: 89 c6                	movl	%eax, %esi
ffffffff8137bc01: 81 f9 00 01 00 00    	cmpl	$0x100, %ecx            # imm = 0x100
ffffffff8137bc07: 0f 85 70 03 00 00    	jne	0xffffffff8137bf7d <do_jit+0x356d>
ffffffff8137bc0d: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137bc11: 4c 8b 44 24 38       	movq	0x38(%rsp), %r8
ffffffff8137bc16: e8 75 8e 26 00       	callq	0xffffffff815e4a90 <emit_atomic_ld_st_index>
ffffffff8137bc1b: e9 6b 03 00 00       	jmp	0xffffffff8137bf8b <do_jit+0x357b>
ffffffff8137bc20: 48 8b 7c 24 60       	movq	0x60(%rsp), %rdi
ffffffff8137bc25: 4c 8b 4d 10          	movq	0x10(%rbp), %r9
ffffffff8137bc29: 48 8d b4 24 c0 00 00 00      	leaq	0xc0(%rsp), %rsi
ffffffff8137bc31: 48 8d 94 24 cc 00 00 00      	leaq	0xcc(%rsp), %rdx
ffffffff8137bc39: 48 8b 4c 24 58       	movq	0x58(%rsp), %rcx
ffffffff8137bc3e: 4d 89 e0             	movq	%r12, %r8
ffffffff8137bc41: e8 1a 92 26 00       	callq	0xffffffff815e4e60 <emit_bpf_tail_call_indirect>
ffffffff8137bc46: e9 43 d6 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137bc4b: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137bc50: 4c 8b 4c 24 18       	movq	0x18(%rsp), %r9
ffffffff8137bc55: 44 8b 54 24 0c       	movl	0xc(%rsp), %r10d
ffffffff8137bc5a: 48 89 c6             	movq	%rax, %rsi
ffffffff8137bc5d: 05 23 ff ff ff       	addl	$0xffffff23, %eax       # imm = 0xFFFFFF23
ffffffff8137bc62: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137bc6a: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137bc6d: 0f 83 0b d8 ff ff    	jae	0xffffffff8137947e <do_jit+0xa6e>
ffffffff8137bc73: e9 6e d8 ff ff       	jmp	0xffffffff813794e6 <do_jit+0xad6>
ffffffff8137bc78: 83 7c 24 48 20       	cmpl	$0x20, 0x48(%rsp)
ffffffff8137bc7d: 0f 85 17 03 00 00    	jne	0xffffffff8137bf9a <do_jit+0x358a>
ffffffff8137bc83: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137bc87: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137bc8c: 0f a3 c8             	btl	%ecx, %eax
ffffffff8137bc8f: 0f 83 50 03 00 00    	jae	0xffffffff8137bfe5 <do_jit+0x35d5>
ffffffff8137bc95: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137bc9a: 66 c7 00 41 0f       	movw	$0xf41, (%rax)          # imm = 0xF41
ffffffff8137bc9f: b8 02 00 00 00       	movl	$0x2, %eax
ffffffff8137bca4: e9 49 03 00 00       	jmp	0xffffffff8137bff2 <do_jit+0x35e2>
ffffffff8137bca9: 66 c7 02 0f b7       	movw	$0xb70f, (%rdx)         # imm = 0xB70F
ffffffff8137bcae: ba 05 00 00 00       	movl	$0x5, %edx
ffffffff8137bcb3: 8d 0c c9             	leal	(%rcx,%rcx,8), %ecx
ffffffff8137bcb6: 48 8d 44 10 01       	leaq	0x1(%rax,%rdx), %rax
ffffffff8137bcbb: e9 2f 01 00 00       	jmp	0xffffffff8137bdef <do_jit+0x33df>
ffffffff8137bcc0: 89 f1                	movl	%esi, %ecx
ffffffff8137bcc2: 83 e1 07             	andl	$0x7, %ecx
ffffffff8137bcc5: 83 f9 01             	cmpl	$0x1, %ecx
ffffffff8137bcc8: 0f 85 44 03 00 00    	jne	0xffffffff8137c012 <do_jit+0x3602>
ffffffff8137bcce: 48 8b 54 24 10       	movq	0x10(%rsp), %rdx
ffffffff8137bcd3: 89 c1                	movl	%eax, %ecx
ffffffff8137bcd5: 83 e0 18             	andl	$0x18, %eax
ffffffff8137bcd8: 83 e1 e0             	andl	$-0x20, %ecx
ffffffff8137bcdb: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137bce3: 48 89 c6             	movq	%rax, %rsi
ffffffff8137bce6: 44 0f bf 42 02       	movswl	0x2(%rdx), %r8d
ffffffff8137bceb: 81 f9 c0 00 00 00    	cmpl	$0xc0, %ecx
ffffffff8137bcf1: 0f 85 43 03 00 00    	jne	0xffffffff8137c03a <do_jit+0x362a>
ffffffff8137bcf7: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137bcfb: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137bd00: e8 fb 88 26 00       	callq	0xffffffff815e4600 <emit_ldsx_r12>
ffffffff8137bd05: e9 3e 03 00 00       	jmp	0xffffffff8137c048 <do_jit+0x3638>
ffffffff8137bd0a: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137bd0f: 8b 70 04             	movl	0x4(%rax), %esi
ffffffff8137bd12: 89 f0                	movl	%esi, %eax
ffffffff8137bd14: 83 e0 ef             	andl	$-0x11, %eax
ffffffff8137bd17: 3d 00 01 00 00       	cmpl	$0x100, %eax            # imm = 0x100
ffffffff8137bd1c: 75 5b                	jne	0xffffffff8137bd79 <do_jit+0x3369>
ffffffff8137bd1e: 83 fe 41             	cmpl	$0x41, %esi
ffffffff8137bd21: 0f 84 e3 03 00 00    	je	0xffffffff8137c10a <do_jit+0x36fa>
ffffffff8137bd27: 81 fe a1 00 00 00    	cmpl	$0xa1, %esi
ffffffff8137bd2d: 0f 84 d7 03 00 00    	je	0xffffffff8137c10a <do_jit+0x36fa>
ffffffff8137bd33: 83 fe 51             	cmpl	$0x51, %esi
ffffffff8137bd36: 0f 84 ce 03 00 00    	je	0xffffffff8137c10a <do_jit+0x36fa>
ffffffff8137bd3c: 48 8b 4c 24 10       	movq	0x10(%rsp), %rcx
ffffffff8137bd41: 41 80 e7 18          	andb	$0x18, %r15b
ffffffff8137bd45: 89 f0                	movl	%esi, %eax
ffffffff8137bd47: 83 e0 ef             	andl	$-0x11, %eax
ffffffff8137bd4a: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137bd52: 45 0f b6 cf          	movzbl	%r15b, %r9d
ffffffff8137bd56: 44 0f bf 41 02       	movswl	0x2(%rcx), %r8d
ffffffff8137bd5b: 3d 00 01 00 00       	cmpl	$0x100, %eax            # imm = 0x100
ffffffff8137bd60: 0f 85 b3 04 00 00    	jne	0xffffffff8137c219 <do_jit+0x3809>
ffffffff8137bd66: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137bd6a: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137bd6f: e8 ac 8c 26 00       	callq	0xffffffff815e4a20 <emit_atomic_ld_st>
ffffffff8137bd74: e9 ae 04 00 00       	jmp	0xffffffff8137c227 <do_jit+0x3817>
ffffffff8137bd79: 48 c7 c7 e3 8d dc 82 	movq	$-0x7d23721d, %rdi      # imm = 0x82DC8DE3
ffffffff8137bd80: e9 76 03 00 00       	jmp	0xffffffff8137c0fb <do_jit+0x36eb>
ffffffff8137bd85: 83 7c 24 48 20       	cmpl	$0x20, 0x48(%rsp)
ffffffff8137bd8a: 0f 85 fe d4 ff ff    	jne	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137bd90: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137bd94: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137bd99: 0f a3 c8             	btl	%ecx, %eax
ffffffff8137bd9c: 73 10                	jae	0xffffffff8137bdae <do_jit+0x339e>
ffffffff8137bd9e: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137bda3: c6 00 45             	movb	$0x45, (%rax)
ffffffff8137bda6: 48 ff c0             	incq	%rax
ffffffff8137bda9: 48 89 44 24 18       	movq	%rax, 0x18(%rsp)
ffffffff8137bdae: 8b 44 24 0c          	movl	0xc(%rsp), %eax
ffffffff8137bdb2: 8b 04 85 10 29 f2 82 	movl	-0x7d0dd6f0(,%rax,4), %eax
ffffffff8137bdb9: c1 e0 08             	shll	$0x8, %eax
ffffffff8137bdbc: 8d 84 c0 89 c0 ff ff 	leal	-0x3f77(%rax,%rax,8), %eax
ffffffff8137bdc3: e9 b2 d4 ff ff       	jmp	0xffffffff8137927a <do_jit+0x86a>
ffffffff8137bdc8: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137bdcd: 66 c7 00 0f b7       	movw	$0xb70f, (%rax)         # imm = 0xB70F
ffffffff8137bdd2: b8 02 00 00 00       	movl	$0x2, %eax
ffffffff8137bdd7: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137bddb: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137bde0: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137bde7: 48 8d 44 02 01       	leaq	0x1(%rdx,%rax), %rax
ffffffff8137bdec: 8d 0c c9             	leal	(%rcx,%rcx,8), %ecx
ffffffff8137bdef: 80 c1 c0             	addb	$-0x40, %cl
ffffffff8137bdf2: 88 48 ff             	movb	%cl, -0x1(%rax)
ffffffff8137bdf5: e9 65 04 00 00       	jmp	0xffffffff8137c25f <do_jit+0x384f>
ffffffff8137bdfa: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137bdff: c6 00 51             	movb	$0x51, (%rax)
ffffffff8137be02: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137be07: 48 8b 74 24 18       	movq	0x18(%rsp), %rsi
ffffffff8137be0c: 48 8b 7c 24 38       	movq	0x38(%rsp), %rdi
ffffffff8137be11: 31 d2                	xorl	%edx, %edx
ffffffff8137be13: 48 8d 0c 06          	leaq	(%rsi,%rax), %rcx
ffffffff8137be17: 48 8d 74 06 03       	leaq	0x3(%rsi,%rax), %rsi
ffffffff8137be1c: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137be24: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137be29: 0f a3 f9             	btl	%edi, %ecx
ffffffff8137be2c: 89 f9                	movl	%edi, %ecx
ffffffff8137be2e: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137be35: 0f 92 c2             	setb	%dl
ffffffff8137be38: c1 e1 13             	shll	$0x13, %ecx
ffffffff8137be3b: 81 c1 00 00 c1 00    	addl	$0xc10000, %ecx         # imm = 0xC10000
ffffffff8137be41: 81 e1 00 00 f9 00    	andl	$0xf90000, %ecx         # imm = 0xF90000
ffffffff8137be47: 8d 8c 91 48 89 00 00 	leal	0x8948(%rcx,%rdx,4), %ecx
ffffffff8137be4e: 89 4e fd             	movl	%ecx, -0x3(%rsi)
ffffffff8137be51: 48 89 b4 24 c0 00 00 00      	movq	%rsi, 0xc0(%rsp)
ffffffff8137be59: 48 89 74 24 18       	movq	%rsi, 0x18(%rsp)
ffffffff8137be5e: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137be63: 44 8a 38             	movb	(%rax), %r15b
ffffffff8137be66: 41 f6 d7             	notb	%r15b
ffffffff8137be69: b0 48                	movb	$0x48, %al
ffffffff8137be6b: 41 f6 c7 07          	testb	$0x7, %r15b
ffffffff8137be6f: 74 10                	je	0xffffffff8137be81 <do_jit+0x3471>
ffffffff8137be71: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137be75: b9 a0 d3 00 00       	movl	$0xd3a0, %ecx           # imm = 0xD3A0
ffffffff8137be7a: b0 40                	movb	$0x40, %al
ffffffff8137be7c: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137be7f: 73 20                	jae	0xffffffff8137bea1 <do_jit+0x3491>
ffffffff8137be81: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137be85: b9 a0 d3 01 00       	movl	$0x1d3a0, %ecx          # imm = 0x1D3A0
ffffffff8137be8a: 0f a3 d1             	btl	%edx, %ecx
ffffffff8137be8d: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137be92: 0f 92 c1             	setb	%cl
ffffffff8137be95: 08 c1                	orb	%al, %cl
ffffffff8137be97: 88 0a                	movb	%cl, (%rdx)
ffffffff8137be99: 48 ff c2             	incq	%rdx
ffffffff8137be9c: 48 89 54 24 18       	movq	%rdx, 0x18(%rsp)
ffffffff8137bea1: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137bea6: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137beab: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137beaf: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137beb7: 0f b6 00             	movzbl	(%rax), %eax
ffffffff8137beba: 83 e0 f0             	andl	$-0x10, %eax
ffffffff8137bebd: 8a 80 80 29 f2 82    	movb	-0x7d0dd680(%rax), %al
ffffffff8137bec3: 02 04 8d 10 29 f2 82 	addb	-0x7d0dd6f0(,%rcx,4), %al
ffffffff8137beca: 48 8d 4a 02          	leaq	0x2(%rdx), %rcx
ffffffff8137bece: 0f b6 c0             	movzbl	%al, %eax
ffffffff8137bed1: c1 e0 08             	shll	$0x8, %eax
ffffffff8137bed4: 0d d3 00 00 00       	orl	$0xd3, %eax
ffffffff8137bed9: 83 7c 24 38 04       	cmpl	$0x4, 0x38(%rsp)
ffffffff8137bede: 66 89 02             	movw	%ax, (%rdx)
ffffffff8137bee1: 48 89 8c 24 c0 00 00 00      	movq	%rcx, 0xc0(%rsp)
ffffffff8137bee9: 0f 84 9f d3 ff ff    	je	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137beef: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137bef4: 8a 40 01             	movb	0x1(%rax), %al
ffffffff8137bef7: 24 0f                	andb	$0xf, %al
ffffffff8137bef9: 3c 04                	cmpb	$0x4, %al
ffffffff8137befb: 0f 85 51 03 00 00    	jne	0xffffffff8137c252 <do_jit+0x3842>
ffffffff8137bf01: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137bf06: c7 40 02 4c 89 d9 00 	movl	$0xd9894c, 0x2(%rax)    # imm = 0xD9894C
ffffffff8137bf0d: 48 83 c0 05          	addq	$0x5, %rax
ffffffff8137bf11: e9 49 03 00 00       	jmp	0xffffffff8137c25f <do_jit+0x384f>
ffffffff8137bf16: b0 03                	movb	$0x3, %al
ffffffff8137bf18: eb 02                	jmp	0xffffffff8137bf1c <do_jit+0x350c>
ffffffff8137bf1a: 31 c0                	xorl	%eax, %eax
ffffffff8137bf1c: 8b 74 24 0c          	movl	0xc(%rsp), %esi
ffffffff8137bf20: 41 80 e7 07          	andb	$0x7, %r15b
ffffffff8137bf24: 31 c9                	xorl	%ecx, %ecx
ffffffff8137bf26: 44 0f b6 c0          	movzbl	%al, %r8d
ffffffff8137bf2a: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137bf32: 48 8b 54 24 38       	movq	0x38(%rsp), %rdx
ffffffff8137bf37: 41 80 ff 07          	cmpb	$0x7, %r15b
ffffffff8137bf3b: 0f 94 c1             	sete	%cl
ffffffff8137bf3e: e8 ed 84 26 00       	callq	0xffffffff815e4430 <emit_shiftx>
ffffffff8137bf43: e9 46 d3 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137bf48: 48 8b 4c 24 48       	movq	0x48(%rsp), %rcx
ffffffff8137bf4d: c1 e0 08             	shll	$0x8, %eax
ffffffff8137bf50: c1 e1 10             	shll	$0x10, %ecx
ffffffff8137bf53: 8d 84 08 c1 00 00 00 	leal	0xc1(%rax,%rcx), %eax
ffffffff8137bf5a: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137bf5f: 89 01                	movl	%eax, (%rcx)
ffffffff8137bf61: eb 79                	jmp	0xffffffff8137bfdc <do_jit+0x35cc>
ffffffff8137bf63: 83 f8 02             	cmpl	$0x2, %eax
ffffffff8137bf66: 0f 85 00 03 00 00    	jne	0xffffffff8137c26c <do_jit+0x385c>
ffffffff8137bf6c: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff8137bf71: 88 02                	movb	%al, (%rdx)
ffffffff8137bf73: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137bf78: e9 fb 02 00 00       	jmp	0xffffffff8137c278 <do_jit+0x3868>
ffffffff8137bf7d: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137bf81: 4c 8b 44 24 38       	movq	0x38(%rsp), %r8
ffffffff8137bf86: e8 75 8b 26 00       	callq	0xffffffff815e4b00 <emit_atomic_rmw_index>
ffffffff8137bf8b: 89 c3                	movl	%eax, %ebx
ffffffff8137bf8d: 85 c0                	testl	%eax, %eax
ffffffff8137bf8f: 0f 85 fa d4 ff ff    	jne	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137bf95: e9 ae 00 00 00       	jmp	0xffffffff8137c048 <do_jit+0x3638>
ffffffff8137bf9a: 83 7c 24 48 40       	cmpl	$0x40, 0x48(%rsp)
ffffffff8137bf9f: 0f 85 e9 d2 ff ff    	jne	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137bfa5: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137bfa9: b8 a0 d3 01 00       	movl	$0x1d3a0, %eax          # imm = 0x1D3A0
ffffffff8137bfae: c4 e2 73 f7 c0       	shrxl	%ecx, %eax, %eax
ffffffff8137bfb3: 89 c9                	movl	%ecx, %ecx
ffffffff8137bfb5: 8b 0c 8d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rcx,4), %ecx
ffffffff8137bfbc: 83 e0 01             	andl	$0x1, %eax
ffffffff8137bfbf: c1 e1 10             	shll	$0x10, %ecx
ffffffff8137bfc2: 81 c1 00 00 c8 00    	addl	$0xc80000, %ecx         # imm = 0xC80000
ffffffff8137bfc8: 81 e1 00 00 ff 00    	andl	$0xff0000, %ecx         # imm = 0xFF0000
ffffffff8137bfce: 8d 84 08 48 0f 00 00 	leal	0xf48(%rax,%rcx), %eax
ffffffff8137bfd5: 48 8b 4c 24 18       	movq	0x18(%rsp), %rcx
ffffffff8137bfda: 89 01                	movl	%eax, (%rcx)
ffffffff8137bfdc: 48 83 c1 03          	addq	$0x3, %rcx
ffffffff8137bfe0: e9 a1 d2 ff ff       	jmp	0xffffffff81379286 <do_jit+0x876>
ffffffff8137bfe5: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137bfea: c6 00 0f             	movb	$0xf, (%rax)
ffffffff8137bfed: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff8137bff2: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137bff6: 48 8b 54 24 18       	movq	0x18(%rsp), %rdx
ffffffff8137bffb: 8a 0c 8d 10 29 f2 82 	movb	-0x7d0dd6f0(,%rcx,4), %cl
ffffffff8137c002: 48 8d 44 02 01       	leaq	0x1(%rdx,%rax), %rax
ffffffff8137c007: 80 c1 c8             	addb	$-0x38, %cl
ffffffff8137c00a: 88 48 ff             	movb	%cl, -0x1(%rax)
ffffffff8137c00d: e9 4d 02 00 00       	jmp	0xffffffff8137c25f <do_jit+0x384f>
ffffffff8137c012: 48 8b 4c 24 10       	movq	0x10(%rsp), %rcx
ffffffff8137c017: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137c01b: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137c023: 48 89 c6             	movq	%rax, %rsi
ffffffff8137c026: 83 e6 18             	andl	$0x18, %esi
ffffffff8137c029: 44 0f bf 41 02       	movswl	0x2(%rcx), %r8d
ffffffff8137c02e: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137c033: e8 98 92 26 00       	callq	0xffffffff815e52d0 <emit_stx_index>
ffffffff8137c038: eb 0e                	jmp	0xffffffff8137c048 <do_jit+0x3638>
ffffffff8137c03a: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137c03e: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137c043: e8 38 91 26 00       	callq	0xffffffff815e5180 <emit_ldx_index>
ffffffff8137c048: 48 8b 44 24 60       	movq	0x60(%rsp), %rax
ffffffff8137c04d: 48 8b 48 50          	movq	0x50(%rax), %rcx
ffffffff8137c051: 48 8b 81 68 04 00 00 	movq	0x468(%rcx), %rax
ffffffff8137c058: 48 85 c0             	testq	%rax, %rax
ffffffff8137c05b: 0f 84 2d d2 ff ff    	je	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137c061: 48 8b 54 24 50       	movq	0x50(%rsp), %rdx
ffffffff8137c066: 3b 91 60 04 00 00    	cmpl	0x460(%rcx), %edx
ffffffff8137c06c: 0f 83 82 00 00 00    	jae	0xffffffff8137c0f4 <do_jit+0x36e4>
ffffffff8137c072: 48 63 54 24 50       	movslq	0x50(%rsp), %rdx
ffffffff8137c077: 48 63 4c 24 30       	movslq	0x30(%rsp), %rcx
ffffffff8137c07c: 48 8b 74 24 78       	movq	0x78(%rsp), %rsi
ffffffff8137c081: 48 8d 14 52          	leaq	(%rdx,%rdx,2), %rdx
ffffffff8137c085: 48 01 f1             	addq	%rsi, %rcx
ffffffff8137c088: 4c 01 f1             	addq	%r14, %rcx
ffffffff8137c08b: 48 8d 1c 90          	leaq	(%rax,%rdx,4), %rbx
ffffffff8137c08f: 48 8b 54 24 70       	movq	0x70(%rsp), %rdx
ffffffff8137c094: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137c099: 29 d9                	subl	%ebx, %ecx
ffffffff8137c09b: 48 29 f3             	subq	%rsi, %rbx
ffffffff8137c09e: 89 0c 1a             	movl	%ecx, (%rdx,%rbx)
ffffffff8137c0a1: c7 44 1a 08 07 00 00 00      	movl	$0x7, 0x8(%rdx,%rbx)
ffffffff8137c0a9: 0f b6 00             	movzbl	(%rax), %eax
ffffffff8137c0ac: 89 c1                	movl	%eax, %ecx
ffffffff8137c0ae: 83 e1 07             	andl	$0x7, %ecx
ffffffff8137c0b1: 83 f9 01             	cmpl	$0x1, %ecx
ffffffff8137c0b4: 74 25                	je	0xffffffff8137c0db <do_jit+0x36cb>
ffffffff8137c0b6: 83 f9 03             	cmpl	$0x3, %ecx
ffffffff8137c0b9: 0f 85 c9 01 00 00    	jne	0xffffffff8137c288 <do_jit+0x3878>
ffffffff8137c0bf: f7 d0                	notl	%eax
ffffffff8137c0c1: a8 c0                	testb	$-0x40, %al
ffffffff8137c0c3: 0f 85 bf 01 00 00    	jne	0xffffffff8137c288 <do_jit+0x3878>
ffffffff8137c0c9: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff8137c0ce: 81 78 04 00 01 00 00 	cmpl	$0x100, 0x4(%rax)       # imm = 0x100
ffffffff8137c0d5: 0f 85 ad 01 00 00    	jne	0xffffffff8137c288 <do_jit+0x3878>
ffffffff8137c0db: 8b 44 24 38          	movl	0x38(%rsp), %eax
ffffffff8137c0df: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137c0e3: 8b 0c 85 30 78 f1 82 	movl	-0x7d0e87d0(,%rax,4), %ecx
ffffffff8137c0ea: b8 00 00 00 80       	movl	$0x80000000, %eax       # imm = 0x80000000
ffffffff8137c0ef: e9 15 02 00 00       	jmp	0xffffffff8137c309 <do_jit+0x38f9>
ffffffff8137c0f4: 48 c7 c7 ec 6a e1 82 	movq	$-0x7d1e9514, %rdi      # imm = 0x82E16AEC
ffffffff8137c0fb: e8 40 23 ee ff       	callq	0xffffffff8125e440 <_printk>
ffffffff8137c100: bb f2 ff ff ff       	movl	$0xfffffff2, %ebx       # imm = 0xFFFFFFF2
ffffffff8137c105: e9 85 d3 ff ff       	jmp	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137c10a: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137c10f: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137c117: 41 80 e7 18          	andb	$0x18, %r15b
ffffffff8137c11b: c7 00 49 89 c2 00    	movl	$0xc28949, (%rax)       # imm = 0xC28949
ffffffff8137c121: 48 83 c0 03          	addq	$0x3, %rax
ffffffff8137c125: 48 89 07             	movq	%rax, (%rdi)
ffffffff8137c128: 48 89 44 24 18       	movq	%rax, 0x18(%rsp)
ffffffff8137c12d: b8 0c 00 00 00       	movl	$0xc, %eax
ffffffff8137c132: 4c 8b 64 24 10       	movq	0x10(%rsp), %r12
ffffffff8137c137: 48 8b 5c 24 38       	movq	0x38(%rsp), %rbx
ffffffff8137c13c: 44 8b 6c 24 0c       	movl	0xc(%rsp), %r13d
ffffffff8137c141: 41 0f b6 34 24       	movzbl	(%r12), %esi
ffffffff8137c146: 45 0f bf 44 24 02    	movswl	0x2(%r12), %r8d
ffffffff8137c14c: 85 db                	testl	%ebx, %ebx
ffffffff8137c14e: 0f 44 d8             	cmovel	%eax, %ebx
ffffffff8137c151: 45 85 ed             	testl	%r13d, %r13d
ffffffff8137c154: 44 0f 44 e8          	cmovel	%eax, %r13d
ffffffff8137c158: 31 d2                	xorl	%edx, %edx
ffffffff8137c15a: 44 89 e9             	movl	%r13d, %ecx
ffffffff8137c15d: 83 e6 18             	andl	$0x18, %esi
ffffffff8137c160: e8 6b dd 0d 00       	callq	0xffffffff81459ed0 <emit_ldx>
ffffffff8137c165: b8 a0 d3 00 00       	movl	$0xd3a0, %eax           # imm = 0xD3A0
ffffffff8137c16a: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137c172: ba 0e 00 00 00       	movl	$0xe, %edx
ffffffff8137c177: 0f a3 d8             	btl	%ebx, %eax
ffffffff8137c17a: 0f 92 c0             	setb	%al
ffffffff8137c17d: 31 f6                	xorl	%esi, %esi
ffffffff8137c17f: c0 e0 02             	shlb	$0x2, %al
ffffffff8137c182: 8d 48 41             	leal	0x41(%rax), %ecx
ffffffff8137c185: 0c 49                	orb	$0x49, %al
ffffffff8137c187: 41 80 ff 18          	cmpb	$0x18, %r15b
ffffffff8137c18b: 40 0f 94 c6          	sete	%sil
ffffffff8137c18f: 0f b6 c0             	movzbl	%al, %eax
ffffffff8137c192: 44 0f b6 f1          	movzbl	%cl, %r14d
ffffffff8137c196: 44 0f 44 f0          	cmovel	%eax, %r14d
ffffffff8137c19a: 31 c9                	xorl	%ecx, %ecx
ffffffff8137c19c: e8 5f 7d 26 00       	callq	0xffffffff815e3f00 <emit_mov_reg>
ffffffff8137c1a1: 48 8d bc 24 c0 00 00 00      	leaq	0xc0(%rsp), %rdi
ffffffff8137c1a9: be f1 00 00 00       	movl	$0xf1, %esi
ffffffff8137c1ae: 48 8b 07             	movq	(%rdi), %rax
ffffffff8137c1b1: 48 8d 48 01          	leaq	0x1(%rax), %rcx
ffffffff8137c1b5: 44 88 30             	movb	%r14b, (%rax)
ffffffff8137c1b8: 49 89 de             	movq	%rbx, %r14
ffffffff8137c1bb: 48 89 0f             	movq	%rcx, (%rdi)
ffffffff8137c1be: 8b 14 9d 10 29 f2 82 	movl	-0x7d0dd6f0(,%rbx,4), %edx
ffffffff8137c1c5: 41 8b 4c 24 04       	movl	0x4(%r12), %ecx
ffffffff8137c1ca: c1 e2 0b             	shll	$0xb, %edx
ffffffff8137c1cd: 81 e1 f0 00 00 00    	andl	$0xf0, %ecx
ffffffff8137c1d3: 0f b6 89 80 29 f2 82 	movzbl	-0x7d0dd680(%rcx), %ecx
ffffffff8137c1da: 8d 8c 0a 00 c3 ff ff 	leal	-0x3d00(%rdx,%rcx), %ecx
ffffffff8137c1e1: 44 89 ea             	movl	%r13d, %edx
ffffffff8137c1e4: 66 89 48 01          	movw	%cx, 0x1(%rax)
ffffffff8137c1e8: 48 83 c0 03          	addq	$0x3, %rax
ffffffff8137c1ec: b9 0e 00 00 00       	movl	$0xe, %ecx
ffffffff8137c1f1: 48 89 07             	movq	%rax, (%rdi)
ffffffff8137c1f4: 45 0f b6 0c 24       	movzbl	(%r12), %r9d
ffffffff8137c1f9: 45 0f bf 44 24 02    	movswl	0x2(%r12), %r8d
ffffffff8137c1ff: 41 83 e1 18          	andl	$0x18, %r9d
ffffffff8137c203: e8 88 86 26 00       	callq	0xffffffff815e4890 <emit_atomic_rmw>
ffffffff8137c208: 85 c0                	testl	%eax, %eax
ffffffff8137c20a: 0f 84 9d 00 00 00    	je	0xffffffff8137c2ad <do_jit+0x389d>
ffffffff8137c210: 0f 0b                	ud2
ffffffff8137c212: 89 c3                	movl	%eax, %ebx
ffffffff8137c214: e9 76 d2 ff ff       	jmp	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137c219: 8b 54 24 0c          	movl	0xc(%rsp), %edx
ffffffff8137c21d: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff8137c222: e8 69 86 26 00       	callq	0xffffffff815e4890 <emit_atomic_rmw>
ffffffff8137c227: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137c22c: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137c231: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137c236: 48 8b 4c 24 30       	movq	0x30(%rsp), %rcx
ffffffff8137c23b: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137c243: 89 c3                	movl	%eax, %ebx
ffffffff8137c245: 85 c0                	testl	%eax, %eax
ffffffff8137c247: 0f 85 42 d2 ff ff    	jne	0xffffffff8137948f <do_jit+0xa7f>
ffffffff8137c24d: e9 cb cd ff ff       	jmp	0xffffffff8137901d <do_jit+0x60d>
ffffffff8137c252: 48 8b 44 24 18       	movq	0x18(%rsp), %rax
ffffffff8137c257: c6 40 02 59          	movb	$0x59, 0x2(%rax)
ffffffff8137c25b: 48 83 c0 03          	addq	$0x3, %rax
ffffffff8137c25f: 48 89 84 24 c0 00 00 00      	movq	%rax, 0xc0(%rsp)
ffffffff8137c267: e9 22 d0 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137c26c: 48 8b 44 24 48       	movq	0x48(%rsp), %rax
ffffffff8137c271: 89 02                	movl	%eax, (%rdx)
ffffffff8137c273: b8 04 00 00 00       	movl	$0x4, %eax
ffffffff8137c278: 48 01 c2             	addq	%rax, %rdx
ffffffff8137c27b: 48 89 94 24 c0 00 00 00      	movq	%rdx, 0xc0(%rsp)
ffffffff8137c283: e9 06 d0 ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137c288: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137c28d: e8 7e 84 26 00       	callq	0xffffffff815e4710 <bpf_atomic_load_reg>
ffffffff8137c292: 8b 4c 24 0c          	movl	0xc(%rsp), %ecx
ffffffff8137c296: 8b 0c 8d 30 78 f1 82 	movl	-0x7d0e87d0(,%rcx,4), %ecx
ffffffff8137c29d: 85 c0                	testl	%eax, %eax
ffffffff8137c29f: 79 61                	jns	0xffffffff8137c302 <do_jit+0x38f2>
ffffffff8137c2a1: ba 00 01 00 00       	movl	$0x100, %edx            # imm = 0x100
ffffffff8137c2a6: b8 00 00 00 c0       	movl	$0xc0000000, %eax       # imm = 0xC0000000
ffffffff8137c2ab: eb 69                	jmp	0xffffffff8137c316 <do_jit+0x3906>
ffffffff8137c2ad: 48 8d 9c 24 c0 00 00 00      	leaq	0xc0(%rsp), %rbx
ffffffff8137c2b5: 4c 8b 6c 24 18       	movq	0x18(%rsp), %r13
ffffffff8137c2ba: 31 f6                	xorl	%esi, %esi
ffffffff8137c2bc: 41 80 ff 18          	cmpb	$0x18, %r15b
ffffffff8137c2c0: 44 89 f2             	movl	%r14d, %edx
ffffffff8137c2c3: 48 8b 03             	movq	(%rbx), %rax
ffffffff8137c2c6: 40 0f 94 c6          	sete	%sil
ffffffff8137c2ca: 48 89 df             	movq	%rbx, %rdi
ffffffff8137c2cd: 31 c9                	xorl	%ecx, %ecx
ffffffff8137c2cf: 41 29 c5             	subl	%eax, %r13d
ffffffff8137c2d2: 41 c1 e5 08          	shll	$0x8, %r13d
ffffffff8137c2d6: 41 81 c5 75 fe ff ff 	addl	$0xfffffe75, %r13d      # imm = 0xFFFFFE75
ffffffff8137c2dd: 66 44 89 28          	movw	%r13w, (%rax)
ffffffff8137c2e1: 48 83 c0 02          	addq	$0x2, %rax
ffffffff8137c2e5: 48 89 03             	movq	%rax, (%rbx)
ffffffff8137c2e8: e8 13 7c 26 00       	callq	0xffffffff815e3f00 <emit_mov_reg>
ffffffff8137c2ed: 48 8b 03             	movq	(%rbx), %rax
ffffffff8137c2f0: c7 00 4c 89 d0 00    	movl	$0xd0894c, (%rax)       # imm = 0xD0894C
ffffffff8137c2f6: 48 83 c0 03          	addq	$0x3, %rax
ffffffff8137c2fa: 48 89 03             	movq	%rax, (%rbx)
ffffffff8137c2fd: e9 8c cf ff ff       	jmp	0xffffffff8137928e <do_jit+0x87e>
ffffffff8137c302: 89 c2                	movl	%eax, %edx
ffffffff8137c304: b8 00 00 00 c0       	movl	$0xc0000000, %eax       # imm = 0xC0000000
ffffffff8137c309: 8b 14 95 30 78 f1 82 	movl	-0x7d0e87d0(,%rdx,4), %edx
ffffffff8137c310: c1 e2 08             	shll	$0x8, %edx
ffffffff8137c313: 0f b7 d2             	movzwl	%dx, %edx
ffffffff8137c316: 48 8b 74 24 50       	movq	0x50(%rsp), %rsi
ffffffff8137c31b: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff8137c320: ff c6                	incl	%esi
ffffffff8137c322: 48 89 74 24 50       	movq	%rsi, 0x50(%rsp)
ffffffff8137c327: 8b b4 24 c0 00 00 00 	movl	0xc0(%rsp), %esi
ffffffff8137c32e: 2b 74 24 18          	subl	0x18(%rsp), %esi
ffffffff8137c332: 40 0f b6 f6          	movzbl	%sil, %esi
ffffffff8137c336: 09 c6                	orl	%eax, %esi
ffffffff8137c338: 0f b6 c1             	movzbl	%cl, %eax
ffffffff8137c33b: c1 e0 10             	shll	$0x10, %eax
ffffffff8137c33e: 09 c2                	orl	%eax, %edx
ffffffff8137c340: 09 f2                	orl	%esi, %edx
ffffffff8137c342: 48 8b 74 24 70       	movq	0x70(%rsp), %rsi
ffffffff8137c347: 89 54 1e 04          	movl	%edx, 0x4(%rsi,%rbx)
ffffffff8137c34b: 0f b7 47 02          	movzwl	0x2(%rdi), %eax
ffffffff8137c34f: c1 e0 10             	shll	$0x10, %eax
ffffffff8137c352: 83 c8 07             	orl	$0x7, %eax
ffffffff8137c355: 89 44 1e 08          	movl	%eax, 0x8(%rsi,%rbx)
ffffffff8137c359: 4c 8b 7c 24 20       	movq	0x20(%rsp), %r15
ffffffff8137c35e: 4c 8b 64 24 28       	movq	0x28(%rsp), %r12
ffffffff8137c363: 4c 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %r8
ffffffff8137c36b: e9 a8 cc ff ff       	jmp	0xffffffff81379018 <do_jit+0x608>

ffffffff814596f0 <bpf_int_jit_compile>:
ffffffff814596f0: f3 0f 1e fa          	endbr64
ffffffff814596f4: 0f 1f 44 00 00       	nopl	(%rax,%rax)
ffffffff814596f9: 55                   	pushq	%rbp
ffffffff814596fa: 41 57                	pushq	%r15
ffffffff814596fc: 41 56                	pushq	%r14
ffffffff814596fe: 41 55                	pushq	%r13
ffffffff81459700: 41 54                	pushq	%r12
ffffffff81459702: 53                   	pushq	%rbx
ffffffff81459703: 48 83 ec 60          	subq	$0x60, %rsp
ffffffff81459707: 65 48 8b 05 09 a9 36 03      	movq	%gs:0x336a909(%rip), %rax
ffffffff8145970f: 48 89 44 24 58       	movq	%rax, 0x58(%rsp)
ffffffff81459714: 31 c0                	xorl	%eax, %eax
ffffffff81459716: 48 89 44 24 50       	movq	%rax, 0x50(%rsp)
ffffffff8145971b: 48 89 44 24 40       	movq	%rax, 0x40(%rsp)
ffffffff81459720: c7 44 24 48 00 00 00 00      	movl	$0x0, 0x48(%rsp)
ffffffff81459728: 48 89 44 24 38       	movq	%rax, 0x38(%rsp)
ffffffff8145972d: 48 89 44 24 30       	movq	%rax, 0x30(%rsp)
ffffffff81459732: f6 46 02 02          	testb	$0x2, 0x2(%rsi)
ffffffff81459736: 75 18                	jne	0xffffffff81459750 <bpf_int_jit_compile+0x60>
ffffffff81459738: 65 48 8b 05 d8 a8 36 03      	movq	%gs:0x336a8d8(%rip), %rax
ffffffff81459740: 48 3b 44 24 58       	cmpq	0x58(%rsp), %rax
ffffffff81459745: 0f 84 ba 01 00 00    	je	0xffffffff81459905 <bpf_int_jit_compile+0x215>
ffffffff8145974b: e8 b0 5d 1c 01       	callq	0xffffffff8261f500 <__stack_chk_fail>
ffffffff81459750: 48 8b 46 50          	movq	0x50(%rsi), %rax
ffffffff81459754: 48 89 7c 24 28       	movq	%rdi, 0x28(%rsp)
ffffffff81459759: 48 89 34 24          	movq	%rsi, (%rsp)
ffffffff8145975d: 48 8b 88 f8 00 00 00 	movq	0xf8(%rax), %rcx
ffffffff81459764: 48 89 4c 24 10       	movq	%rcx, 0x10(%rsp)
ffffffff81459769: 48 85 c9             	testq	%rcx, %rcx
ffffffff8145976c: 0f 84 3d 03 00 00    	je	0xffffffff81459aaf <bpf_int_jit_compile+0x3bf>
ffffffff81459772: 48 8b 50 58          	movq	0x58(%rax), %rdx
ffffffff81459776: 48 89 54 24 18       	movq	%rdx, 0x18(%rsp)
ffffffff8145977b: 48 85 d2             	testq	%rdx, %rdx
ffffffff8145977e: 0f 84 6c 03 00 00    	je	0xffffffff81459af0 <bpf_int_jit_compile+0x400>
ffffffff81459784: 48 8b 44 24 10       	movq	0x10(%rsp), %rax
ffffffff81459789: 4c 8b 60 10          	movq	0x10(%rax), %r12
ffffffff8145978d: 4d 85 e4             	testq	%r12, %r12
ffffffff81459790: 0f 85 b4 03 00 00    	jne	0xffffffff81459b4a <bpf_int_jit_compile+0x45a>
ffffffff81459796: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff8145979a: ba 01 00 00 00       	movl	$0x1, %edx
ffffffff8145979f: b9 c0 0c 00 00       	movl	$0xcc0, %ecx            # imm = 0xCC0
ffffffff814597a4: 41 b8 ff ff ff ff    	movl	$0xffffffff, %r8d       # imm = 0xFFFFFFFF
ffffffff814597aa: 45 31 f6             	xorl	%r14d, %r14d
ffffffff814597ad: 31 f6                	xorl	%esi, %esi
ffffffff814597af: 8b 78 10             	movl	0x10(%rax), %edi
ffffffff814597b2: ff c7                	incl	%edi
ffffffff814597b4: 48 c1 e7 02          	shlq	$0x2, %rdi
ffffffff814597b8: e8 e3 d0 00 00       	callq	0xffffffff814668a0 <__kvmalloc_node_noprof>
ffffffff814597bd: 48 85 c0             	testq	%rax, %rax
ffffffff814597c0: 0f 84 3f 02 00 00    	je	0xffffffff81459a05 <bpf_int_jit_compile+0x315>
ffffffff814597c6: 49 89 c4             	movq	%rax, %r12
ffffffff814597c9: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff814597cd: 8b 40 10             	movl	0x10(%rax), %eax
ffffffff814597d0: 8d 48 01             	leal	0x1(%rax), %ecx
ffffffff814597d3: 83 f9 01             	cmpl	$0x1, %ecx
ffffffff814597d6: 83 d0 01             	adcl	$0x1, %eax
ffffffff814597d9: 31 c9                	xorl	%ecx, %ecx
ffffffff814597db: 41 83 c6 40          	addl	$0x40, %r14d
ffffffff814597df: 48 63 c9             	movslq	%ecx, %rcx
ffffffff814597e2: 45 89 34 8c          	movl	%r14d, (%r12,%rcx,4)
ffffffff814597e6: ff c1                	incl	%ecx
ffffffff814597e8: 39 c8                	cmpl	%ecx, %eax
ffffffff814597ea: 75 ef                	jne	0xffffffff814597db <bpf_int_jit_compile+0xeb>
ffffffff814597ec: 44 89 74 24 40       	movl	%r14d, 0x40(%rsp)
ffffffff814597f1: 31 c9                	xorl	%ecx, %ecx
ffffffff814597f3: 45 31 f6             	xorl	%r14d, %r14d
ffffffff814597f6: 48 c7 44 24 20 00 00 00 00   	movq	$0x0, 0x20(%rsp)
ffffffff814597ff: 48 c7 44 24 08 00 00 00 00   	movq	$0x0, 0x8(%rsp)
ffffffff81459808: 48 8b 44 24 20       	movq	0x20(%rsp), %rax
ffffffff8145980d: 45 31 ed             	xorl	%r13d, %r13d
ffffffff81459810: 89 c3                	movl	%eax, %ebx
ffffffff81459812: 0f b6 c3             	movzbl	%bl, %eax
ffffffff81459815: bb 01 00 00 00       	movl	$0x1, %ebx
ffffffff8145981a: 4c 8b 44 24 38       	movq	0x38(%rsp), %r8
ffffffff8145981f: 48 8b 7c 24 28       	movq	0x28(%rsp), %rdi
ffffffff81459824: 48 8b 34 24          	movq	(%rsp), %rsi
ffffffff81459828: 4c 89 e2             	movq	%r12, %rdx
ffffffff8145982b: 45 89 f1             	movl	%r14d, %r9d
ffffffff8145982e: a8 01                	testb	$0x1, %al
ffffffff81459830: 0f 45 d8             	cmovnel	%eax, %ebx
ffffffff81459833: 41 83 fd 0f          	cmpl	$0xf, %r13d
ffffffff81459837: 0f 4c d8             	cmovll	%eax, %ebx
ffffffff8145983a: 0f b6 c3             	movzbl	%bl, %eax
ffffffff8145983d: 50                   	pushq	%rax
ffffffff8145983e: 48 8d 44 24 48       	leaq	0x48(%rsp), %rax
ffffffff81459843: 50                   	pushq	%rax
ffffffff81459844: e8 c7 f1 f1 ff       	callq	0xffffffff81378a10 <do_jit>
ffffffff81459849: 48 83 c4 10          	addq	$0x10, %rsp
ffffffff8145984d: 85 c0                	testl	%eax, %eax
ffffffff8145984f: 0f 8e 54 03 00 00    	jle	0xffffffff81459ba9 <bpf_int_jit_compile+0x4b9>
ffffffff81459855: 48 8b 6c 24 30       	movq	0x30(%rsp), %rbp
ffffffff8145985a: 41 89 c7             	movl	%eax, %r15d
ffffffff8145985d: 48 85 ed             	testq	%rbp, %rbp
ffffffff81459860: 0f 85 b6 00 00 00    	jne	0xffffffff8145991c <bpf_int_jit_compile+0x22c>
ffffffff81459866: 45 39 f7             	cmpl	%r14d, %r15d
ffffffff81459869: 75 73                	jne	0xffffffff814598de <bpf_int_jit_compile+0x1ee>
ffffffff8145986b: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff8145986f: 41 83 c6 03          	addl	$0x3, %r14d
ffffffff81459873: 45 31 d2             	xorl	%r10d, %r10d
ffffffff81459876: 48 8d 74 24 30       	leaq	0x30(%rsp), %rsi
ffffffff8145987b: ba 04 00 00 00       	movl	$0x4, %edx
ffffffff81459880: 4c 8d 44 24 38       	leaq	0x38(%rsp), %r8
ffffffff81459885: 49 c7 c1 b0 0a 5e 81 	movq	$-0x7ea1f550, %r9       # imm = 0x815E0AB0
ffffffff8145988c: 41 83 e6 fc          	andl	$-0x4, %r14d
ffffffff81459890: 48 8b 48 50          	movq	0x50(%rax), %rcx
ffffffff81459894: 83 78 08 00          	cmpl	$0x0, 0x8(%rax)
ffffffff81459898: 8b 89 60 04 00 00    	movl	0x460(%rcx), %ecx
ffffffff8145989e: 41 0f 94 c2          	sete	%r10b
ffffffff814598a2: 8d 0c 49             	leal	(%rcx,%rcx,2), %ecx
ffffffff814598a5: 41 8d 3c 8e          	leal	(%r14,%rcx,4), %edi
ffffffff814598a9: 48 8d 4c 24 50       	leaq	0x50(%rsp), %rcx
ffffffff814598ae: 41 52                	pushq	%r10
ffffffff814598b0: e8 5b 03 00 00       	callq	0xffffffff81459c10 <bpf_jit_binary_pack_alloc>
ffffffff814598b5: 48 83 c4 08          	addq	$0x8, %rsp
ffffffff814598b9: 48 89 44 24 08       	movq	%rax, 0x8(%rsp)
ffffffff814598be: 48 85 c0             	testq	%rax, %rax
ffffffff814598c1: 0f 84 3b 01 00 00    	je	0xffffffff81459a02 <bpf_int_jit_compile+0x312>
ffffffff814598c7: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff814598cb: 44 89 f1             	movl	%r14d, %ecx
ffffffff814598ce: 48 03 4c 24 30       	addq	0x30(%rsp), %rcx
ffffffff814598d3: 48 8b 40 50          	movq	0x50(%rax), %rax
ffffffff814598d7: 48 89 88 68 04 00 00 	movq	%rcx, 0x468(%rax)
ffffffff814598de: e8 55 88 1d 01       	callq	0xffffffff82632138 <__SCT__cond_resched>
ffffffff814598e3: 48 8b 4c 24 30       	movq	0x30(%rsp), %rcx
ffffffff814598e8: 41 ff c5             	incl	%r13d
ffffffff814598eb: 45 89 fe             	movl	%r15d, %r14d
ffffffff814598ee: 41 83 fd 14          	cmpl	$0x14, %r13d
ffffffff814598f2: 0f 9c c0             	setl	%al
ffffffff814598f5: 48 85 c9             	testq	%rcx, %rcx
ffffffff814598f8: 0f 95 c2             	setne	%dl
ffffffff814598fb: 08 c2                	orb	%al, %dl
ffffffff814598fd: 0f 85 0f ff ff ff    	jne	0xffffffff81459812 <bpf_int_jit_compile+0x122>
ffffffff81459903: eb 23                	jmp	0xffffffff81459928 <bpf_int_jit_compile+0x238>
ffffffff81459905: 48 89 f0             	movq	%rsi, %rax
ffffffff81459908: 48 83 c4 60          	addq	$0x60, %rsp
ffffffff8145990c: 5b                   	popq	%rbx
ffffffff8145990d: 41 5c                	popq	%r12
ffffffff8145990f: 41 5d                	popq	%r13
ffffffff81459911: 41 5e                	popq	%r14
ffffffff81459913: 41 5f                	popq	%r15
ffffffff81459915: 5d                   	popq	%rbp
ffffffff81459916: 2e e9 14 81 1d 01    	jmp	0xffffffff82631a30 <__x86_return_thunk>
ffffffff8145991c: 45 39 f7             	cmpl	%r14d, %r15d
ffffffff8145991f: 0f 85 72 02 00 00    	jne	0xffffffff81459b97 <bpf_int_jit_compile+0x4a7>
ffffffff81459925: 45 89 f7             	movl	%r14d, %r15d
ffffffff81459928: 83 3d 69 41 88 02 02 	cmpl	$0x2, 0x2884169(%rip)   # 0xffffffff83cdda98 <bpf_jit_enable>
ffffffff8145992f: 0f 8d 24 01 00 00    	jge	0xffffffff81459a59 <bpf_int_jit_compile+0x369>
ffffffff81459935: 48 85 ed             	testq	%rbp, %rbp
ffffffff81459938: 0f 84 c4 00 00 00    	je	0xffffffff81459a02 <bpf_int_jit_compile+0x312>
ffffffff8145993e: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff81459942: f6 40 03 01          	testb	$0x1, 0x3(%rax)
ffffffff81459946: 0f 94 c0             	sete	%al
ffffffff81459949: 0a 44 24 20          	orb	0x20(%rsp), %al
ffffffff8145994d: a8 01                	testb	$0x1, %al
ffffffff8145994f: 74 27                	je	0xffffffff81459978 <bpf_int_jit_compile+0x288>
ffffffff81459951: 48 8b 74 24 50       	movq	0x50(%rsp), %rsi
ffffffff81459956: 48 8b 7c 24 08       	movq	0x8(%rsp), %rdi
ffffffff8145995b: e8 40 43 37 00       	callq	0xffffffff817cdca0 <bpf_jit_binary_pack_finalize>
ffffffff81459960: 85 c0                	testl	%eax, %eax
ffffffff81459962: 0f 85 15 01 00 00    	jne	0xffffffff81459a7d <bpf_int_jit_compile+0x38d>
ffffffff81459968: 48 8b 3c 24          	movq	(%rsp), %rdi
ffffffff8145996c: e8 1f 92 18 00       	callq	0xffffffff815e2b90 <bpf_tail_call_direct_fixup>
ffffffff81459971: 48 8b 6c 24 30       	movq	0x30(%rsp), %rbp
ffffffff81459976: eb 32                	jmp	0xffffffff814599aa <bpf_int_jit_compile+0x2ba>
ffffffff81459978: 48 8b 4c 24 10       	movq	0x10(%rsp), %rcx
ffffffff8145997d: 48 8b 54 24 08       	movq	0x8(%rsp), %rdx
ffffffff81459982: 4c 89 61 10          	movq	%r12, 0x10(%rcx)
ffffffff81459986: 48 8b 44 24 40       	movq	0x40(%rsp), %rax
ffffffff8145998b: 48 89 41 24          	movq	%rax, 0x24(%rcx)
ffffffff8145998f: 8b 44 24 48          	movl	0x48(%rsp), %eax
ffffffff81459993: 89 41 2c             	movl	%eax, 0x2c(%rcx)
ffffffff81459996: 44 89 79 20          	movl	%r15d, 0x20(%rcx)
ffffffff8145999a: 48 89 69 18          	movq	%rbp, 0x18(%rcx)
ffffffff8145999e: 48 89 51 08          	movq	%rdx, 0x8(%rcx)
ffffffff814599a2: 48 8b 44 24 50       	movq	0x50(%rsp), %rax
ffffffff814599a7: 48 89 01             	movq	%rax, (%rcx)
ffffffff814599aa: 4c 8b 34 24          	movq	(%rsp), %r14
ffffffff814599ae: 4c 89 e6             	movq	%r12, %rsi
ffffffff814599b1: 48 89 ea             	movq	%rbp, %rdx
ffffffff814599b4: 4c 89 f7             	movq	%r14, %rdi
ffffffff814599b7: e8 74 54 3d 00       	callq	0xffffffff8182ee30 <bpf_prog_update_insn_ptrs>
ffffffff814599bc: 48 8b 4c 24 30       	movq	0x30(%rsp), %rcx
ffffffff814599c1: 49 89 4e 48          	movq	%rcx, 0x48(%r14)
ffffffff814599c5: 41 8b 46 02          	movl	0x2(%r14), %eax
ffffffff814599c9: 89 c2                	movl	%eax, %edx
ffffffff814599cb: 83 ca 01             	orl	$0x1, %edx
ffffffff814599ce: 41 89 56 02          	movl	%edx, 0x2(%r14)
ffffffff814599d2: 45 89 7e 14          	movl	%r15d, 0x14(%r14)
ffffffff814599d6: 48 85 c9             	testq	%rcx, %rcx
ffffffff814599d9: 74 27                	je	0xffffffff81459a02 <bpf_int_jit_compile+0x312>
ffffffff814599db: 0f ba e0 08          	btl	$0x8, %eax
ffffffff814599df: 48 8b 34 24          	movq	(%rsp), %rsi
ffffffff814599e3: 0f 93 c0             	setae	%al
ffffffff814599e6: 0a 44 24 20          	orb	0x20(%rsp), %al
ffffffff814599ea: a8 01                	testb	$0x1, %al
ffffffff814599ec: 0f 84 46 fd ff ff    	je	0xffffffff81459738 <bpf_int_jit_compile+0x48>
ffffffff814599f2: 49 8d 44 24 04       	leaq	0x4(%r12), %rax
ffffffff814599f7: 48 89 f7             	movq	%rsi, %rdi
ffffffff814599fa: 48 89 c6             	movq	%rax, %rsi
ffffffff814599fd: e8 1e 27 37 00       	callq	0xffffffff817cc120 <bpf_prog_fill_jited_linfo>
ffffffff81459a02: 4d 89 e6             	movq	%r12, %r14
ffffffff81459a05: 4c 89 f7             	movq	%r14, %rdi
ffffffff81459a08: e8 43 66 e9 ff       	callq	0xffffffff812f0050 <kvfree>
ffffffff81459a0d: 48 83 7c 24 18 00    	cmpq	$0x0, 0x18(%rsp)
ffffffff81459a13: 74 22                	je	0xffffffff81459a37 <bpf_int_jit_compile+0x347>
ffffffff81459a15: 48 83 7c 24 30 00    	cmpq	$0x0, 0x30(%rsp)
ffffffff81459a1b: 75 1a                	jne	0xffffffff81459a37 <bpf_int_jit_compile+0x347>
ffffffff81459a1d: 48 8b 7c 24 18       	movq	0x18(%rsp), %rdi
ffffffff81459a22: e8 b9 31 ef ff       	callq	0xffffffff8134cbe0 <free_percpu>
ffffffff81459a27: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff81459a2b: 48 8b 40 50          	movq	0x50(%rax), %rax
ffffffff81459a2f: 48 c7 40 58 00 00 00 00      	movq	$0x0, 0x58(%rax)
ffffffff81459a37: 48 8b 7c 24 10       	movq	0x10(%rsp), %rdi
ffffffff81459a3c: e8 df a6 e9 ff       	callq	0xffffffff812f4120 <kfree>
ffffffff81459a41: 48 8b 34 24          	movq	(%rsp), %rsi
ffffffff81459a45: 48 8b 46 50          	movq	0x50(%rsi), %rax
ffffffff81459a49: 48 c7 80 f8 00 00 00 00 00 00 00     	movq	$0x0, 0xf8(%rax)
ffffffff81459a54: e9 df fc ff ff       	jmp	0xffffffff81459738 <bpf_int_jit_compile+0x48>
ffffffff81459a59: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff81459a5d: 48 8b 4c 24 38       	movq	0x38(%rsp), %rcx
ffffffff81459a62: 41 ff c5             	incl	%r13d
ffffffff81459a65: 44 89 fe             	movl	%r15d, %esi
ffffffff81459a68: 44 89 ea             	movl	%r13d, %edx
ffffffff81459a6b: 8b 78 10             	movl	0x10(%rax), %edi
ffffffff81459a6e: e8 8d ff e1 ff       	callq	0xffffffff81279a00 <bpf_jit_dump>
ffffffff81459a73: 48 8b 6c 24 30       	movq	0x30(%rsp), %rbp
ffffffff81459a78: e9 b8 fe ff ff       	jmp	0xffffffff81459935 <bpf_int_jit_compile+0x245>
ffffffff81459a7d: 0f 0b                	ud2
ffffffff81459a7f: 48 c7 44 24 30 00 00 00 00   	movq	$0x0, 0x30(%rsp)
ffffffff81459a88: 80 7c 24 20 00       	cmpb	$0x0, 0x20(%rsp)
ffffffff81459a8d: 0f 84 6f ff ff ff    	je	0xffffffff81459a02 <bpf_int_jit_compile+0x312>
ffffffff81459a93: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff81459a97: 48 c7 40 48 00 00 00 00      	movq	$0x0, 0x48(%rax)
ffffffff81459a9f: 80 60 02 fe          	andb	$-0x2, 0x2(%rax)
ffffffff81459aa3: c7 40 14 00 00 00 00 	movl	$0x0, 0x14(%rax)
ffffffff81459aaa: e9 53 ff ff ff       	jmp	0xffffffff81459a02 <bpf_int_jit_compile+0x312>
ffffffff81459aaf: 48 8b 3d da e4 d0 01 	movq	0x1d0e4da(%rip), %rdi   # 0xffffffff83167f90 <kmalloc_caches+0x30>
ffffffff81459ab6: ba 30 00 00 00       	movl	$0x30, %edx
ffffffff81459abb: be c0 0d 00 00       	movl	$0xdc0, %esi            # imm = 0xDC0
ffffffff81459ac0: e8 5b ec e9 ff       	callq	0xffffffff812f8720 <__kmalloc_cache_noprof>
ffffffff81459ac5: 48 8b 34 24          	movq	(%rsp), %rsi
ffffffff81459ac9: 48 89 44 24 10       	movq	%rax, 0x10(%rsp)
ffffffff81459ace: 48 85 c0             	testq	%rax, %rax
ffffffff81459ad1: 0f 84 61 fc ff ff    	je	0xffffffff81459738 <bpf_int_jit_compile+0x48>
ffffffff81459ad7: 48 8b 46 50          	movq	0x50(%rsi), %rax
ffffffff81459adb: 48 8b 4c 24 10       	movq	0x10(%rsp), %rcx
ffffffff81459ae0: 48 89 88 f8 00 00 00 	movq	%rcx, 0xf8(%rax)
ffffffff81459ae7: 48 8b 46 50          	movq	0x50(%rsi), %rax
ffffffff81459aeb: e9 82 fc ff ff       	jmp	0xffffffff81459772 <bpf_int_jit_compile+0x82>
ffffffff81459af0: 80 b8 9b 00 00 00 01 	cmpb	$0x1, 0x9b(%rax)
ffffffff81459af7: 0f 85 ea 00 00 00    	jne	0xffffffff81459be7 <bpf_int_jit_compile+0x4f7>
ffffffff81459afd: 8b 68 1c             	movl	0x1c(%rax), %ebp
ffffffff81459b00: be 08 00 00 00       	movl	$0x8, %esi
ffffffff81459b05: b9 c0 0c 00 00       	movl	$0xcc0, %ecx            # imm = 0xCC0
ffffffff81459b0a: 31 d2                	xorl	%edx, %edx
ffffffff81459b0c: ff cd                	decl	%ebp
ffffffff81459b0e: 83 cd 07             	orl	$0x7, %ebp
ffffffff81459b11: 83 c5 11             	addl	$0x11, %ebp
ffffffff81459b14: 48 63 fd             	movslq	%ebp, %rdi
ffffffff81459b17: e8 e4 28 ef ff       	callq	0xffffffff8134c400 <pcpu_alloc_noprof>
ffffffff81459b1c: 48 89 44 24 18       	movq	%rax, 0x18(%rsp)
ffffffff81459b21: 48 85 c0             	testq	%rax, %rax
ffffffff81459b24: 0f 84 0d ff ff ff    	je	0xffffffff81459a37 <bpf_int_jit_compile+0x347>
ffffffff81459b2a: 48 8b 5c 24 18       	movq	0x18(%rsp), %rbx
ffffffff81459b2f: 89 ee                	movl	%ebp, %esi
ffffffff81459b31: 48 89 df             	movq	%rbx, %rdi
ffffffff81459b34: e8 c7 8f 18 00       	callq	0xffffffff815e2b00 <priv_stack_init_guard>
ffffffff81459b39: 48 8b 04 24          	movq	(%rsp), %rax
ffffffff81459b3d: 48 8b 40 50          	movq	0x50(%rax), %rax
ffffffff81459b41: 48 89 58 58          	movq	%rbx, 0x58(%rax)
ffffffff81459b45: e9 3a fc ff ff       	jmp	0xffffffff81459784 <bpf_int_jit_compile+0x94>
ffffffff81459b4a: 48 8b 54 24 10       	movq	0x10(%rsp), %rdx
ffffffff81459b4f: 8b 42 2c             	movl	0x2c(%rdx), %eax
ffffffff81459b52: 89 44 24 48          	movl	%eax, 0x48(%rsp)
ffffffff81459b56: 48 8b 42 24          	movq	0x24(%rdx), %rax
ffffffff81459b5a: 48 89 44 24 40       	movq	%rax, 0x40(%rsp)
ffffffff81459b5f: 48 8b 4a 18          	movq	0x18(%rdx), %rcx
ffffffff81459b63: 44 8b 72 20          	movl	0x20(%rdx), %r14d
ffffffff81459b67: 48 89 4c 24 30       	movq	%rcx, 0x30(%rsp)
ffffffff81459b6c: 48 8b 7a 08          	movq	0x8(%rdx), %rdi
ffffffff81459b70: 48 8b 02             	movq	(%rdx), %rax
ffffffff81459b73: 48 89 ca             	movq	%rcx, %rdx
ffffffff81459b76: 48 29 fa             	subq	%rdi, %rdx
ffffffff81459b79: 48 89 44 24 50       	movq	%rax, 0x50(%rsp)
ffffffff81459b7e: 48 89 7c 24 08       	movq	%rdi, 0x8(%rsp)
ffffffff81459b83: 48 01 c2             	addq	%rax, %rdx
ffffffff81459b86: b0 01                	movb	$0x1, %al
ffffffff81459b88: 48 89 54 24 38       	movq	%rdx, 0x38(%rsp)
ffffffff81459b8d: 48 89 44 24 20       	movq	%rax, 0x20(%rsp)
ffffffff81459b92: e9 71 fc ff ff       	jmp	0xffffffff81459808 <bpf_int_jit_compile+0x118>
ffffffff81459b97: 48 c7 c7 2c 1b e3 82 	movq	$-0x7d1ce4d4, %rdi      # imm = 0x82E31B2C
ffffffff81459b9e: 44 89 fe             	movl	%r15d, %esi
ffffffff81459ba1: 44 89 f2             	movl	%r14d, %edx
ffffffff81459ba4: e8 97 48 e0 ff       	callq	0xffffffff8125e440 <_printk>
ffffffff81459ba9: 48 83 7c 24 08 00    	cmpq	$0x0, 0x8(%rsp)
ffffffff81459baf: 48 c7 44 24 30 00 00 00 00   	movq	$0x0, 0x30(%rsp)
ffffffff81459bb8: 0f 84 ca fe ff ff    	je	0xffffffff81459a88 <bpf_int_jit_compile+0x398>
ffffffff81459bbe: 48 8b 5c 24 08       	movq	0x8(%rsp), %rbx
ffffffff81459bc3: 48 8b 74 24 50       	movq	0x50(%rsp), %rsi
ffffffff81459bc8: ba 04 00 00 00       	movl	$0x4, %edx
ffffffff81459bcd: 48 89 df             	movq	%rbx, %rdi
ffffffff81459bd0: e8 3b 5f 12 00       	callq	0xffffffff8157fb10 <text_poke_copy>
ffffffff81459bd5: 48 8b 74 24 50       	movq	0x50(%rsp), %rsi
ffffffff81459bda: 48 89 df             	movq	%rbx, %rdi
ffffffff81459bdd: e8 1e 41 37 00       	callq	0xffffffff817cdd00 <bpf_jit_binary_pack_free>
ffffffff81459be2: e9 a1 fe ff ff       	jmp	0xffffffff81459a88 <bpf_int_jit_compile+0x398>
ffffffff81459be7: 48 c7 44 24 18 00 00 00 00   	movq	$0x0, 0x18(%rsp)
ffffffff81459bf0: e9 8f fb ff ff       	jmp	0xffffffff81459784 <bpf_int_jit_compile+0x94>
ffffffff81459bf5: cc                   	int3
ffffffff81459bf6: cc                   	int3
ffffffff81459bf7: cc                   	int3
ffffffff81459bf8: cc                   	int3
ffffffff81459bf9: cc                   	int3
ffffffff81459bfa: cc                   	int3
ffffffff81459bfb: cc                   	int3
ffffffff81459bfc: cc                   	int3
ffffffff81459bfd: cc                   	int3
ffffffff81459bfe: cc                   	int3
ffffffff81459bff: cc                   	int3
