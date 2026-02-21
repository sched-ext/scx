/*
 * sim_sigfpe.c - SIGFPE handler for BPF division-by-zero semantics
 *
 * BPF division by zero returns 0; native C crashes with SIGFPE.
 * This handler skips the faulting div/idiv instruction and sets
 * RAX=0, RDX=0 to match BPF semantics.
 *
 * x86-64 only. The handler decodes the instruction at RIP to
 * determine its length (REX prefix + opcode + ModR/M + SIB/disp).
 *
 * This file does NOT include sim_wrapper.h or vmlinux.h to avoid
 * conflicts with <signal.h> type definitions.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <ucontext.h>
#include <string.h>

static void sim_sigfpe_handler(int sig, siginfo_t *info, void *ctx)
{
	ucontext_t *uc = (ucontext_t *)ctx;
	mcontext_t *mc = &uc->uc_mcontext;
	unsigned char *rip = (unsigned char *)mc->gregs[REG_RIP];
	int off = 0;

	(void)sig;
	(void)info;

	/* Skip REX prefix (0x40-0x4F) */
	if ((rip[off] & 0xf0) == 0x40)
		off++;

	/* F6 = div/idiv r/m8; F7 = div/idiv r/m{16,32,64} */
	if (rip[off] == 0xF6 || rip[off] == 0xF7) {
		unsigned char modrm, mod, rm;

		off++; /* skip opcode */
		modrm = rip[off];
		mod = (modrm >> 6) & 3;
		rm = modrm & 7;
		off++; /* skip ModR/M */

		if (mod == 0) {
			if (rm == 4) off++; /* SIB byte */
			if (rm == 5) off += 4; /* disp32 */
		} else if (mod == 1) {
			if (rm == 4) off++; /* SIB byte */
			off++; /* disp8 */
		} else if (mod == 2) {
			if (rm == 4) off++; /* SIB byte */
			off += 4; /* disp32 */
		}
		/* mod == 3: register-direct, no extra bytes */
	}

	/* Set quotient (RAX) and remainder (RDX) to 0 */
	mc->gregs[REG_RAX] = 0;
	mc->gregs[REG_RDX] = 0;
	mc->gregs[REG_RIP] = (greg_t)(rip + off);
}

void sim_install_sigfpe_handler(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sim_sigfpe_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGFPE, &sa, NULL);
}
