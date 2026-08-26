/*
 * cakeload -- the synthetic load regime, with a comm you cannot mistake.
 *
 * Regime is the first covariate in this project: vkd3d_fence wake p99 is
 * 3.16us on a quiet host and ~50us under load, an 84x span, so a game
 * measurement on a calm machine measures the case with nothing to fix. Every
 * scored rotation therefore runs N busy threads alongside the game.
 *
 * The reason this is a compiled binary rather than a shell one-liner is
 * ATTRIBUTION. An ad-hoc `python3 -c` or `sh -c` spinner shares its comm with
 * the capture wrapper and half the harness, and a trace cannot tell them
 * apart. That cost a false finding on 2026-08-01: 793% of a core was read as
 * the measurement instrument contaminating the run when it was the load doing
 * exactly its job. A distinct comm makes the same mistake impossible.
 *
 * Ignores SIGHUP so a rotation surviving a terminal hangup keeps its load, and
 * writes every child pid so the caller can verify N/N alive BEFORE and AFTER
 * every arm -- an early rig silently lost spinners mid-rotation and produced
 * an arm at 7% external CPU next to arms at 27%, which inverted a verdict.
 *
 * Build:  cc -O2 -o cakeload cakeload.c
 * Usage:  cakeload <nr_threads> <pidfile>     (SIGTERM/SIGINT to stop)
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void on_stop(int sig)
{
	(void)sig;
	stop = 1;
}

int main(int argc, char **argv)
{
	long nr, i;
	FILE *pf;
	pid_t *kids;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <nr_threads> <pidfile>\n", argv[0]);
		return 2;
	}
	nr = strtol(argv[1], NULL, 10);
	if (nr < 1 || nr > 4096) {
		fprintf(stderr, "nr_threads out of range: %s\n", argv[1]);
		return 2;
	}
	kids = calloc((size_t)nr, sizeof(*kids));
	if (!kids)
		return 1;

	signal(SIGHUP, SIG_IGN);

	for (i = 0; i < nr; i++) {
		pid_t p = fork();

		if (p < 0) {
			perror("fork");
			return 1;
		}
		if (p == 0) {
			signal(SIGHUP, SIG_IGN);
			signal(SIGTERM, on_stop);
			signal(SIGINT, on_stop);
			while (!stop)
				;
			_exit(0);
		}
		kids[i] = p;
	}

	pf = fopen(argv[2], "w");
	if (!pf) {
		perror("pidfile");
		return 1;
	}
	for (i = 0; i < nr; i++)
		fprintf(pf, "%d\n", (int)kids[i]);
	fclose(pf);

	/*
	 * The parent must not spin: it would be an (N+1)th load thread that the
	 * caller's N/N liveness check does not know about.
	 */
	signal(SIGTERM, on_stop);
	signal(SIGINT, on_stop);
	while (!stop)
		pause();

	for (i = 0; i < nr; i++)
		kill(kids[i], SIGTERM);
	for (i = 0; i < nr; i++)
		waitpid(kids[i], NULL, 0);
	free(kids);
	return 0;
}
