#pragma once

/*
 * Loop counters the verifier cannot see through.
 *
 * A may_goto loop converges when the state at its head is within the state
 * of a previous iteration. A counter tracked as a precise constant prevents
 * that convergence: every iteration creates a new state, and the verifier
 * unrolls the loop until it runs out of budget whenever the counter feeds an
 * operation that requires precision.
 *
 * Loading a writable global gives the verifier an unknown scalar while its
 * runtime value remains zero. Loading it only in the initializer is not
 * enough because the loop body can make the counter precise again. Reload it
 * in the increment so the counter's bounds do not shift on each iteration.
 * volatile is required to keep the compiler from hoisting or eliminating the
 * loads, and the value must remain non-const so the verifier cannot resolve
 * it. The variable is file-local so loaders cannot modify it through the
 * generated skeleton. Its runtime value must never be changed from zero.
 *
 * bpf_for() avoids this verifier behavior too, but calls bpf_iter_num_next()
 * on every iteration. bpf_arena_for() is intended for hot scheduler walks
 * where that cost matters. @var must be no wider than u32, and @start and
 * @end must be representable as u32.
 */
static volatile u32 bpf_arena_loop_zero;

#define __bpf_arena_loop_start(var, start)				\
	({								\
		_Static_assert(sizeof(var) <= sizeof(u32),		\
			       "bpf_arena_for() index must fit in u32");	\
		(start) + bpf_arena_loop_zero;				\
	})

#define bpf_arena_for(var, start, end)					\
	for (var = __bpf_arena_loop_start(var, start);			\
	     var < (end) && can_loop;					\
	     var += 1 + bpf_arena_loop_zero)
