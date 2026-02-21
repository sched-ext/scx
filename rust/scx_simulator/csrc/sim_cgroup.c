/*
 * sim_cgroup.c - Cgroup CSS iterator for the simulator
 *
 * Implements sim_css_next() which walks the cgroup tree in pre-order
 * (depth-first, parent-before-children) to support bpf_for_each(css, ...).
 *
 * The iterator state is maintained in a global array of cgroup pointers
 * that is populated from Rust before iteration begins.
 */
#include "sim_wrapper.h"

/* Forward declaration for libc functions */
extern void *memset(void *s, int c, unsigned long n);

/*
 * CSS iterator state.
 *
 * The Rust code populates sim_css_list[] with cgroup pointers in pre-order
 * before iteration. sim_css_next() walks through the list sequentially.
 */
#define MAX_CSS_ITER_CGROUPS 256

static struct cgroup *sim_css_list[MAX_CSS_ITER_CGROUPS];
static int sim_css_count;
static int sim_css_index;
static struct cgroup *sim_css_root;

/*
 * Reset the CSS iterator state (called from Rust before populating).
 */
void sim_css_iter_reset(void)
{
	memset(sim_css_list, 0, sizeof(sim_css_list));
	sim_css_count = 0;
	sim_css_index = 0;
	sim_css_root = NULL;
}

/*
 * Add a cgroup to the iteration list (called from Rust in pre-order).
 */
void sim_css_iter_add(void *cgrp)
{
	if (sim_css_count < MAX_CSS_ITER_CGROUPS && cgrp)
		sim_css_list[sim_css_count++] = (struct cgroup *)cgrp;
}

/*
 * Set the root cgroup for the current iteration.
 */
void sim_css_iter_set_root(void *root)
{
	sim_css_root = (struct cgroup *)root;
}

/*
 * Get the next CSS in pre-order iteration.
 *
 * This is called from the _bpf_for_each_css macro:
 *   - root: the root cgroup's CSS (ignored, we use sim_css_root)
 *   - prev: the previously returned CSS, or NULL to start iteration
 *
 * Returns the next cgroup's &self (CSS), or NULL when done.
 *
 * The iterator expects the Rust side to have populated sim_css_list[]
 * with all descendant cgroups in pre-order before iteration starts.
 */
struct cgroup_subsys_state *sim_css_next(
	struct cgroup_subsys_state *root,
	struct cgroup_subsys_state *prev)
{
	struct cgroup *cgrp;

	(void)root; /* We use sim_css_root set by Rust */

	if (prev == NULL) {
		/* Start of iteration */
		sim_css_index = 0;
	} else {
		/* Continue iteration */
		sim_css_index++;
	}

	if (sim_css_index >= sim_css_count)
		return NULL;

	cgrp = sim_css_list[sim_css_index];
	if (!cgrp)
		return NULL;

	/* Return the cgroup's self CSS */
	return &cgrp->self;
}

/*
 * Check if a cgroup is dying (percpu_count_ptr has the dying bit set).
 * In our simulator, cgroups are never dying, so this always returns false.
 */
bool sim_cgroup_is_dying(void *cgrp)
{
	(void)cgrp;
	return false;
}
