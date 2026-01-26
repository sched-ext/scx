#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <bpf_arena_spin_lock.h>
#endif /* __BPF__ */

#define RB_MAXLVL_PRINT (16)

struct rbnode;

typedef struct rbnode __arena rbnode_t;

struct rbnode {
	rbnode_t *parent;
	union {
		struct {
			rbnode_t *left;
			rbnode_t *right;
		};

		rbnode_t *child[2];
	};
	uint64_t key;
	/* Used as a linked list or to store KV pairs. */
	union {
		rbnode_t *next;
		uint64_t value;
	};
	bool is_red;
};

/* 
 * Does the rbtree allocate is own nodes, or do they get
 * allocated by the caller?
 */
enum rbtree_alloc {
	RB_ALLOC,
	RB_NOALLOC,
};

/*
 * Specify the behavior of rbtree insertions when the key is
 * already present in the tree.
 *
 * RB_DEFAULT: Default behavior, reject the new insert.
 *
 * RB_UPDATE: Update the existing value in the rbtree.
 * This updates the node itself, not just the value in
 * the existing node.
 *
 * RB_DUPLICATE: Allow nodes with identical keys in the rbtree.
 * Finding/popping/removing a key acts on any of the nodes
 * with the appropriate key - there is no ordering by time
 * of insertion.
 */
enum rbtree_insert_mode {
	RB_DEFAULT,
	RB_UPDATE,
	RB_DUPLICATE,
};

struct rbtree {
	rbnode_t *root;
	rbnode_t *freelist;
	enum rbtree_alloc alloc;
	enum rbtree_insert_mode insert;
};

typedef struct rbtree __arena rbtree_t;
#ifdef __BPF__
u64 rb_create_internal(enum rbtree_alloc alloc, enum rbtree_insert_mode insert);
#define rb_create(alloc, insert) ((rbtree_t *)rb_create_internal((alloc), (insert)))

int rb_destroy(rbtree_t *rbtree);
int rb_insert(rbtree_t *rbtree, u64 key, u64 value);
int rb_remove(rbtree_t *rbtree, u64 key);
int rb_find(rbtree_t *rbtree, u64 key, u64 *value);
int rb_print(rbtree_t *rbtree);
int rb_least(rbtree_t *rbtree, u64 *key, u64 *value);
int rb_pop(rbtree_t *rbtree, u64 *key, u64 *value);

int rb_insert_node(rbtree_t *rbtree, rbnode_t *node);
int rb_remove_node(rbtree_t *rbtree, rbnode_t *node);
u64 rb_node_alloc_internal(rbtree_t *rbtree, u64 key, u64 value);
#define rb_node_alloc(rbtree, key, value) ((rbnode_t *)rb_node_alloc_internal((rbtree), (key), (value)))
int rb_node_free(rbtree_t *rbtree, rbnode_t *rbnode);

int rb_integrity_check(rbtree_t *rbtree);

#endif /* __BPF__ */
