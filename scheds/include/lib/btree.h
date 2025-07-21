#pragma once

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#define BT_MAXLVL_PRINT (10)
#define BT_LEAFSZ 5

#define BT_F_LEAF (0x1)
#define BT_F_ROOT (0x2)

struct bt_node;
typedef struct bt_node __arena bt_node;

struct bt_node {
	u64 keys[BT_LEAFSZ];
	u64 values[BT_LEAFSZ];
	u64 flags;
	u64 numkeys;
	bt_node *parent;
};

struct btree {
	bt_node *root;
	/* XXXETSAL Locking */
};

typedef struct btree __arena btree_t;

u64 bt_create_internal(void);
#define bt_create() ((btree_t *)(bt_create_internal()))

int bt_destroy(btree_t *btree);
int bt_insert(btree_t *btree, u64 key, u64 value, bool update);
int bt_remove(btree_t *btree, u64 key);
int bt_find(btree_t *btree, u64 key, u64 *value);
int bt_print(btree_t *btree);

/* XXXETSAL Iterators */
