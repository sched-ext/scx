#pragma once

struct scx_test_map {
	void **keys;
	void **values;
	unsigned int max_entries;
	unsigned int key_size;
	unsigned int value_size;
	int nr;
};

struct scx_percpu_test_map {
	struct scx_test_map *per_cpu_maps;
	int nr_cpus;
};

void scx_test_map_register(struct scx_test_map *map, void *map_ptr);
void *scx_test_map_lookup_elem(void *map, const void *key);
void *scx_test_map_lookup_percpu_elem(void *map, const void *key, int cpu);
int scx_test_map_update_elem(void *map, const void *key, const void *value,
			     unsigned long flags);
struct scx_percpu_test_map *scx_alloc_percpu_test_map(int nr_cpus);
void scx_init_percpu_test_map(struct scx_percpu_test_map *map, unsigned int max_entries,
			      unsigned int key_size, unsigned int value_size);
void scx_register_percpu_test_map(struct scx_percpu_test_map *map, void *map_ptr);
void *scx_test_task_storage_get(void *map, const void *key, void *value,
				unsigned long flags);

/*
 * The kernel doesn't have this, it always does it on it's current CPU, but we
 * need this for unit testing to update a specific cpu's map.
 */
int scx_test_map_update_percpu_elem(void *map, const void *key, const void *value,
				    int cpu, unsigned long flags);

#define MAX_ENTRIES(bpfmap) sizeof(*bpfmap.max_entries) / sizeof((*bpfmap.max_entries)[0])

#define INIT_SCX_TEST_MAP(map, bpfmap) \
	do { \
		(map)->values = NULL; \
		(map)->keys = NULL; \
		(map)->max_entries = MAX_ENTRIES(bpfmap); \
		(map)->key_size = sizeof(typeof(*bpfmap.key)); \
		(map)->value_size = sizeof(typeof(*bpfmap.value)); \
		(map)->nr = 0; \
	} while (0)

#define INIT_SCX_TEST_MAP_FROM_TASK_STORAGE(map, bpfmap) \
	do { \
		(map)->values = NULL; \
		(map)->keys = NULL; \
		(map)->max_entries = 100; \
		(map)->key_size = sizeof(typeof(*bpfmap.key)); \
		(map)->value_size = sizeof(typeof(*bpfmap.value)); \
		(map)->nr = 0; \
	} while (0)

#define INIT_SCX_PERCPU_TEST_MAP(map, bpfmap) \
	scx_init_percpu_test_map(map, MAX_ENTRIES(bpfmap), \
		sizeof(typeof(*bpfmap.key)), sizeof(typeof(*bpfmap.value)))

#define bpf_map_lookup_elem(map, key) scx_test_map_lookup_elem(map, key)
#define bpf_map_lookup_percpu_elem(map, key, cpu) scx_test_map_lookup_percpu_elem(map, key, cpu)
#define bpf_map_update_elem(map, key, value, flags) \
	scx_test_map_update_elem(map, key, value, flags)
#define bpf_task_storage_get(map, task, value, flags) \
	scx_test_task_storage_get(map, task, value, flags)
