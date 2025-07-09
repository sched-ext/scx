#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <linux/bpf.h>

#include "scx_test_map.h"

enum {
	SCX_MAP_TYPE_NORMAL,
	SCX_MAP_TYPE_PERCPU,
};

struct scx_map_type {
	void *map_ptr;
	int map_type;
};

struct scx_map_entry {
	void *map_ptr;
	struct scx_test_map *map;
};

struct scx_percpu_map_entry {
	void *map_ptr;
	struct scx_percpu_test_map *map;
};

static __thread struct scx_map_entry *scx_map_entries = NULL;
static __thread int scx_map_entries_count = 0;

static __thread struct scx_percpu_map_entry *scx_percpu_map_entries = NULL;
static __thread int scx_percpu_map_entries_count = 0;

static __thread struct scx_map_type *scx_map_types = NULL;
static __thread int scx_map_types_count = 0;

static void scx_regsiter_map_type(void *map_ptr, int map_type)
{
	int index = scx_map_types_count;

	scx_map_types_count++;
	scx_map_types = reallocarray(scx_map_types, scx_map_types_count,
				    sizeof(struct scx_map_type));
	if (!scx_map_types) {
		perror("Failed to allocate memory for scx_map_types");
		exit(EXIT_FAILURE);
	}

	scx_map_types[index].map_ptr = map_ptr;
	scx_map_types[index].map_type = map_type;
}

static struct scx_test_map *scx_percpu_entry(const void *map_ptr, int cpu)
{
	for (int i = 0; i < scx_percpu_map_entries_count; i++) {
		if (scx_percpu_map_entries[i].map_ptr == map_ptr) {
			return &scx_percpu_map_entries[i].map->per_cpu_maps[cpu];
		}
	}
	return NULL;
}

static struct scx_test_map *scx_normal_entry(const void *map_ptr)
{
	for (int i = 0; i < scx_map_entries_count; i++) {
		if (scx_map_entries[i].map_ptr == map_ptr) {
			return scx_map_entries[i].map;
		}
	}
	return NULL;
}

static struct scx_test_map *scx_test_map_lookup(const void *map_ptr, int cpu)
{
	for (int i = 0; i < scx_map_types_count; i++) {
		if (scx_map_types[i].map_ptr == map_ptr) {
			if (scx_map_types[i].map_type == SCX_MAP_TYPE_PERCPU) {
				return scx_percpu_entry(map_ptr, cpu);
			} else if (scx_map_types[i].map_type == SCX_MAP_TYPE_NORMAL) {
				return scx_normal_entry(map_ptr);
			}
		}
	}
	return NULL;
}

void *scx_test_map_lookup_percpu_elem(void *map, const void *key, int cpu)
{
	struct scx_test_map *test_map = scx_test_map_lookup(map, cpu);
	if (!test_map) {
		return NULL;
	}

	for (int i = 0; i < test_map->nr; i++) {
		if (memcmp(&test_map->keys[i], key, test_map->key_size) == 0) {
			return &test_map->values[i];
		}
	}

	return NULL;
}

void *scx_test_map_lookup_elem(void *map, const void *key)
{
	struct scx_test_map *test_map = scx_test_map_lookup(map, 0);
	if (!test_map) {
		return NULL;
	}

	for (int i = 0; i < test_map->nr; i++) {
		if (memcmp(&test_map->keys[i], key, test_map->key_size) == 0) {
			return &test_map->values[i];
		}
	}

	return NULL;
}

static int map_update_elem(struct scx_test_map *test_map, const void *key,
			    const void *value, unsigned long flags)
{
	int index;

	for (int i = 0; i < test_map->nr; i++) {
		if (memcmp(&test_map->keys[i], key, test_map->key_size) == 0) {
			if (flags & BPF_NOEXIST) {
				return -1;
			}
			memcpy(&test_map->values[i], value, test_map->value_size);
			return 0;
		}
	}

	if (flags & BPF_EXIST) {
		return -1;
	}

	if (test_map->nr < 0) {
		return -1;
	}
	if ((unsigned int)test_map->nr >= test_map->max_entries) {
		return -1;
	}

	index = test_map->nr;
	test_map->nr++;

	test_map->keys = reallocarray(test_map->keys, test_map->nr, test_map->key_size);
	if (!test_map->keys) {
		perror("Failed to allocate memory for keys");
		exit(EXIT_FAILURE);
	}
	test_map->values = reallocarray(test_map->values, test_map->nr, test_map->value_size);
	if (!test_map->values) {
		perror("Failed to allocate memory for values");
		exit(EXIT_FAILURE);
	}
	memcpy(&test_map->keys[index], key, test_map->key_size);
	memcpy(&test_map->values[index], value, test_map->value_size);
	return 0;
}

void *scx_test_task_storage_get(void *map, const void *key, void *value,
				unsigned long flags)
{
	void *newvalue = NULL;
	struct scx_test_map *test_map;

	void *ret = scx_test_map_lookup_elem(map, key);
	if (ret)
		return ret;

	if (!(flags & BPF_LOCAL_STORAGE_GET_F_CREATE))
		return NULL;

	test_map = scx_test_map_lookup(map, 0);

	/*
	 * If no value is specified we have to allocate an empty value and
	 * insert it.
	 */
	if (!value) {
		newvalue = calloc(1, test_map->value_size);
		if (!newvalue) {
			perror("Failed to allocate empty value for scx_test_task_storage_get");
			exit(EXIT_FAILURE);
		}
		value = newvalue;
	}

	map_update_elem(test_map, key, value, BPF_ANY);
	if (newvalue)
		free(newvalue);

	return scx_test_map_lookup_elem(map, key);
}


int scx_test_map_update_elem(void *map, const void *key, const void *value,
			     unsigned long flags)
{
	struct scx_test_map *test_map = scx_test_map_lookup(map, 0);

	if (!test_map) {
		return -1;
	}

	return map_update_elem(test_map, key, value, flags);
}

int scx_test_map_update_percpu_elem(void *map, const void *key, const void *value,
				    int cpu, unsigned long flags)
{
	struct scx_test_map *test_map = scx_test_map_lookup(map, cpu);

	if (!test_map) {
		return -1;
	}

	return map_update_elem(test_map, key, value, flags);
}

void scx_test_map_register(struct scx_test_map *map, void *map_ptr)
{
	int index = scx_map_entries_count;

	scx_map_entries_count++;
	scx_map_entries = reallocarray(scx_map_entries, scx_map_entries_count,
				       sizeof(struct scx_map_entry));
	if (!scx_map_entries) {
		perror("Failed to allocate memory for scx_map_entries");
		exit(EXIT_FAILURE);
	}

	scx_map_entries[index].map_ptr = map_ptr;
	scx_map_entries[index].map = map;
	scx_regsiter_map_type(map_ptr, SCX_MAP_TYPE_NORMAL);
}

struct scx_percpu_test_map *scx_alloc_percpu_test_map(int nr_cpus)
{
	struct scx_percpu_test_map *map = malloc(sizeof(struct scx_percpu_test_map));
	if (!map) {
		perror("Failed to allocate memory for scx_percpu_test_map");
		exit(EXIT_FAILURE);
	}
	map->per_cpu_maps = calloc(nr_cpus, sizeof(struct scx_test_map));
	if (!map->per_cpu_maps) {
		perror("Failed to allocate memory for per_cpu_maps");
		free(map);
		exit(EXIT_FAILURE);
	}
	map->nr_cpus = nr_cpus;
	return map;
}

void scx_init_percpu_test_map(struct scx_percpu_test_map *map, unsigned int max_entries,
			      unsigned int key_size, unsigned int value_size)
{
	for (int i = 0; i < map->nr_cpus; i++) {
		map->per_cpu_maps[i].keys = NULL;
		map->per_cpu_maps[i].values = NULL;
		map->per_cpu_maps[i].max_entries = max_entries;
		map->per_cpu_maps[i].key_size = key_size;
		map->per_cpu_maps[i].value_size = value_size;
		map->per_cpu_maps[i].nr = 0;
	}
}

void scx_register_percpu_test_map(struct scx_percpu_test_map *map, void *map_ptr)
{
	int index = scx_percpu_map_entries_count;

	scx_percpu_map_entries_count++;
	scx_percpu_map_entries = reallocarray(scx_percpu_map_entries, scx_percpu_map_entries_count,
					      sizeof(struct scx_percpu_map_entry));
	if (!scx_percpu_map_entries) {
		perror("Failed to allocate memory for scx_percpu_map_entries");
		exit(EXIT_FAILURE);
	}

	scx_percpu_map_entries[index].map_ptr = map_ptr;
	scx_percpu_map_entries[index].map = map;
	scx_regsiter_map_type(map_ptr, SCX_MAP_TYPE_PERCPU);
}
