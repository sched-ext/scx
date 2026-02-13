# Performance Optimization Guide

This document provides guidance on high-performance Rust patterns, with a focus on zero-copy patterns and minimizing allocations.

## Zero-Copy Patterns and Best Practices

### 1. Avoid Unnecessary `clone()`

**Problem**: Cloning creates deep copies of data, which is expensive for large structures.

**Solution**: Use references and manage lifetimes appropriately.

```rust
// BAD: Unnecessary clone
fn process_items(items: &Vec<Item>) -> Vec<Item> {
    items.clone()
}

// GOOD: Return reference or iterator
fn process_items(items: &Vec<Item>) -> &[Item] {
    items.as_slice()
}

// EVEN BETTER: Return iterator for lazy evaluation
fn process_items(items: &Vec<Item>) -> impl Iterator<Item = &Item> {
    items.iter().filter(|i| i.is_active())
}
```

**When to use `.iter().cloned()` vs `.clone().iter()`**:
- `v.iter().cloned()` creates a borrowed iterator that clones items on-the-fly (no Vec allocation)
- `v.clone().iter()` clones the entire Vec first (expensive heap allocation)
- Always prefer `v.iter().cloned()` when you need owned values from iteration

### 2. Avoid Unnecessary `collect()`

**Problem**: Calling `collect()` allocates a new collection when the data might only be iterated once.

**Solution**: Return iterator types (`impl Iterator<Item=T>`) instead of `Vec<T>`.

```rust
// BAD: Unnecessary collect
fn get_active(items: &[Item]) -> Vec<&Item> {
    items.iter().filter(|i| i.is_active()).collect()
}

// GOOD: Return iterator
fn get_active(items: &[Item]) -> impl Iterator<Item = &Item> + '_ {
    items.iter().filter(|i| i.is_active())
}
```

### 3. Chain Iterator Operations

**Problem**: Multiple `collect()` calls between operations create temporary collections.

**Solution**: Chain iterator methods together for a single traversal.

```rust
// BAD: Multiple collects
let filtered: Vec<_> = items.iter().filter(|i| i.is_active()).collect();
let mapped: Vec<_> = filtered.iter().map(|i| i.id()).collect();

// GOOD: Chained operations
let ids = items.iter()
    .filter(|i| i.is_active())
    .map(|i| i.id());
```

### 4. Use Slices Instead of Owned Types

**Problem**: Taking owned `String` or `Vec<T>` when you only need to read.

**Solution**: Use `&str` instead of `&String`, and `&[T]` instead of `&Vec<T>`.

```rust
// BAD: Unnecessary specificity
fn print_name(name: &String) { }
fn process(items: &Vec<Item>) { }

// GOOD: Use slices
fn print_name(name: &str) { }
fn process(items: &[Item]) { }
```

### 5. Implement `size_hint()` for Custom Iterators

**Problem**: Collections can't pre-allocate if they don't know the iterator size.

**Solution**: Implement `Iterator::size_hint()` or `ExactSizeIterator::len()` when possible.

### 6. Arena Allocation for Short-Lived Objects

**Problem**: Frequent small allocations and deallocations fragment memory and slow down the allocator.

**Solution**: Use arena allocators (like `bumpalo` or `typed-arena`) for short-lived, bulk allocations.

**Benefits**:
- Allocation is just pointer increment (extremely fast)
- Deallocation is bulk operation (drop entire arena)
- Better cache locality (adjacent allocations)

### 7. Use `SmallVec` for Expected-Small Collections

**Problem**: Many structures have 0-2 items but we allocate on the heap for any collection.

**Solution**: Use `smallvec::SmallVec` to avoid heap allocation for small counts.

```rust
use smallvec::SmallVec;

// Stores up to 4 items inline, only heap-allocates if more
type ShortList = SmallVec<[Item; 4]>;
```

### 8. Prefer Unboxed Enums Over `Vec<Box<dyn Trait>>`

**Problem**: Vectors of boxed trait objects create pointer chasing and heap fragmentation.

**Solution**: Use enums with data variants when the set of types is closed.

```rust
// Less efficient: Boxed trait objects
Vec<Box<dyn Action>>

// More efficient: Unboxed enum
enum Action {
    Insert { dsq: DsqId, task: Pid },
    Dispatch { cpu: CpuId },
    // ... more variants
}
```

Vectors of enums are stored contiguously without pointer indirection.

### 9. Cow (Clone-on-Write) for Conditional Ownership

**Problem**: Sometimes you need owned data, sometimes borrowed, leading to unnecessary clones.

**Solution**: Use `std::borrow::Cow` to defer cloning until necessary.

## Common Anti-Patterns to Avoid

### 1. Returning Fresh Collections

```rust
// BAD: Allocates new Vec every call
pub fn get_items(&self) -> Vec<Id> {
    self.storage.iter().filter(|i| i.matches()).map(|i| i.id).collect()
}

// GOOD: Returns iterator over existing data
pub fn get_items(&self) -> impl Iterator<Item = Id> + '_ {
    self.storage.iter().filter(|i| i.matches()).map(|i| i.id)
}
```

### 2. Cloning to Satisfy the Borrow Checker

```rust
// BAD: Clone to avoid borrow checker
let items = self.list.clone();
self.mutate();
for item in items { /* ... */ }

// GOOD: Collect IDs first (smaller), or restructure
let ids: Vec<_> = self.list.iter().map(|i| i.id).collect();
self.mutate();
for id in ids {
    let item = self.get(id);
    /* ... */
}
```

### 3. Collecting Then Chaining

```rust
// BAD: Collect then iterate again
let step1: Vec<_> = items.iter().filter(|i| i.is_active()).collect();
let step2: Vec<_> = step1.iter().filter(|i| i.is_ready()).collect();

// GOOD: Chain without intermediate collection
let result = items.iter()
    .filter(|i| i.is_active())
    .filter(|i| i.is_ready());
```

## References

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Rust Performance Pitfalls](https://llogiq.github.io/2017/06/01/perf-pitfalls.html)
- [Arenas in Rust](https://manishearth.github.io/blog/2021/03/15/arenas-in-rust/)
