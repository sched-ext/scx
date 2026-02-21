//! Deterministic HashMap with sorted iteration.
//!
//! Regular HashMap iteration order depends on internal hash state, which can
//! vary between runs even with identical inputs. This causes non-determinism
//! in simulations that must be reproducible with a given seed.
//!
//! `DetHashMap` wraps `HashMap` and provides iteration methods that sort keys,
//! ensuring consistent ordering at the cost of O(n log n) iteration.
//!
//! # When to use
//!
//! - **Use `DetHashMap`** when lookup performance matters (O(1)) but iteration
//!   is infrequent and must be deterministic.
//! - **Use `BTreeMap`** when iteration is frequent or the primary operation.
//! - **Use `HashMap`** only when iteration order doesn't matter.

use std::collections::HashMap;
use std::hash::Hash;

/// A HashMap wrapper that provides deterministic iteration order.
///
/// All lookup operations delegate directly to the inner HashMap with O(1)
/// performance. Iteration methods sort keys before returning, making them
/// O(n log n) but deterministic.
///
/// # Example
///
/// ```
/// use scx_simulator::det_hashmap::DetHashMap;
///
/// let mut map: DetHashMap<i32, &str> = DetHashMap::new();
/// map.insert(3, "three");
/// map.insert(1, "one");
/// map.insert(2, "two");
///
/// // Iteration is always in sorted key order
/// let keys: Vec<_> = map.iter_sorted().map(|(k, _)| *k).collect();
/// assert_eq!(keys, vec![1, 2, 3]);
/// ```
#[derive(Debug, Clone)]
pub struct DetHashMap<K, V>(HashMap<K, V>);

impl<K, V> DetHashMap<K, V>
where
    K: Eq + Hash,
{
    /// Creates an empty DetHashMap.
    pub fn new() -> Self {
        DetHashMap(HashMap::new())
    }

    /// Inserts a key-value pair, returning the previous value if present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.0.insert(key, value)
    }

    /// Returns a reference to the value for the given key.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.0.get(key)
    }

    /// Returns a mutable reference to the value for the given key.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.0.get_mut(key)
    }

    /// Removes a key-value pair, returning the value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.0.remove(key)
    }

    /// Returns true if the map contains the given key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.0.contains_key(key)
    }

    /// Returns the number of entries in the map.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Removes all entries from the map.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Gets the entry for in-place manipulation.
    pub fn entry(&mut self, key: K) -> std::collections::hash_map::Entry<'_, K, V> {
        self.0.entry(key)
    }
}

impl<K, V> DetHashMap<K, V>
where
    K: Eq + Hash + Ord + Copy,
{
    /// Iterates over key-value pairs in sorted key order.
    ///
    /// This allocates a Vec to sort keys, making it O(n log n).
    /// Use sparingly for determinism-critical iteration.
    pub fn iter_sorted(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut keys: Vec<&K> = self.0.keys().collect();
        keys.sort();
        keys.into_iter().map(move |k| (k, &self.0[k]))
    }

    /// Iterates over keys in sorted order.
    pub fn keys_sorted(&self) -> impl Iterator<Item = &K> {
        let mut keys: Vec<&K> = self.0.keys().collect();
        keys.sort();
        keys.into_iter()
    }

    /// Iterates over values in sorted key order.
    pub fn values_sorted(&self) -> impl Iterator<Item = &V> {
        self.iter_sorted().map(|(_, v)| v)
    }

    /// Drains all entries, returning them in sorted key order.
    pub fn drain_sorted(&mut self) -> impl Iterator<Item = (K, V)> {
        let mut entries: Vec<(K, V)> = self.0.drain().collect();
        entries.sort_by_key(|(k, _)| *k);
        entries.into_iter()
    }
}

impl<K, V> Default for DetHashMap<K, V>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sorted_iteration() {
        let mut map: DetHashMap<i32, &str> = DetHashMap::new();
        map.insert(5, "five");
        map.insert(1, "one");
        map.insert(3, "three");
        map.insert(2, "two");
        map.insert(4, "four");

        let keys: Vec<i32> = map.iter_sorted().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_drain_sorted() {
        let mut map: DetHashMap<i32, i32> = DetHashMap::new();
        map.insert(3, 30);
        map.insert(1, 10);
        map.insert(2, 20);

        let entries: Vec<(i32, i32)> = map.drain_sorted().collect();
        assert_eq!(entries, vec![(1, 10), (2, 20), (3, 30)]);
        assert!(map.is_empty());
    }

    #[test]
    fn test_basic_operations() {
        let mut map: DetHashMap<i32, &str> = DetHashMap::new();
        assert!(map.is_empty());

        map.insert(1, "one");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&1), Some(&"one"));
        assert!(map.contains_key(&1));

        map.remove(&1);
        assert!(!map.contains_key(&1));
    }
}
