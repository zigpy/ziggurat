//! Sorted-`Vec` drop-in replacements for `BTreeMap`/`BTreeSet`.
//!
//! The stack's tables hold tens of entries, but each `BTreeMap<K, V>`
//! instantiation costs ~4 KB of node-rebalancing code on the embedded build.
//! A sorted `Vec` with binary search keeps the same API subset and ordered
//! iteration at a fraction of the code size.

use alloc::vec::Vec;

pub struct FlatMap<K, V> {
    entries: Vec<(K, V)>,
}

impl<K: Ord, V> FlatMap<K, V> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn index_of(&self, key: &K) -> Result<usize, usize> {
        self.entries.binary_search_by(|(k, _)| k.cmp(key))
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.index_of(key).ok().map(|i| &self.entries[i].1)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.index_of(key).ok().map(|i| &mut self.entries[i].1)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.index_of(key).is_ok()
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.index_of(&key) {
            Ok(i) => Some(core::mem::replace(&mut self.entries[i].1, value)),
            Err(i) => {
                self.entries.insert(i, (key, value));
                None
            }
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.index_of(key).ok().map(|i| self.entries.remove(i).1)
    }

    pub fn pop_first(&mut self) -> Option<(K, V)> {
        if self.entries.is_empty() {
            None
        } else {
            Some(self.entries.remove(0))
        }
    }

    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        match self.index_of(&key) {
            Ok(index) => Entry::Occupied(OccupiedEntry { map: self, index }),
            Err(index) => Entry::Vacant(VacantEntry {
                map: self,
                index,
                key,
            }),
        }
    }

    pub fn retain(&mut self, mut f: impl FnMut(&K, &mut V) -> bool) {
        self.entries.retain_mut(|(k, v)| f(k, v));
    }
}

impl<K, V> FlatMap<K, V> {
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            inner: self.entries.iter(),
        }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut {
            inner: self.entries.iter_mut(),
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.entries.iter_mut().map(|(_, v)| v)
    }
}

impl<K: Ord, V> Default for FlatMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone, V: Clone> Clone for FlatMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

impl<K: PartialEq, V: PartialEq> PartialEq for FlatMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl<K: Eq, V: Eq> Eq for FlatMap<K, V> {}

impl<K: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for FlatMap<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K: Ord, V, const N: usize> From<[(K, V); N]> for FlatMap<K, V> {
    fn from(entries: [(K, V); N]) -> Self {
        entries.into_iter().collect()
    }
}

impl<K: Ord, V> FromIterator<(K, V)> for FlatMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::new();
        map.extend(iter);
        map
    }
}

impl<K: Ord, V> Extend<(K, V)> for FlatMap<K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (key, value) in iter {
            self.insert(key, value);
        }
    }
}

impl<K, V> IntoIterator for FlatMap<K, V> {
    type Item = (K, V);
    type IntoIter = alloc::vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a FlatMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, K, V> IntoIterator for &'a mut FlatMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

pub struct Iter<'a, K, V> {
    inner: core::slice::Iter<'a, (K, V)>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (k, v))
    }
}

pub struct IterMut<'a, K, V> {
    inner: core::slice::IterMut<'a, (K, V)>,
}

impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (&*k, v))
    }
}

pub enum Entry<'a, K: Ord, V> {
    Occupied(OccupiedEntry<'a, K, V>),
    Vacant(VacantEntry<'a, K, V>),
}

impl<'a, K: Ord, V> Entry<'a, K, V> {
    pub fn or_insert_with(self, default: impl FnOnce() -> V) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }

    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        self.or_insert_with(V::default)
    }

    pub fn and_modify(mut self, f: impl FnOnce(&mut V)) -> Self {
        if let Entry::Occupied(ref mut entry) = self {
            f(entry.get_mut());
        }
        self
    }
}

pub struct OccupiedEntry<'a, K, V> {
    map: &'a mut FlatMap<K, V>,
    index: usize,
}

impl<'a, K, V> OccupiedEntry<'a, K, V> {
    pub fn get_mut(&mut self) -> &mut V {
        &mut self.map.entries[self.index].1
    }

    pub fn into_mut(self) -> &'a mut V {
        &mut self.map.entries[self.index].1
    }

    pub fn insert(&mut self, value: V) -> V {
        core::mem::replace(self.get_mut(), value)
    }
}

pub struct VacantEntry<'a, K, V> {
    map: &'a mut FlatMap<K, V>,
    index: usize,
    key: K,
}

impl<'a, K, V> VacantEntry<'a, K, V> {
    pub fn insert(self, value: V) -> &'a mut V {
        self.map.entries.insert(self.index, (self.key, value));
        &mut self.map.entries[self.index].1
    }
}

pub struct FlatSet<T> {
    map: FlatMap<T, ()>,
}

impl<T: Ord> FlatSet<T> {
    pub const fn new() -> Self {
        Self {
            map: FlatMap::new(),
        }
    }

    /// Returns whether the value was newly inserted.
    pub fn insert(&mut self, value: T) -> bool {
        self.map.insert(value, ()).is_none()
    }

    pub fn contains(&self, value: &T) -> bool {
        self.map.contains_key(value)
    }

    pub fn remove(&mut self, value: &T) -> bool {
        self.map.remove(value).is_some()
    }
}

impl<T> FlatSet<T> {
    pub const fn len(&self) -> usize {
        self.map.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.map.keys()
    }
}

impl<T: Ord> Default for FlatSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for FlatSet<T> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

impl<T: PartialEq> PartialEq for FlatSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl<T: Eq> Eq for FlatSet<T> {}

impl<T: core::fmt::Debug> core::fmt::Debug for FlatSet<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<T: Ord, const N: usize> From<[T; N]> for FlatSet<T> {
    fn from(values: [T; N]) -> Self {
        values.into_iter().collect()
    }
}

impl<T: Ord> FromIterator<T> for FlatSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }
}

impl<T: Ord> Extend<T> for FlatSet<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for value in iter {
            self.insert(value);
        }
    }
}

impl<'a, T> IntoIterator for &'a FlatSet<T> {
    type Item = &'a T;
    type IntoIter = core::iter::Map<core::slice::Iter<'a, (T, ())>, fn(&'a (T, ())) -> &'a T>;

    fn into_iter(self) -> Self::IntoIter {
        let project: fn(&'a (T, ())) -> &'a T = |(v, ())| v;
        self.map.entries.iter().map(project)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_flat_map() {
        let mut map: FlatMap<u16, &str> = FlatMap::new();
        assert!(map.is_empty());
        assert_eq!(map.insert(3, "three"), None);
        assert_eq!(map.insert(1, "one"), None);
        assert_eq!(map.insert(2, "two"), None);
        assert_eq!(map.insert(2, "TWO"), Some("two"));
        assert_eq!(map.len(), 3);

        // Iteration is sorted by key, like BTreeMap
        assert_eq!(
            map.iter().collect::<alloc::vec::Vec<_>>(),
            [(&1, &"one"), (&2, &"TWO"), (&3, &"three")]
        );

        assert_eq!(map.get(&2), Some(&"TWO"));
        assert!(map.contains_key(&3));
        assert!(!map.contains_key(&4));
        assert_eq!(map.remove(&2), Some("TWO"));
        assert_eq!(map.remove(&2), None);
        assert_eq!(map.pop_first(), Some((1, "one")));

        *map.entry(5).or_insert_with(|| "five") = "FIVE";
        map.entry(5)
            .and_modify(|v| *v = "cinq")
            .or_insert_with(|| "?");
        assert_eq!(map.get(&5), Some(&"cinq"));
        match map.entry(5) {
            Entry::Occupied(mut entry) => assert_eq!(entry.insert("cinco"), "cinq"),
            Entry::Vacant(_) => unreachable!(),
        }

        map.retain(|&k, _| k == 5);
        assert_eq!(map.len(), 1);

        map.clear();
        assert_eq!(map.pop_first(), None);
    }

    #[test]
    fn test_flat_set() {
        let mut set = FlatSet::from([3u16, 1]);
        assert!(set.insert(2));
        assert!(!set.insert(2));
        assert_eq!(set.iter().collect::<alloc::vec::Vec<_>>(), [&1, &2, &3]);
        assert!(set.contains(&3));
        assert!(set.remove(&3));
        assert!(!set.remove(&3));
        assert_eq!(set.len(), 2);
    }
}
