// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Cpumask
//!
//! A crate that allows creating, reading, and manipulating cpumasks.
//!
//! Cpumask
//! -------
//!
//! A Cpumask object is simply a BitVec of u64's, along with a series of helper
//! functions for creating, manipulating, and reading these BitVec objects.
//!
//! Empty Cpumasks can be created directly, or they can be created from a
//! hexadecimal string:
//!
//!```no_run
//!     use scx_utils::Cpumask;
//!     let all_zeroes = Cpumask::new();
//!     let from_str_mask = Cpumask::from_str("0xf0");
//!```
//!
//! The hexadecimal string also supports the special values "none" and "all",
//! respectively to specify no CPU (empty mask) or all CPUs (full mask):
//!
//!```
//!     use scx_utils::Cpumask;
//!     let str = String::from("none");
//!     let all_zeroes = Cpumask::from_str(&str);
//!
//!     let str = String::from("all");
//!     let all_ones = Cpumask::from_str(&str);
//!```
//!
//! A Cpumask can be queried and updated using its helper functions:
//!
//!```rust
//!     use log::info;
//!     use scx_utils::Cpumask;
//!     let str = String::from("none");
//!     let mut mask = Cpumask::from_str(&str).unwrap();
//!     info!("{:#?}", mask); // 32:<11111111000000001111111100000000>
//!     assert!(!mask.test_cpu(0));
//!     mask.set_cpu(0);
//!     assert!(mask.test_cpu(0));
//!
//!     mask.clear_all();
//!     info!("{:#?}", mask); // 32:<00000000000000000000000000000000>
//!     assert!(!mask.test_cpu(0));
//!
//!     mask.set_all();
//!     info!("{:#?}", mask); // 32:<11111111111111111111111111111111>
//!     assert!(mask.test_cpu(0));
//!```

use crate::NR_CPU_IDS;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitvec::prelude::*;
use sscanf::sscanf;
use std::fmt;
use std::ops::BitAndAssign;
use std::ops::BitOrAssign;
use std::ops::BitXorAssign;

#[derive(Debug, Eq, Clone, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cpumask {
    mask: BitVec<u64, Lsb0>,
}

impl Cpumask {
    fn check_cpu(&self, cpu: usize) -> Result<()> {
        if cpu >= *NR_CPU_IDS {
            bail!("Invalid CPU {} passed, max {}", cpu, *NR_CPU_IDS);
        }

        Ok(())
    }

    /// Build a new empty Cpumask object.
    pub fn new() -> Cpumask {
        Cpumask {
            mask: bitvec![u64, Lsb0; 0; *NR_CPU_IDS],
        }
    }

    /// Build a Cpumask object from a hexadecimal string.
    pub fn from_str(cpumask: &str) -> Result<Cpumask> {
        match cpumask {
            "none" => {
                let mask = bitvec![u64, Lsb0; 0; *NR_CPU_IDS];
                return Ok(Self { mask });
            }
            "all" => {
                let mask = bitvec![u64, Lsb0; 1; *NR_CPU_IDS];
                return Ok(Self { mask });
            }
            _ => {}
        }
        let hex_str = {
            let mut tmp_str = cpumask
                .strip_prefix("0x")
                .unwrap_or(cpumask)
                .replace('_', "");
            if tmp_str.len() % 2 != 0 {
                tmp_str = "0".to_string() + &tmp_str;
            }
            tmp_str
        };
        let byte_vec =
            hex::decode(&hex_str).with_context(|| format!("Failed to parse cpumask: {cpumask}"))?;

        let mut mask = bitvec![u64, Lsb0; 0; *NR_CPU_IDS];
        for (index, &val) in byte_vec.iter().rev().enumerate() {
            let mut v = val;
            while v != 0 {
                let lsb = v.trailing_zeros() as usize;
                v &= !(1 << lsb);
                let cpu = index * 8 + lsb;
                if cpu >= *NR_CPU_IDS {
                    bail!(
                        concat!(
                            "Found cpu ({}) in cpumask ({}) which is larger",
                            " than the number of cpus on the machine ({})"
                        ),
                        cpu,
                        cpumask,
                        *NR_CPU_IDS
                    );
                }
                mask.set(cpu, true);
            }
        }

        Ok(Self { mask })
    }

    pub fn from_cpulist(cpulist: &str) -> Result<Cpumask> {
        let mut mask = Cpumask::new();
        for cpu_id in read_cpulist(cpulist)? {
            let _ = mask.set_cpu(cpu_id);
        }

        Ok(mask)
    }

    pub fn from_vec(vec: Vec<u64>) -> Self {
        Self {
            mask: BitVec::from_vec(vec),
        }
    }

    pub fn from_bitvec(bitvec: BitVec<u64, Lsb0>) -> Self {
        Self { mask: bitvec }
    }

    /// Return a slice of u64's whose bits reflect the Cpumask.
    pub fn as_raw_slice(&self) -> &[u64] {
        self.mask.as_raw_slice()
    }

    /// Return the mutable raw BitVec object backing the Cpumask.
    pub fn as_raw_bitvec_mut(&mut self) -> &mut BitVec<u64, Lsb0> {
        &mut self.mask
    }

    /// Return the raw BitVec object backing the Cpumask.
    pub fn as_raw_bitvec(&self) -> &BitVec<u64, Lsb0> {
        &self.mask
    }

    /// Set all bits in the Cpumask to 1
    pub fn set_all(&mut self) {
        self.mask.fill(true);
    }

    /// Set all bits in the Cpumask to 0
    pub fn clear_all(&mut self) {
        self.mask.fill(false);
    }

    /// Set a bit in the Cpumask. Returns an error if the specified CPU exceeds
    /// the size of the Cpumask.
    pub fn set_cpu(&mut self, cpu: usize) -> Result<()> {
        self.check_cpu(cpu)?;
        self.mask.set(cpu, true);
        Ok(())
    }

    /// Clear a bit from the Cpumask. Returns an error if the specified CPU
    /// exceeds the size of the Cpumask.
    pub fn clear_cpu(&mut self, cpu: usize) -> Result<()> {
        self.check_cpu(cpu)?;
        self.mask.set(cpu, false);
        Ok(())
    }

    /// Test whether the specified CPU bit is set in the Cpumask. If the CPU
    /// exceeds the number of possible CPUs on the host, false is returned.
    pub fn test_cpu(&self, cpu: usize) -> bool {
        match self.mask.get(cpu) {
            Some(bit) => *bit,
            None => false,
        }
    }

    /// Count the number of bits set in the Cpumask.
    pub fn weight(&self) -> usize {
        self.mask.count_ones()
    }

    /// Return true if the Cpumask has no bit set, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.mask.count_ones() == 0
    }

    /// Return true if the Cpumask has all bits set, false otherwise.
    pub fn is_full(&self) -> bool {
        self.mask.count_ones() == *NR_CPU_IDS
    }

    /// The total size of the cpumask.
    pub fn len(&self) -> usize {
        *NR_CPU_IDS
    }

    /// Create a Cpumask that is the negation of the current Cpumask.
    pub fn not(&self) -> Cpumask {
        let mut new = self.clone();
        new.mask = !new.mask;
        new
    }

    /// Create a Cpumask that is the AND of the current Cpumask and another.
    pub fn and(&self, other: &Cpumask) -> Cpumask {
        let mut new = self.clone();
        new.mask &= other.mask.clone();
        new
    }

    /// Create a Cpumask that is the OR of the current Cpumask and another.
    pub fn or(&self, other: &Cpumask) -> Cpumask {
        let mut new = self.clone();
        new.mask |= other.mask.clone();
        new
    }

    /// Create a Cpumask that is the XOR of the current Cpumask and another.
    pub fn xor(&self, other: &Cpumask) -> Cpumask {
        let mut new = self.clone();
        new.mask ^= other.mask.clone();
        new
    }

    /// Iterate over each element of a Cpumask, and return the indices with bits
    /// set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use log::info;
    /// use scx_utils::Cpumask;
    /// let str = String::from("all");
    /// let mask = Cpumask::from_str(&str).unwrap();
    /// for cpu in mask.iter() {
    ///     info!("cpu {} was set", cpu);
    /// }
    /// ```
    pub fn iter(&self) -> CpumaskIterator<'_> {
        CpumaskIterator {
            mask: self,
            index: 0,
        }
    }

    /// Write out a CPU mask to a raw memory pointer. We normally use this as part of updating
    /// the CPU masks on the BPF side.
    ///
    /// # Safety
    ///
    /// The caller must enforce that the bpfptr is valid and points to a valid region of
    /// writable BPF memory that represents a CPU mask. This function is not thread safe.
    pub unsafe fn write_to_ptr(&self, bpfptr: *mut u64, len: usize) -> Result<()> {
        let cpumask_slice = self.as_raw_slice();
        if len != cpumask_slice.len() {
            bail!(
                "BPF CPU mask has length {} u64s, Cpumask size is {}",
                len,
                cpumask_slice.len()
            );
        }

        let ptr = bpfptr as *mut [u64; 64];
        let bpfmask: &mut [u64; 64] = unsafe { &mut *ptr };
        let (left, _) = bpfmask.split_at_mut(cpumask_slice.len());
        left.clone_from_slice(cpumask_slice);

        Ok(())
    }

    fn fmt_with(&self, f: &mut fmt::Formatter<'_>, case: char) -> fmt::Result {
        let mut masks: Vec<u32> = self
            .as_raw_slice()
            .iter()
            .flat_map(|x| [*x as u32, (x >> 32) as u32])
            .collect();

        // Throw out possible stray from u64 -> u32.
        masks.truncate((*NR_CPU_IDS).div_ceil(32));

        // Print the highest 32bit. Trim digits beyond *NR_CPU_IDS.
        let width = match (*NR_CPU_IDS).div_ceil(4) % 8 {
            0 => 8,
            v => v,
        };
        match case {
            'x' => write!(f, "{:0width$x}", masks.pop().unwrap(), width = width)?,
            'X' => write!(f, "{:0width$X}", masks.pop().unwrap(), width = width)?,
            _ => unreachable!(),
        }

        // The rest in descending order.
        for submask in masks.iter().rev() {
            match case {
                'x' => write!(f, ",{submask:08x}")?,
                'X' => write!(f, ",{submask:08X}")?,
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}

pub fn read_cpulist(cpulist: &str) -> Result<Vec<usize>> {
    let cpulist = cpulist.trim_end_matches('\0');
    let cpu_groups: Vec<&str> = cpulist.split(',').collect();
    let mut cpu_ids = vec![];
    for group in cpu_groups.iter() {
        let (min, max) = match sscanf!(group.trim(), "{usize}-{usize}") {
            Ok((x, y)) => (x, y),
            Err(_) => match sscanf!(group.trim(), "{usize}") {
                Ok(x) => (x, x),
                Err(_) => {
                    bail!("Failed to parse cpulist {}", group.trim());
                }
            },
        };
        for i in min..(max + 1) {
            cpu_ids.push(i);
        }
    }

    Ok(cpu_ids)
}

pub struct CpumaskIterator<'a> {
    mask: &'a Cpumask,
    index: usize,
}

impl Iterator for CpumaskIterator<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < *NR_CPU_IDS {
            let index = self.index;
            self.index += 1;
            let bit_val = self.mask.test_cpu(index);
            if bit_val {
                return Some(index);
            }
        }

        None
    }
}

impl fmt::Display for Cpumask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with(f, 'x')
    }
}

impl fmt::LowerHex for Cpumask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with(f, 'x')
    }
}

impl fmt::UpperHex for Cpumask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with(f, 'X')
    }
}

impl BitAndAssign<&Self> for Cpumask {
    fn bitand_assign(&mut self, rhs: &Self) {
        self.mask &= &rhs.mask;
    }
}

impl BitOrAssign<&Self> for Cpumask {
    fn bitor_assign(&mut self, rhs: &Self) {
        self.mask |= &rhs.mask;
    }
}

impl BitXorAssign<&Self> for Cpumask {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.mask ^= &rhs.mask;
    }
}
