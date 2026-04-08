// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::collections::BTreeMap;

use crate::bpf_skel::*;
use anyhow::Result;
use scx_utils::Cpumask;
use scx_utils::Topology;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct Domain {
    id: usize,
    mask: Cpumask,
    pub ctx: Arc<Mutex<Option<*mut types::dom_ctx>>>,
}

impl Domain {
    /// Get the Domain's ID.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get a copy of the domain's cpumask.
    pub fn mask(&self) -> Cpumask {
        self.mask.clone()
    }

    /// Get a raw slice of the domain's cpumask as a set of one or more u64
    /// variables whose bits represent CPUs in the mask.
    pub fn mask_slice(&self) -> &[u64] {
        self.mask.as_raw_slice()
    }

    /// The number of CPUs in the domain.
    pub fn weight(&self) -> usize {
        self.mask.weight()
    }

    pub fn ctx(&self) -> Option<&mut types::dom_ctx> {
        let domc = self.ctx.lock().unwrap();

        // Ideally we would be storing the dom_ctx as a reference in struct Domain,
        // in the first place. Rust makes embedding references to structs into other
        // structs very difficult, so this is more pragmatic.
        match *domc {
            Some(ptr) => Some(unsafe { &mut *(ptr) }),
            None => None,
        }
    }
}

#[derive(Debug)]
pub struct DomainGroup {
    doms: BTreeMap<usize, Domain>,
    dom_numa_map: BTreeMap<usize, usize>,
    num_numa_nodes: usize,
    span: Cpumask,
}

impl DomainGroup {
    pub fn new(top: &Topology) -> Result<Self> {
        let mut span = Cpumask::new();
        let mut dom_numa_map = BTreeMap::new();
        // Track the domain ID separate from the LLC ID, because LLC IDs can
        // have gaps if there are offlined CPUs, and domain IDs need to be
        // contiguous (at least for now, until we can update libraries to not
        // return vectors of domain values).
        let mut dom_id = 0;
        let mut doms: BTreeMap<usize, Domain> = BTreeMap::new();
        for (node_id, node) in &top.nodes {
            for (_, llc) in node.llcs.iter() {
                let mask = llc.span.clone();
                span |= &mask;
                doms.insert(
                    dom_id,
                    Domain {
                        id: dom_id,
                        mask,
                        ctx: Arc::new(Mutex::new(None)),
                    },
                );
                dom_numa_map.insert(dom_id, *node_id);
                dom_id += 1;
            }
        }

        Ok(Self {
            doms,
            dom_numa_map,
            num_numa_nodes: top.nodes.len(),
            span,
        })
    }

    pub fn numa_doms(&self, numa_id: &usize) -> Vec<Domain> {
        let mut numa_doms = Vec::new();
        // XXX dom_numa_map never gets updated even if we cross NUMA nodes
        for (d_id, n_id) in self.dom_numa_map.iter() {
            if n_id == numa_id {
                let dom = self.doms.get(d_id).unwrap();
                numa_doms.push(dom.clone());
            }
        }

        numa_doms
    }

    pub fn doms(&self) -> &BTreeMap<usize, Domain> {
        &self.doms
    }

    pub fn nr_doms(&self) -> usize {
        self.doms.len()
    }

    pub fn nr_nodes(&self) -> usize {
        self.num_numa_nodes
    }

    pub fn dom_numa_id(&self, dom_id: &usize) -> Option<usize> {
        self.dom_numa_map.get(dom_id).copied()
    }

    pub fn weight(&self) -> usize {
        self.span.weight()
    }
}
