// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::fs;
use std::io::Read;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::bpf_intf;

use libc::pid_t;

use once_cell::sync::Lazy;
use procfs::process::Process;
use procfs::process::StatFlags;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FrameSchedConfig {
    pub specs: Vec<FrameSchedSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameSchedSpec {
    pub name: String,
    pub comment: Option<String>,
    pub matches: Vec<Vec<FrameSchedMatch>>,
    pub qos: FrameSchedQoS,
}

// Default spec if none is specified by the user.
static DEFAULT_SPECS: Lazy<Vec<FrameSchedSpec>> = Lazy::new(|| {
    let max_qos = FrameSchedSpec {
        name: String::from("max_qos"),
        comment: None,
        matches: vec![vec![FrameSchedMatch::NiceEquals(-19)]],
        qos: FrameSchedQoS::Max,
    };
    let high_qos = FrameSchedSpec {
        name: String::from("high_qos"),
        comment: None,
        matches: vec![vec![FrameSchedMatch::NiceBelow(0)]],
        qos: FrameSchedQoS::High,
    };
    let normal_qos = FrameSchedSpec {
        name: String::from("normal_qos"),
        comment: None,
        matches: vec![vec![FrameSchedMatch::NiceEquals(0)]],
        qos: FrameSchedQoS::Normal,
    };
    let low_qos = FrameSchedSpec {
        name: String::from("low_qos"),
        comment: None,
        matches: vec![vec![FrameSchedMatch::NiceAbove(0)]],
        qos: FrameSchedQoS::Low,
    };

    vec![max_qos, high_qos, normal_qos, low_qos]
});

impl FrameSchedSpec {
    pub fn parse(input: &str) -> Result<Vec<Self>> {
        let file = fs::OpenOptions::new()
            .read(true)
            .open(input);
        let config: FrameSchedConfig = match file  {
            Ok(mut opened) => {
                let mut content = String::new();
                opened.read_to_string(&mut content)?;
                serde_json::from_str(&content)
            },
            Err(_) => serde_json::from_str(input)
        }?;

        Ok(config.specs)
    }

    pub fn default() -> &'static[Self] {
        &DEFAULT_SPECS
    }

    pub fn matches(&self, matcher: &ThreadMatcher) -> bool {
        for match_ors in &self.matches {
            let mut matches_passed = true;
            for match_and in match_ors {
                matches_passed &= match_and.matches(matcher);
            }
            if matches_passed {
                return true;
            }
        }

        false
    }
}

#[derive(Debug)]
pub struct ThreadMatcher {
    cgroup: Option<String>,
    comm: String,
    niceness: i64,
    tgid: i32,
    is_group_leader: bool,
    is_kthread: bool,
}

impl ThreadMatcher {
    pub fn create(tid: pid_t) -> Result<ThreadMatcher> {
        let thread = Process::new(tid)?;
        let cgroup = match thread.cgroups() {
            Ok(proc_cgroups) => {
                let cgroups_vec = proc_cgroups.0;
                if cgroups_vec.len() > 1 || cgroups_vec[0].hierarchy != 0 {
                    None
                } else {
                    Some(cgroups_vec[0].pathname.clone())
                }
            }
            Err(_) => None,
        };
        let stat = thread.stat()?;

        let comm = stat.comm.clone();
        let niceness = stat.nice;

        let main_task = thread.task_main_thread()?;
        let tgid = main_task.pid;
        let is_group_leader = tgid == tid;

        let pf_flags = stat.flags()?;
        let is_kthread = pf_flags.contains(StatFlags::PF_KTHREAD);

        Ok(Self {
            cgroup,
            comm,
            niceness,
            tgid,
            is_group_leader,
            is_kthread,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FrameSchedMatch {
    CgroupPrefix(String),
    CgroupSuffix(String),
    CommPrefix(String),
    CommSuffix(String),
    NiceAbove(i64),
    NiceBelow(i64),
    NiceEquals(i64),
    TGIDEquals(i32),
    IsGroupLeader(bool),
    IsKthread(bool),
}

impl FrameSchedMatch {
    pub fn matches(&self, matcher: &ThreadMatcher) -> bool {
        match self {
            FrameSchedMatch::CgroupPrefix(substr) | FrameSchedMatch::CgroupSuffix(substr) => {
                match &matcher.cgroup {
                    Some(cgroup) => {
                        match self {
                            FrameSchedMatch::CgroupPrefix(_) => cgroup.starts_with(substr),
                            FrameSchedMatch::CgroupSuffix(_) => cgroup.ends_with(substr),
                            _ => unreachable!(),
                        }
                    },
                    _ => false,
                }
            },
            FrameSchedMatch::CommPrefix(prefix) => matcher.comm.starts_with(prefix),
            FrameSchedMatch::CommSuffix(suffix) => matcher.comm.ends_with(suffix),
            FrameSchedMatch::NiceAbove(niceness) => matcher.niceness > *niceness,
            FrameSchedMatch::NiceBelow(niceness) => matcher.niceness < *niceness,
            FrameSchedMatch::NiceEquals(niceness) => matcher.niceness == *niceness,
            FrameSchedMatch::TGIDEquals(tgid) => matcher.tgid == *tgid,
            FrameSchedMatch::IsGroupLeader(is_group_leader) => matcher.is_group_leader == *is_group_leader,
            FrameSchedMatch::IsKthread(is_kthread) => matcher.is_kthread == *is_kthread,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FrameSchedQoS {
	Low,
	Normal,
	High,
	Max,
}

impl FrameSchedQoS {
    pub fn as_bpf_enum(&self) -> u32 {
        match self {
            FrameSchedQoS::Low => bpf_intf::fs_dl_qos_FS_DL_QOS_LOW,
            FrameSchedQoS::Normal => bpf_intf::fs_dl_qos_FS_DL_QOS_NORMAL,
            FrameSchedQoS::High => bpf_intf::fs_dl_qos_FS_DL_QOS_HIGH,
            FrameSchedQoS::Max => bpf_intf::fs_dl_qos_FS_DL_QOS_MAX,
        }
    }
}
