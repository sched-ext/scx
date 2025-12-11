// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Centralized event type constants and utilities for perfetto trace analysis

use serde::{Deserialize, Serialize};

/// Scheduler events
pub const SCHED_SWITCH: &str = "sched_switch";
pub const SCHED_WAKEUP: &str = "sched_wakeup";
pub const SCHED_WAKING: &str = "sched_waking";
pub const SCHED_MIGRATE_TASK: &str = "sched_migrate_task";
pub const SCHED_PROCESS_FORK: &str = "sched_process_fork";
pub const SCHED_PROCESS_EXIT: &str = "sched_process_exit";
pub const SCHED_PROCESS_EXEC: &str = "sched_process_exec";
pub const SCHED_PROCESS_WAIT: &str = "sched_process_wait";
pub const SCHED_BLOCKED_REASON: &str = "sched_blocked_reason";
pub const SCHED_PI_SETPRIO: &str = "sched_pi_setprio";

/// IRQ/Interrupt events
pub const IRQ_HANDLER_ENTRY: &str = "irq_handler_entry";
pub const IRQ_HANDLER_EXIT: &str = "irq_handler_exit";
pub const SOFTIRQ_ENTRY: &str = "softirq_entry";
pub const SOFTIRQ_EXIT: &str = "softirq_exit";
pub const SOFTIRQ_RAISE: &str = "softirq_raise";
pub const IPI_ENTRY: &str = "ipi_entry";
pub const IPI_EXIT: &str = "ipi_exit";
pub const IPI_RAISE: &str = "ipi_raise";

/// Block I/O events
pub const BLOCK_RQ_INSERT: &str = "block_rq_insert";
pub const BLOCK_RQ_ISSUE: &str = "block_rq_issue";
pub const BLOCK_RQ_COMPLETE: &str = "block_rq_complete";
pub const BLOCK_BIO_QUEUE: &str = "block_bio_queue";
pub const BLOCK_BIO_BACKMERGE: &str = "block_bio_backmerge";
pub const BLOCK_BIO_FRONTMERGE: &str = "block_bio_frontmerge";

/// Network events
pub const NET_DEV_XMIT: &str = "net_dev_xmit";
pub const NETIF_RECEIVE_SKB: &str = "netif_receive_skb";
pub const NET_DEV_QUEUE: &str = "net_dev_queue";

/// Memory management events
pub const MM_PAGE_ALLOC: &str = "mm_page_alloc";
pub const MM_PAGE_FREE: &str = "mm_page_free";
pub const KMEM_CACHE_ALLOC: &str = "kmem_cache_alloc";
pub const KMEM_CACHE_FREE: &str = "kmem_cache_free";
pub const MM_COMPACTION_BEGIN: &str = "mm_compaction_begin";
pub const MM_COMPACTION_END: &str = "mm_compaction_end";
pub const MM_VMSCAN_DIRECT_RECLAIM_BEGIN: &str = "mm_vmscan_direct_reclaim_begin";
pub const MM_VMSCAN_DIRECT_RECLAIM_END: &str = "mm_vmscan_direct_reclaim_end";
pub const OOM_SCORE_ADJ_UPDATE: &str = "oom_score_adj_update";

/// Power management events
pub const CPU_FREQUENCY: &str = "cpu_frequency";
pub const CPU_IDLE: &str = "cpu_idle";
pub const SUSPEND_RESUME: &str = "suspend_resume";

/// Filesystem events
pub const EXT4_DA_WRITE_PAGES: &str = "ext4_da_write_pages";
pub const EXT4_SYNC_FILE_ENTER: &str = "ext4_sync_file_enter";
pub const EXT4_SYNC_FILE_EXIT: &str = "ext4_sync_file_exit";
pub const EXT4_ALLOC_DA_BLOCKS: &str = "ext4_alloc_da_blocks";

/// Lock/synchronization events
pub const CONTENTION_BEGIN: &str = "contention_begin";
pub const CONTENTION_END: &str = "contention_end";

/// Workqueue events
pub const WORKQUEUE_EXECUTE_START: &str = "workqueue_execute_start";
pub const WORKQUEUE_EXECUTE_END: &str = "workqueue_execute_end";
pub const WORKQUEUE_ACTIVATE_WORK: &str = "workqueue_activate_work";
pub const WORKQUEUE_QUEUE_WORK: &str = "workqueue_queue_work";

/// Event category classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    Scheduler,
    Interrupt,
    BlockIO,
    Network,
    Memory,
    Power,
    FileSystem,
    Synchronization,
    Workqueue,
    Unknown,
}

impl EventCategory {
    /// Get category name as string
    pub fn as_str(&self) -> &'static str {
        match self {
            EventCategory::Scheduler => "Scheduler",
            EventCategory::Interrupt => "Interrupt",
            EventCategory::BlockIO => "Block I/O",
            EventCategory::Network => "Network",
            EventCategory::Memory => "Memory",
            EventCategory::Power => "Power",
            EventCategory::FileSystem => "FileSystem",
            EventCategory::Synchronization => "Synchronization",
            EventCategory::Workqueue => "Workqueue",
            EventCategory::Unknown => "Unknown",
        }
    }
}

/// Get human-readable name for event type
pub fn event_type_name(event_type: &str) -> &str {
    match event_type {
        SCHED_SWITCH => "Context Switch",
        SCHED_WAKEUP => "Task Wakeup",
        SCHED_WAKING => "Task Waking",
        SCHED_MIGRATE_TASK => "Task Migration",
        SCHED_PROCESS_FORK => "Process Fork",
        SCHED_PROCESS_EXIT => "Process Exit",
        IRQ_HANDLER_ENTRY => "IRQ Handler Entry",
        IRQ_HANDLER_EXIT => "IRQ Handler Exit",
        SOFTIRQ_ENTRY => "Softirq Entry",
        SOFTIRQ_EXIT => "Softirq Exit",
        SOFTIRQ_RAISE => "Softirq Raise",
        BLOCK_RQ_INSERT => "Block Request Insert",
        BLOCK_RQ_ISSUE => "Block Request Issue",
        BLOCK_RQ_COMPLETE => "Block Request Complete",
        NET_DEV_XMIT => "Network Transmit",
        NETIF_RECEIVE_SKB => "Network Receive",
        MM_PAGE_ALLOC => "Page Allocation",
        MM_PAGE_FREE => "Page Free",
        MM_VMSCAN_DIRECT_RECLAIM_BEGIN => "Direct Reclaim Begin",
        MM_VMSCAN_DIRECT_RECLAIM_END => "Direct Reclaim End",
        CPU_FREQUENCY => "CPU Frequency Change",
        CPU_IDLE => "CPU Idle State",
        EXT4_SYNC_FILE_ENTER => "Ext4 Sync File Enter",
        EXT4_SYNC_FILE_EXIT => "Ext4 Sync File Exit",
        CONTENTION_BEGIN => "Lock Contention Begin",
        CONTENTION_END => "Lock Contention End",
        WORKQUEUE_EXECUTE_START => "Workqueue Execute Start",
        WORKQUEUE_EXECUTE_END => "Workqueue Execute End",
        _ => event_type,
    }
}

/// Get category for event type
pub fn event_category(event_type: &str) -> EventCategory {
    match event_type {
        SCHED_SWITCH | SCHED_WAKEUP | SCHED_WAKING | SCHED_MIGRATE_TASK | SCHED_PROCESS_FORK
        | SCHED_PROCESS_EXIT | SCHED_PROCESS_EXEC | SCHED_PROCESS_WAIT | SCHED_BLOCKED_REASON
        | SCHED_PI_SETPRIO => EventCategory::Scheduler,

        IRQ_HANDLER_ENTRY | IRQ_HANDLER_EXIT | SOFTIRQ_ENTRY | SOFTIRQ_EXIT | SOFTIRQ_RAISE
        | IPI_ENTRY | IPI_EXIT | IPI_RAISE => EventCategory::Interrupt,

        BLOCK_RQ_INSERT | BLOCK_RQ_ISSUE | BLOCK_RQ_COMPLETE | BLOCK_BIO_QUEUE
        | BLOCK_BIO_BACKMERGE | BLOCK_BIO_FRONTMERGE => EventCategory::BlockIO,

        NET_DEV_XMIT | NETIF_RECEIVE_SKB | NET_DEV_QUEUE => EventCategory::Network,

        MM_PAGE_ALLOC
        | MM_PAGE_FREE
        | KMEM_CACHE_ALLOC
        | KMEM_CACHE_FREE
        | MM_COMPACTION_BEGIN
        | MM_COMPACTION_END
        | MM_VMSCAN_DIRECT_RECLAIM_BEGIN
        | MM_VMSCAN_DIRECT_RECLAIM_END
        | OOM_SCORE_ADJ_UPDATE => EventCategory::Memory,

        CPU_FREQUENCY | CPU_IDLE | SUSPEND_RESUME => EventCategory::Power,

        EXT4_DA_WRITE_PAGES | EXT4_SYNC_FILE_ENTER | EXT4_SYNC_FILE_EXIT | EXT4_ALLOC_DA_BLOCKS => {
            EventCategory::FileSystem
        }

        CONTENTION_BEGIN | CONTENTION_END => EventCategory::Synchronization,

        WORKQUEUE_EXECUTE_START
        | WORKQUEUE_EXECUTE_END
        | WORKQUEUE_ACTIVATE_WORK
        | WORKQUEUE_QUEUE_WORK => EventCategory::Workqueue,

        _ => EventCategory::Unknown,
    }
}

/// Get all event types for a category
pub fn events_in_category(category: EventCategory) -> Vec<&'static str> {
    match category {
        EventCategory::Scheduler => vec![
            SCHED_SWITCH,
            SCHED_WAKEUP,
            SCHED_WAKING,
            SCHED_MIGRATE_TASK,
            SCHED_PROCESS_FORK,
            SCHED_PROCESS_EXIT,
            SCHED_PROCESS_EXEC,
            SCHED_PROCESS_WAIT,
            SCHED_BLOCKED_REASON,
            SCHED_PI_SETPRIO,
        ],
        EventCategory::Interrupt => vec![
            IRQ_HANDLER_ENTRY,
            IRQ_HANDLER_EXIT,
            SOFTIRQ_ENTRY,
            SOFTIRQ_EXIT,
            SOFTIRQ_RAISE,
            IPI_ENTRY,
            IPI_EXIT,
            IPI_RAISE,
        ],
        EventCategory::BlockIO => vec![
            BLOCK_RQ_INSERT,
            BLOCK_RQ_ISSUE,
            BLOCK_RQ_COMPLETE,
            BLOCK_BIO_QUEUE,
            BLOCK_BIO_BACKMERGE,
            BLOCK_BIO_FRONTMERGE,
        ],
        EventCategory::Network => vec![NET_DEV_XMIT, NETIF_RECEIVE_SKB, NET_DEV_QUEUE],
        EventCategory::Memory => vec![
            MM_PAGE_ALLOC,
            MM_PAGE_FREE,
            KMEM_CACHE_ALLOC,
            KMEM_CACHE_FREE,
            MM_COMPACTION_BEGIN,
            MM_COMPACTION_END,
            MM_VMSCAN_DIRECT_RECLAIM_BEGIN,
            MM_VMSCAN_DIRECT_RECLAIM_END,
            OOM_SCORE_ADJ_UPDATE,
        ],
        EventCategory::Power => vec![CPU_FREQUENCY, CPU_IDLE, SUSPEND_RESUME],
        EventCategory::FileSystem => vec![
            EXT4_DA_WRITE_PAGES,
            EXT4_SYNC_FILE_ENTER,
            EXT4_SYNC_FILE_EXIT,
            EXT4_ALLOC_DA_BLOCKS,
        ],
        EventCategory::Synchronization => vec![CONTENTION_BEGIN, CONTENTION_END],
        EventCategory::Workqueue => vec![
            WORKQUEUE_EXECUTE_START,
            WORKQUEUE_EXECUTE_END,
            WORKQUEUE_ACTIVATE_WORK,
            WORKQUEUE_QUEUE_WORK,
        ],
        EventCategory::Unknown => vec![],
    }
}

/// Softirq type names (for softirq_entry/exit vec field)
pub fn softirq_type_name(softirq_nr: u32) -> &'static str {
    match softirq_nr {
        0 => "HI",
        1 => "TIMER",
        2 => "NET_TX",
        3 => "NET_RX",
        4 => "BLOCK",
        5 => "IRQ_POLL",
        6 => "TASKLET",
        7 => "SCHED",
        8 => "HRTIMER",
        9 => "RCU",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_category() {
        assert_eq!(event_category(SCHED_SWITCH), EventCategory::Scheduler);
        assert_eq!(event_category(IRQ_HANDLER_ENTRY), EventCategory::Interrupt);
        assert_eq!(event_category(BLOCK_RQ_ISSUE), EventCategory::BlockIO);
        assert_eq!(event_category(NET_DEV_XMIT), EventCategory::Network);
        assert_eq!(event_category(MM_PAGE_ALLOC), EventCategory::Memory);
        assert_eq!(event_category(CPU_FREQUENCY), EventCategory::Power);
        assert_eq!(
            event_category(EXT4_SYNC_FILE_ENTER),
            EventCategory::FileSystem
        );
        assert_eq!(
            event_category(CONTENTION_BEGIN),
            EventCategory::Synchronization
        );
        assert_eq!(
            event_category(WORKQUEUE_EXECUTE_START),
            EventCategory::Workqueue
        );
        assert_eq!(event_category("unknown_event"), EventCategory::Unknown);
    }

    #[test]
    fn test_event_type_name() {
        assert_eq!(event_type_name(SCHED_SWITCH), "Context Switch");
        assert_eq!(event_type_name(IRQ_HANDLER_ENTRY), "IRQ Handler Entry");
        assert_eq!(event_type_name("unknown"), "unknown");
    }

    #[test]
    fn test_events_in_category() {
        let sched_events = events_in_category(EventCategory::Scheduler);
        assert!(sched_events.contains(&SCHED_SWITCH));
        assert!(sched_events.contains(&SCHED_WAKEUP));
        assert_eq!(sched_events.len(), 10);

        let irq_events = events_in_category(EventCategory::Interrupt);
        assert!(irq_events.contains(&IRQ_HANDLER_ENTRY));
        assert!(irq_events.contains(&SOFTIRQ_ENTRY));
        assert_eq!(irq_events.len(), 8);
    }

    #[test]
    fn test_softirq_type_name() {
        assert_eq!(softirq_type_name(0), "HI");
        assert_eq!(softirq_type_name(1), "TIMER");
        assert_eq!(softirq_type_name(3), "NET_RX");
        assert_eq!(softirq_type_name(9), "RCU");
        assert_eq!(softirq_type_name(99), "UNKNOWN");
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(EventCategory::Scheduler.as_str(), "Scheduler");
        assert_eq!(EventCategory::Interrupt.as_str(), "Interrupt");
        assert_eq!(EventCategory::BlockIO.as_str(), "Block I/O");
    }
}
