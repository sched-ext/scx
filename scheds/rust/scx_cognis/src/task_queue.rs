// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only

use std::mem::MaybeUninit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePush {
    Primary,
    Deferred,
}

/// Fixed-capacity FIFO ring buffer with one allocation at construction time.
///
/// This is used for the scheduler's per-label task queues so pushes and pops
/// remain O(1) with no heap traffic after init.
pub struct TaskRing<T> {
    buf: Box<[MaybeUninit<T>]>,
    head: usize,
    tail: usize,
    len: usize,
}

impl<T> TaskRing<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "TaskRing capacity must be > 0");

        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, MaybeUninit::uninit);

        Self {
            buf: buf.into_boxed_slice(),
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    #[inline(always)]
    pub fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.len == self.buf.len() {
            return Err(value);
        }

        unsafe {
            self.buf[self.tail].as_mut_ptr().write(value);
        }
        self.tail = (self.tail + 1) % self.buf.len();
        self.len += 1;
        Ok(())
    }

    #[inline(always)]
    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        let idx = self.head;
        self.head = (self.head + 1) % self.buf.len();
        self.len -= 1;
        Some(unsafe { self.buf[idx].assume_init_read() })
    }

    #[inline(always)]
    pub fn front(&self) -> Option<&T> {
        if self.len == 0 {
            return None;
        }

        Some(unsafe { self.buf[self.head].assume_init_ref() })
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.len == self.buf.len()
    }
}

/// Fixed-capacity FIFO with one inline deferred slot.
///
/// The deferred slot is used to absorb a single saturation event without
/// losing a task. After the next successful pop from the primary ring, the
/// deferred task is immediately moved into the ring tail, clearing the slot
/// without any allocation.
pub struct TaskQueue<T> {
    primary: TaskRing<T>,
    deferred: Option<T>,
}

impl<T> TaskQueue<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            primary: TaskRing::with_capacity(capacity),
            deferred: None,
        }
    }

    #[inline(always)]
    pub fn push_back(&mut self, value: T) -> Result<QueuePush, T> {
        if !self.primary.is_full() {
            return self.primary.push_back(value).map(|_| QueuePush::Primary);
        }

        if self.deferred.is_none() {
            self.deferred = Some(value);
            return Ok(QueuePush::Deferred);
        }

        Err(value)
    }

    #[inline(always)]
    pub fn pop_front(&mut self) -> Option<T> {
        if let Some(task) = self.primary.pop_front() {
            self.refill_from_deferred();
            return Some(task);
        }

        self.deferred.take()
    }

    #[inline(always)]
    pub fn front(&self) -> Option<&T> {
        self.primary.front().or(self.deferred.as_ref())
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.primary.is_empty() && self.deferred.is_none()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.primary.len() + usize::from(self.deferred.is_some())
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.primary.capacity() + 1
    }

    #[inline(always)]
    pub fn has_deferred(&self) -> bool {
        self.deferred.is_some()
    }

    #[inline(always)]
    fn refill_from_deferred(&mut self) {
        if self.deferred.is_none() || self.primary.is_full() {
            return;
        }

        if let Some(deferred) = self.deferred.take() {
            if let Err(task) = self.primary.push_back(deferred) {
                self.deferred = Some(task);
            }
        }
    }
}

impl<T> Drop for TaskRing<T> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::{QueuePush, TaskQueue, TaskRing};

    #[test]
    fn push_pop_fifo() {
        let mut q = TaskRing::with_capacity(4);
        q.push_back(1).unwrap();
        q.push_back(2).unwrap();
        q.push_back(3).unwrap();

        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), Some(3));
        assert_eq!(q.pop_front(), None);
    }

    #[test]
    fn wraparound_preserves_order() {
        let mut q = TaskRing::with_capacity(3);
        q.push_back(10).unwrap();
        q.push_back(20).unwrap();
        assert_eq!(q.pop_front(), Some(10));
        q.push_back(30).unwrap();
        q.push_back(40).unwrap();

        assert_eq!(q.pop_front(), Some(20));
        assert_eq!(q.pop_front(), Some(30));
        assert_eq!(q.pop_front(), Some(40));
        assert_eq!(q.pop_front(), None);
    }

    #[test]
    fn deferred_slot_preserves_fifo_order() {
        let mut q = TaskQueue::with_capacity(2);

        assert_eq!(q.push_back(1), Ok(QueuePush::Primary));
        assert_eq!(q.push_back(2), Ok(QueuePush::Primary));
        assert_eq!(q.push_back(3), Ok(QueuePush::Deferred));

        assert_eq!(q.pop_front(), Some(1));
        assert!(!q.has_deferred());
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), Some(3));
        assert_eq!(q.pop_front(), None);
    }

    #[test]
    fn second_deferred_push_is_rejected() {
        let mut q = TaskQueue::with_capacity(1);

        assert_eq!(q.push_back(7), Ok(QueuePush::Primary));
        assert_eq!(q.push_back(8), Ok(QueuePush::Deferred));
        assert_eq!(q.push_back(9), Err(9));
    }
}
