// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::event_filter::EventFilter;
use crate::Action;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

/// A single subscription
#[derive(Clone)]
pub struct Subscription {
    pub id: String,
    pub filter: EventFilter,
    pub sender: UnboundedSender<Value>,
    pub max_rate: Option<u64>, // Max events per second
    pub created_at: u64,
    pub event_count: u64,
}

/// Manages event subscriptions
pub struct SubscriptionManager {
    subscriptions: HashMap<String, Subscription>,
    rate_limiters: HashMap<String, RateLimiter>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
            rate_limiters: HashMap::new(),
        }
    }

    /// Add a new subscription
    pub fn subscribe(
        &mut self,
        id: String,
        filter: EventFilter,
        max_rate: Option<u64>,
    ) -> Result<tokio::sync::mpsc::UnboundedReceiver<Value>, String> {
        // Validate filter
        filter.validate()?;

        // Check if subscription already exists
        if self.subscriptions.contains_key(&id) {
            return Err(format!("Subscription with id '{}' already exists", id));
        }

        let (tx, rx) = unbounded_channel();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let subscription = Subscription {
            id: id.clone(),
            filter,
            sender: tx,
            max_rate,
            created_at,
            event_count: 0,
        };

        self.subscriptions.insert(id.clone(), subscription);

        if let Some(rate) = max_rate {
            self.rate_limiters
                .insert(id.clone(), RateLimiter::new(rate));
        }

        Ok(rx)
    }

    /// Remove a subscription
    pub fn unsubscribe(&mut self, id: &str) -> Result<(), String> {
        if self.subscriptions.remove(id).is_some() {
            self.rate_limiters.remove(id);
            Ok(())
        } else {
            Err(format!("Subscription '{}' not found", id))
        }
    }

    /// Publish an event to all matching subscriptions
    pub fn publish(&mut self, action: &Action, json: &Value) {
        let mut to_remove = Vec::new();

        for (id, sub) in self.subscriptions.iter_mut() {
            // Check filter
            if !sub.filter.matches(action, json) {
                continue;
            }

            // Check rate limit
            if let Some(limiter) = self.rate_limiters.get_mut(id) {
                if !limiter.allow() {
                    continue;
                }
            }

            // Try to send
            if sub.sender.send(json.clone()).is_err() {
                // Receiver dropped, mark for removal
                to_remove.push(id.clone());
            } else {
                sub.event_count += 1;
            }
        }

        // Remove dead subscriptions
        for id in to_remove {
            self.subscriptions.remove(&id);
            self.rate_limiters.remove(&id);
        }
    }

    /// Get subscription statistics
    pub fn get_stats(&self) -> Vec<SubscriptionStats> {
        self.subscriptions
            .values()
            .map(|sub| SubscriptionStats {
                id: sub.id.clone(),
                filter: sub.filter.clone(),
                max_rate: sub.max_rate,
                created_at: sub.created_at,
                event_count: sub.event_count,
                current_rate: self
                    .rate_limiters
                    .get(&sub.id)
                    .map(|l| l.current_rate())
                    .unwrap_or(0.0),
            })
            .collect()
    }

    /// List all subscription IDs
    pub fn list_subscriptions(&self) -> Vec<String> {
        self.subscriptions.keys().cloned().collect()
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SubscriptionStats {
    pub id: String,
    pub filter: EventFilter,
    pub max_rate: Option<u64>,
    pub created_at: u64,
    pub event_count: u64,
    pub current_rate: f64,
}

/// Simple rate limiter using token bucket algorithm
struct RateLimiter {
    max_rate: u64, // tokens per second
    tokens: f64,   // current tokens
    last_update: std::time::Instant,
    event_count: u64,
    window_start: std::time::Instant,
}

impl RateLimiter {
    fn new(max_rate: u64) -> Self {
        let now = std::time::Instant::now();
        Self {
            max_rate,
            tokens: max_rate as f64,
            last_update: now,
            event_count: 0,
            window_start: now,
        }
    }

    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.max_rate as f64).min(self.max_rate as f64);
        self.last_update = now;

        // Check if we have a token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.event_count += 1;
            true
        } else {
            false
        }
    }

    fn current_rate(&self) -> f64 {
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.event_count as f64 / elapsed
        } else {
            0.0
        }
    }
}

pub type SharedSubscriptionManager = Arc<Mutex<SubscriptionManager>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscribe_unsubscribe() {
        let mut manager = SubscriptionManager::new();

        let filter = EventFilter::default();
        let _rx = manager
            .subscribe("test1".to_string(), filter, None)
            .unwrap();

        assert_eq!(manager.list_subscriptions().len(), 1);

        manager.unsubscribe("test1").unwrap();
        assert_eq!(manager.list_subscriptions().len(), 0);
    }

    #[test]
    fn test_duplicate_subscription() {
        let mut manager = SubscriptionManager::new();

        let filter = EventFilter::default();
        let _rx = manager
            .subscribe("test1".to_string(), filter.clone(), None)
            .unwrap();
        let result = manager.subscribe("test1".to_string(), filter, None);

        assert!(result.is_err());
    }
}
