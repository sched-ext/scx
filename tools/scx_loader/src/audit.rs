// SPDX-License-Identifier: GPL-2.0

use crate::SupportedSched;

/// Audit event types for security logging
#[derive(Debug, Clone, PartialEq)]
pub enum AuditEvent {
    /// Scheduler started
    SchedulerStarted {
        scheduler: SupportedSched,
        args: Vec<String>,
        success: bool,
    },
    /// Scheduler stopped
    SchedulerStopped { scheduler: SupportedSched },
    /// Scheduler switched
    SchedulerSwitched {
        from: Option<SupportedSched>,
        to: SupportedSched,
        args: Vec<String>,
        success: bool,
    },
    /// Scheduler restarted
    SchedulerRestarted {
        scheduler: SupportedSched,
        args: Vec<String>,
        success: bool,
    },
    /// Authorization check
    AuthorizationCheck {
        method: String,
        authorized: bool,
        reason: Option<String>,
    },
    /// Argument validation
    ArgumentValidation {
        scheduler: SupportedSched,
        args: Vec<String>,
        valid: bool,
        reason: Option<String>,
    },
    /// Configuration loaded
    ConfigurationLoaded {
        path: String,
        success: bool,
        reason: Option<String>,
    },
    /// Security warning
    SecurityWarning { message: String },
}

impl AuditEvent {
    /// Get the event type as a string
    pub fn event_type(&self) -> &'static str {
        match self {
            AuditEvent::SchedulerStarted { .. } => "scheduler_started",
            AuditEvent::SchedulerStopped { .. } => "scheduler_stopped",
            AuditEvent::SchedulerSwitched { .. } => "scheduler_switched",
            AuditEvent::SchedulerRestarted { .. } => "scheduler_restarted",
            AuditEvent::AuthorizationCheck { .. } => "authorization_check",
            AuditEvent::ArgumentValidation { .. } => "argument_validation",
            AuditEvent::ConfigurationLoaded { .. } => "configuration_loaded",
            AuditEvent::SecurityWarning { .. } => "security_warning",
        }
    }

    /// Get the severity level
    pub fn severity(&self) -> &'static str {
        match self {
            AuditEvent::SchedulerStarted { success, .. } => {
                if *success {
                    "info"
                } else {
                    "warning"
                }
            }
            AuditEvent::SchedulerStopped { .. } => "info",
            AuditEvent::SchedulerSwitched { success, .. } => {
                if *success {
                    "info"
                } else {
                    "warning"
                }
            }
            AuditEvent::SchedulerRestarted { success, .. } => {
                if *success {
                    "info"
                } else {
                    "warning"
                }
            }
            AuditEvent::AuthorizationCheck { authorized, .. } => {
                if *authorized {
                    "info"
                } else {
                    "warning"
                }
            }
            AuditEvent::ArgumentValidation { valid, .. } => {
                if *valid {
                    "info"
                } else {
                    "error"
                }
            }
            AuditEvent::ConfigurationLoaded { success, .. } => {
                if *success {
                    "info"
                } else {
                    "error"
                }
            }
            AuditEvent::SecurityWarning { .. } => "warning",
        }
    }

    /// Format the event as a structured log message
    pub fn format_message(&self) -> String {
        match self {
            AuditEvent::SchedulerStarted {
                scheduler,
                args,
                success,
            } => {
                let sched_name: &str = scheduler.clone().into();
                if *success {
                    format!(
                        "Scheduler '{}' started with args: [{}]",
                        sched_name,
                        args.join(", ")
                    )
                } else {
                    format!(
                        "Failed to start scheduler '{}' with args: [{}]",
                        sched_name,
                        args.join(", ")
                    )
                }
            }
            AuditEvent::SchedulerStopped { scheduler } => {
                let sched_name: &str = scheduler.clone().into();
                format!("Scheduler '{}' stopped", sched_name)
            }
            AuditEvent::SchedulerSwitched {
                from,
                to,
                args,
                success,
            } => {
                let from_name = from.as_ref().map(|s| {
                    let name: &str = s.clone().into();
                    name.to_string()
                });
                let to_name: &str = to.clone().into();
                if *success {
                    format!(
                        "Switched scheduler from '{}' to '{}' with args: [{}]",
                        from_name.unwrap_or_else(|| "none".to_string()),
                        to_name,
                        args.join(", ")
                    )
                } else {
                    format!(
                        "Failed to switch scheduler from '{}' to '{}' with args: [{}]",
                        from_name.unwrap_or_else(|| "none".to_string()),
                        to_name,
                        args.join(", ")
                    )
                }
            }
            AuditEvent::SchedulerRestarted {
                scheduler,
                args,
                success,
            } => {
                let sched_name: &str = scheduler.clone().into();
                if *success {
                    format!(
                        "Scheduler '{}' restarted with args: [{}]",
                        sched_name,
                        args.join(", ")
                    )
                } else {
                    format!(
                        "Failed to restart scheduler '{}' with args: [{}]",
                        sched_name,
                        args.join(", ")
                    )
                }
            }
            AuditEvent::AuthorizationCheck {
                method,
                authorized,
                reason,
            } => {
                if *authorized {
                    format!("Authorization succeeded for method '{}'", method)
                } else {
                    format!(
                        "Authorization failed for method '{}': {}",
                        method,
                        reason.as_deref().unwrap_or("unknown reason")
                    )
                }
            }
            AuditEvent::ArgumentValidation {
                scheduler,
                args,
                valid,
                reason,
            } => {
                let sched_name: &str = scheduler.clone().into();
                if *valid {
                    format!(
                        "Argument validation succeeded for scheduler '{}' with args: [{}]",
                        sched_name,
                        args.join(", ")
                    )
                } else {
                    format!(
                        "Argument validation failed for scheduler '{}' with args: [{}]: {}",
                        sched_name,
                        args.join(", "),
                        reason.as_deref().unwrap_or("unknown reason")
                    )
                }
            }
            AuditEvent::ConfigurationLoaded {
                path,
                success,
                reason,
            } => {
                if *success {
                    format!("Configuration loaded successfully from '{}'", path)
                } else {
                    format!(
                        "Failed to load configuration from '{}': {}",
                        path,
                        reason.as_deref().unwrap_or("unknown reason")
                    )
                }
            }
            AuditEvent::SecurityWarning { message } => {
                format!("Security warning: {}", message)
            }
        }
    }
}

/// Audit logger for security events
pub struct AuditLogger {
    enabled: bool,
}

impl AuditLogger {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Log an audit event
    pub fn log(&self, event: AuditEvent) {
        if !self.enabled {
            return;
        }

        let event_type = event.event_type();
        let severity = event.severity();
        let message = event.format_message();

        // Log with structured format for easy parsing
        let log_msg = format!("[AUDIT] [{}] [{}] {}", severity, event_type, message);

        match severity {
            "info" => log::info!("{}", log_msg),
            "warning" => log::warn!("{}", log_msg),
            "error" => log::error!("{}", log_msg),
            _ => log::info!("{}", log_msg),
        }
    }

    /// Check if audit logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_started_event() {
        let event = AuditEvent::SchedulerStarted {
            scheduler: SupportedSched::Rusty,
            args: vec!["--interval".to_string(), "1000".to_string()],
            success: true,
        };

        assert_eq!(event.event_type(), "scheduler_started");
        assert_eq!(event.severity(), "info");
        assert!(event.format_message().contains("scx_rusty"));
        assert!(event.format_message().contains("--interval"));
    }

    #[test]
    fn test_scheduler_started_failure() {
        let event = AuditEvent::SchedulerStarted {
            scheduler: SupportedSched::Lavd,
            args: vec!["--invalid".to_string()],
            success: false,
        };

        assert_eq!(event.severity(), "warning");
        assert!(event.format_message().contains("Failed"));
    }

    #[test]
    fn test_authorization_check_success() {
        let event = AuditEvent::AuthorizationCheck {
            method: "start_scheduler".to_string(),
            authorized: true,
            reason: None,
        };

        assert_eq!(event.event_type(), "authorization_check");
        assert_eq!(event.severity(), "info");
        assert!(event.format_message().contains("succeeded"));
    }

    #[test]
    fn test_authorization_check_failure() {
        let event = AuditEvent::AuthorizationCheck {
            method: "stop_scheduler".to_string(),
            authorized: false,
            reason: Some("User not in required group".to_string()),
        };

        assert_eq!(event.severity(), "warning");
        assert!(event.format_message().contains("failed"));
        assert!(event.format_message().contains("not in required group"));
    }

    #[test]
    fn test_argument_validation_failure() {
        let event = AuditEvent::ArgumentValidation {
            scheduler: SupportedSched::Rusty,
            args: vec!["; rm -rf /".to_string()],
            valid: false,
            reason: Some("Shell metacharacters detected".to_string()),
        };

        assert_eq!(event.event_type(), "argument_validation");
        assert_eq!(event.severity(), "error");
        assert!(event.format_message().contains("failed"));
        assert!(event.format_message().contains("metacharacters"));
    }

    #[test]
    fn test_scheduler_switched() {
        let event = AuditEvent::SchedulerSwitched {
            from: Some(SupportedSched::Rusty),
            to: SupportedSched::Lavd,
            args: vec!["--performance".to_string()],
            success: true,
        };

        assert_eq!(event.event_type(), "scheduler_switched");
        assert_eq!(event.severity(), "info");
        let msg = event.format_message();
        assert!(msg.contains("scx_rusty"));
        assert!(msg.contains("scx_lavd"));
    }

    #[test]
    fn test_security_warning() {
        let event = AuditEvent::SecurityWarning {
            message: "Running in permissive mode".to_string(),
        };

        assert_eq!(event.event_type(), "security_warning");
        assert_eq!(event.severity(), "warning");
        assert!(event.format_message().contains("permissive"));
    }

    #[test]
    fn test_audit_logger_disabled() {
        let logger = AuditLogger::new(false);
        assert!(!logger.is_enabled());

        // Should not panic when logging while disabled
        logger.log(AuditEvent::SecurityWarning {
            message: "Test".to_string(),
        });
    }

    #[test]
    fn test_audit_logger_enabled() {
        let logger = AuditLogger::new(true);
        assert!(logger.is_enabled());
    }
}
