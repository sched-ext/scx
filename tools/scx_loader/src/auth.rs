// SPDX-License-Identifier: GPL-2.0

use anyhow::{Context, Result};
use nix::unistd::{getuid, Group, Uid, User};
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{AuthorizationMode, SecurityConfig};

/// Authorization checker for D-Bus method calls
pub struct AuthChecker {
    config: Arc<SecurityConfig>,
}

impl AuthChecker {
    pub fn new(config: Arc<SecurityConfig>) -> Self {
        Self { config }
    }

    /// Check if the caller is authorized to perform privileged operations
    ///
    /// # Arguments
    /// * `caller_uid` - The UID of the D-Bus caller (None means use current process UID)
    /// * `bus_name` - The D-Bus bus name of the caller (for Polkit)
    /// * `action_id` - The Polkit action ID (e.g., "org.scx.Loader.StartScheduler")
    /// * `connection` - The D-Bus connection (for Polkit queries)
    pub async fn check_authorization(
        &self,
        caller_uid: Option<u32>,
        bus_name: Option<&str>,
        action_id: &str,
        connection: Option<&zbus::Connection>,
    ) -> Result<bool> {
        match self.config.authorization_mode {
            AuthorizationMode::Permissive => {
                log::debug!("Permissive mode: allowing all requests");
                Ok(true)
            }
            AuthorizationMode::Group => self.check_group_authorization(caller_uid),
            AuthorizationMode::Polkit => {
                self.check_polkit_authorization(bus_name, action_id, connection)
                    .await
            }
        }
    }

    /// Check authorization using Polkit
    async fn check_polkit_authorization(
        &self,
        bus_name: Option<&str>,
        action_id: &str,
        connection: Option<&zbus::Connection>,
    ) -> Result<bool> {
        let bus_name = bus_name.context("Polkit requires D-Bus bus name")?;
        let connection = connection.context("Polkit requires D-Bus connection")?;

        log::debug!("Checking Polkit authorization for action: {}", action_id);

        // Create Polkit subject (system-bus-name)
        let mut subject = HashMap::new();
        subject.insert("name", zvariant::Value::new(bus_name));
        let subject_struct = ("system-bus-name", subject);

        // Create details map (empty for basic check)
        let details: HashMap<String, String> = HashMap::new();

        // Flags: 0 = None, 1 = AllowUserInteraction
        let flags: u32 = 0;

        // Empty cancellation ID
        let cancellation_id = "";

        // Call CheckAuthorization on PolicyKit
        let polkit_proxy = PolkitAuthorityProxy::new(connection)
            .await
            .context("Failed to create Polkit proxy")?;

        let result = polkit_proxy
            .check_authorization(subject_struct, action_id, details, flags, cancellation_id)
            .await
            .context("Polkit CheckAuthorization call failed")?;

        // result is (is_authorized, is_challenge, details)
        let (is_authorized, is_challenge, _details) = result;

        if is_authorized {
            log::debug!("Polkit authorized action: {}", action_id);
            Ok(true)
        } else if is_challenge {
            log::warn!(
                "Polkit requires authentication challenge for action: {}",
                action_id
            );
            Ok(false)
        } else {
            log::warn!("Polkit denied action: {}", action_id);
            Ok(false)
        }
    }

    /// Check if user is member of required group
    fn check_group_authorization(&self, caller_uid: Option<u32>) -> Result<bool> {
        let required_group = self
            .config
            .required_group
            .as_ref()
            .context("Group authorization requires 'required_group' in config")?;

        // Get the UID to check (caller_uid if provided, otherwise current process)
        let uid = caller_uid.map(Uid::from_raw).unwrap_or_else(getuid);

        log::debug!("Checking group authorization for UID {}", uid);

        // Get user information
        let user = User::from_uid(uid)
            .context(format!("Failed to lookup user for UID {}", uid))?
            .context(format!("No user found for UID {}", uid))?;

        log::debug!(
            "Checking if user '{}' is in group '{}'",
            user.name,
            required_group
        );

        // Get required group information
        let group = Group::from_name(required_group)
            .context(format!("Failed to lookup group '{}'", required_group))?
            .context(format!("Group '{}' not found", required_group))?;

        // Check if user's primary group matches
        if user.gid == group.gid {
            log::debug!(
                "User '{}' primary group matches required group '{}'",
                user.name,
                required_group
            );
            return Ok(true);
        }

        // Check if user is in group's member list
        if group.mem.iter().any(|member| member == &user.name) {
            log::debug!(
                "User '{}' is member of group '{}'",
                user.name,
                required_group
            );
            return Ok(true);
        }

        log::warn!(
            "User '{}' (UID {}) is not a member of required group '{}'",
            user.name,
            uid,
            required_group
        );
        Ok(false)
    }

    pub fn print_security_warnings(&self) {
        match self.config.authorization_mode {
            AuthorizationMode::Permissive => {
                log::warn!("╔═══════════════════════════════════════════════════════════════╗");
                log::warn!("║ WARNING: Running in PERMISSIVE mode                           ║");
                log::warn!("║ Any local user can control kernel schedulers                  ║");
                log::warn!("║ This is INSECURE and should only be used for development     ║");
                log::warn!("║                                                               ║");
                log::warn!("║ To enable security, add to /etc/scx_loader.toml:             ║");
                log::warn!("║   [security]                                                  ║");
                log::warn!("║   authorization_mode = \"group\"  # or \"polkit\"                ║");
                log::warn!("║   required_group = \"wheel\"                                   ║");
                log::warn!("╚═══════════════════════════════════════════════════════════════╝");
            }
            AuthorizationMode::Group => {
                if let Some(group) = &self.config.required_group {
                    log::info!("Authorization: Requires membership in group '{}'", group);
                }
            }
            AuthorizationMode::Polkit => {
                log::info!("Authorization: Using Polkit for fine-grained access control");
            }
        }

        if self.config.allow_auto_mode {
            log::warn!("Auto-mode enabled: Scheduler may launch automatically on high CPU usage");
        }

        if !self.config.validate_arguments {
            log::warn!("WARNING: Argument validation disabled - this is INSECURE");
        }
    }
}

/// Check if current process is running as root
pub fn is_root() -> bool {
    getuid() == Uid::from_raw(0)
}

/// Polkit Authority D-Bus proxy
#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait PolkitAuthority {
    /// CheckAuthorization method
    #[allow(clippy::type_complexity)]
    fn check_authorization(
        &self,
        subject: (&str, HashMap<&str, zvariant::Value<'_>>),
        action_id: &str,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_security_config(mode: AuthorizationMode, group: Option<String>) -> SecurityConfig {
        SecurityConfig {
            authorization_mode: mode,
            required_group: group,
            validate_arguments: true,
            strict_allowlist: false,
            max_arguments: 128,
            max_argument_length: 4096,
            allow_auto_mode: false,
            max_concurrent_starts: 3,
            retry_delay_ms: 500,
        }
    }

    #[tokio::test]
    async fn test_permissive_mode_allows_all() {
        let config = Arc::new(test_security_config(AuthorizationMode::Permissive, None));
        let checker = AuthChecker::new(config);

        // Permissive mode should allow any UID
        let result = checker
            .check_authorization(Some(1000), None, "test.action", None)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Including root
        let result = checker
            .check_authorization(Some(0), None, "test.action", None)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // And None (current process)
        let result = checker
            .check_authorization(None, None, "test.action", None)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_polkit_mode_requires_dbus_info() {
        let config = Arc::new(test_security_config(AuthorizationMode::Polkit, None));
        let checker = AuthChecker::new(config);

        // Polkit mode without D-Bus connection and bus name should error
        let result = checker
            .check_authorization(Some(1000), None, "test.action", None)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Should mention either bus name or connection requirement
        assert!(
            err.contains("bus name")
                || err.contains("connection")
                || err.contains("Polkit requires"),
            "Expected Polkit requirement error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_group_mode_requires_group_config() {
        let config = Arc::new(test_security_config(AuthorizationMode::Group, None));
        let checker = AuthChecker::new(config);

        // Group mode without required_group should error
        let result = checker
            .check_authorization(Some(1000), None, "test.action", None)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required_group"));
    }

    #[tokio::test]
    async fn test_group_mode_current_user() {
        // Get current user's primary group
        let uid = getuid();
        let user = User::from_uid(uid).unwrap().unwrap();
        let group = Group::from_gid(user.gid).unwrap().unwrap();

        let config = Arc::new(test_security_config(
            AuthorizationMode::Group,
            Some(group.name.clone()),
        ));
        let checker = AuthChecker::new(config);

        // Current user with their own primary group should be authorized
        let result = checker
            .check_authorization(None, None, "test.action", None)
            .await;
        assert!(result.is_ok(), "Failed with: {:?}", result);
        assert!(
            result.unwrap(),
            "Current user should be authorized for their primary group"
        );
    }

    #[tokio::test]
    async fn test_group_mode_root_in_any_group() {
        // Root (UID 0) should be able to access any group
        // Note: This test assumes root exists and is properly configured
        let config = Arc::new(test_security_config(
            AuthorizationMode::Group,
            Some("root".to_string()),
        ));
        let checker = AuthChecker::new(config);

        // Root should be authorized
        let result = checker
            .check_authorization(Some(0), None, "test.action", None)
            .await;
        if result.is_ok() {
            // Root should be in root group
            assert!(result.unwrap(), "Root should be authorized for root group");
        }
        // Otherwise the root user/group doesn't exist on this system (unusual but possible)
    }

    #[tokio::test]
    async fn test_group_mode_invalid_group() {
        let config = Arc::new(test_security_config(
            AuthorizationMode::Group,
            Some("nonexistent_group_xyz123".to_string()),
        ));
        let checker = AuthChecker::new(config);

        // Use current user's UID to ensure user exists, then check for group not found
        let uid = getuid();
        let result = checker
            .check_authorization(Some(uid.as_raw()), None, "test.action", None)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Error message should mention the group or indicate lookup failure
        assert!(
            err.contains("not found")
                || err.contains("nonexistent_group")
                || err.contains("lookup"),
            "Expected error about group not found, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_group_mode_invalid_uid() {
        let config = Arc::new(test_security_config(
            AuthorizationMode::Group,
            Some("root".to_string()),
        ));
        let checker = AuthChecker::new(config);

        // Use an extremely high UID that shouldn't exist
        let result = checker
            .check_authorization(Some(u32::MAX), None, "test.action", None)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No user found"));
    }

    #[test]
    fn test_is_root() {
        // Test is_root function
        let current_uid = getuid();
        if current_uid == Uid::from_raw(0) {
            assert!(is_root(), "Running as root, is_root() should return true");
        } else {
            assert!(
                !is_root(),
                "Not running as root, is_root() should return false"
            );
        }
    }

    #[test]
    fn test_security_warnings() {
        // Test that print_security_warnings doesn't panic
        let config = Arc::new(test_security_config(AuthorizationMode::Permissive, None));
        let checker = AuthChecker::new(config);
        checker.print_security_warnings();

        let config = Arc::new(test_security_config(
            AuthorizationMode::Group,
            Some("wheel".to_string()),
        ));
        let checker = AuthChecker::new(config);
        checker.print_security_warnings();

        let config = Arc::new(test_security_config(AuthorizationMode::Polkit, None));
        let checker = AuthChecker::new(config);
        checker.print_security_warnings();
    }
}
