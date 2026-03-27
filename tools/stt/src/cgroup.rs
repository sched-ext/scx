use crate::topology::TestTopology;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

pub struct CgroupManager {
    parent: PathBuf,
}

impl CgroupManager {
    pub fn new(parent: &str) -> Self {
        Self {
            parent: PathBuf::from(parent),
        }
    }
    pub fn parent_path(&self) -> &std::path::Path {
        &self.parent
    }

    pub fn setup(&self, enable_cpu_controller: bool) -> Result<()> {
        if !self.parent.exists() {
            fs::create_dir_all(&self.parent)
                .with_context(|| format!("mkdir {}", self.parent.display()))?;
        }
        let controllers = if enable_cpu_controller {
            "+cpuset +cpu"
        } else {
            "+cpuset"
        };
        let root = PathBuf::from("/sys/fs/cgroup");
        if let Ok(rel) = self.parent.strip_prefix(&root) {
            let mut cur = root.clone();
            for c in rel.components() {
                let sc = cur.join("cgroup.subtree_control");
                if sc.exists() {
                    if let Err(e) = fs::write(&sc, controllers) {
                        tracing::warn!(path = %sc.display(), err = %e, "failed to enable controllers");
                    }
                }
                cur = cur.join(c);
            }
            let sc = self.parent.join("cgroup.subtree_control");
            if sc.exists() {
                if let Err(e) = fs::write(&sc, controllers) {
                    tracing::warn!(path = %sc.display(), err = %e, "failed to enable controllers at parent");
                }
            }
        }
        Ok(())
    }

    pub fn create_cell(&self, name: &str) -> Result<()> {
        let p = self.parent.join(name);
        if !p.exists() {
            fs::create_dir_all(&p).with_context(|| format!("mkdir {}", p.display()))?;
        }
        Ok(())
    }

    pub fn remove_cell(&self, name: &str) -> Result<()> {
        let p = self.parent.join(name);
        if !p.exists() {
            return Ok(());
        }
        self.drain_tasks(name)?;
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::remove_dir(&p).with_context(|| format!("rmdir {}", p.display()))
    }

    pub fn set_cpuset(&self, name: &str, cpus: &BTreeSet<usize>) -> Result<()> {
        let p = self.parent.join(name).join("cpuset.cpus");
        fs::write(&p, TestTopology::cpuset_string(cpus))
            .with_context(|| format!("write {}", p.display()))
    }

    pub fn clear_cpuset(&self, name: &str) -> Result<()> {
        let p = self.parent.join(name).join("cpuset.cpus");
        fs::write(&p, "").with_context(|| format!("clear {}", p.display()))
    }

    pub fn move_task(&self, name: &str, tid: u32) -> Result<()> {
        let p = self.parent.join(name).join("cgroup.procs");
        fs::write(&p, tid.to_string()).with_context(|| format!("move tid {tid}"))
    }

    pub fn drain_tasks(&self, name: &str) -> Result<()> {
        let src = self.parent.join(name).join("cgroup.procs");
        let dst = self.parent.join("cgroup.procs");
        if !src.exists() {
            return Ok(());
        }
        if let Ok(content) = fs::read_to_string(&src) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    let _ = fs::write(&dst, pid.to_string());
                }
            }
        }
        Ok(())
    }

    pub fn cleanup_all(&self) -> Result<()> {
        if !self.parent.exists() {
            return Ok(());
        }
        // Remove all child cgroups but keep the parent
        if let Ok(entries) = fs::read_dir(&self.parent) {
            for e in entries.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    cleanup_recursive(&e.path());
                }
            }
        }
        Ok(())
    }
}

fn cleanup_recursive(path: &std::path::Path) {
    // Depth-first: clean children before parent
    if let Ok(entries) = fs::read_dir(path) {
        for e in entries.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                cleanup_recursive(&e.path());
            }
        }
    }
    // Drain tasks to parent
    let procs = path.join("cgroup.procs");
    if let (Some(parent), Ok(content)) = (path.parent(), fs::read_to_string(&procs)) {
        let dst = parent.join("cgroup.procs");
        for l in content.lines() {
            if let Ok(pid) = l.trim().parse::<u32>() {
                let _ = fs::write(&dst, pid.to_string());
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
    let _ = fs::remove_dir(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_manager_path() {
        let cg = CgroupManager::new("/sys/fs/cgroup/test");
        assert_eq!(
            cg.parent_path(),
            std::path::Path::new("/sys/fs/cgroup/test")
        );
    }

    #[test]
    fn create_cell_in_tmpdir() {
        let dir = std::env::temp_dir().join(format!("stt-cg-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cg = CgroupManager::new(dir.to_str().unwrap());
        cg.create_cell("test_cell").unwrap();
        assert!(dir.join("test_cell").exists());
        cg.create_cell("nested/deep").unwrap();
        assert!(dir.join("nested/deep").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_cell_idempotent() {
        let dir = std::env::temp_dir().join(format!("stt-cg-idem-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cg = CgroupManager::new(dir.to_str().unwrap());
        cg.create_cell("cell_0").unwrap();
        cg.create_cell("cell_0").unwrap(); // should not error
        assert!(dir.join("cell_0").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_all_on_nonexistent() {
        let cg = CgroupManager::new("/nonexistent/stt-test-path");
        assert!(cg.cleanup_all().is_ok());
    }

    #[test]
    fn remove_cell_nonexistent() {
        let cg = CgroupManager::new("/nonexistent/stt-test-path");
        assert!(cg.remove_cell("no_such_cell").is_ok());
    }

    #[test]
    fn cleanup_removes_child_dirs() {
        let dir = std::env::temp_dir().join(format!("stt-cg-clean-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cg = CgroupManager::new(dir.to_str().unwrap());
        cg.create_cell("a").unwrap();
        cg.create_cell("b").unwrap();
        cg.create_cell("c/deep").unwrap();
        assert!(dir.join("a").exists());
        assert!(dir.join("c/deep").exists());
        // cleanup_all removes child dirs (not real cgroups, so drain_tasks is a no-op)
        cg.cleanup_all().unwrap();
        assert!(!dir.join("a").exists());
        assert!(!dir.join("b").exists());
        assert!(!dir.join("c").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_tasks_nonexistent_source() {
        let cg = CgroupManager::new("/nonexistent/stt-drain-test");
        assert!(cg.drain_tasks("missing_cell").is_ok());
    }

    #[test]
    fn setup_non_cgroup_path() {
        // setup() on a non-cgroup path should still create the dir
        let dir = std::env::temp_dir().join(format!("stt-setup-{}", std::process::id()));
        let cg = CgroupManager::new(dir.to_str().unwrap());
        cg.setup(true).unwrap();
        assert!(dir.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
