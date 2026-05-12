// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use regex::Regex;
use scx_utils::Cpumask;
use serde::de;
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

use crate::cell_manager::CpuRecipient;

#[derive(Clone, Debug)]
pub struct ConfiguredSubcell {
    pub id: u32,
    pub matches: Vec<Vec<SubcellMatch>>,
}

#[derive(Clone, Debug)]
pub struct ConfiguredCell {
    pub id: u32,
    pub subcells: Vec<ConfiguredSubcell>,
}

#[derive(Clone, Debug)]
pub struct ConfiguredCellResolution {
    pub cell_assignments: Vec<(u64, u32)>,
    pub cell_recipients: Vec<CpuRecipient>,
    pub cells: Vec<ConfiguredCell>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum SubcellMatch {
    CommPrefix(String),
}

#[derive(Clone, Debug, Deserialize)]
enum CellMatch {
    CgroupContains(String),
    CgroupRegex(String),
}

#[derive(Clone, Debug, Deserialize)]
struct CellSpec {
    name: String,
    #[serde(default, deserialize_with = "deserialize_optional_cell_match")]
    matches: Option<CellMatch>,
    #[serde(default)]
    subcells: Vec<SubcellSpec>,
}

#[derive(Clone, Debug, Deserialize)]
struct SubcellSpec {
    #[serde(rename = "name")]
    _name: String,
    #[serde(default = "default_subcell_matches")]
    matches: Vec<Vec<SubcellMatch>>,
}

#[derive(Clone, Debug)]
struct CompiledCellSpec {
    matcher: Option<CompiledCellMatch>,
    subcells: Vec<ConfiguredSubcell>,
}

#[derive(Clone, Debug)]
enum CompiledCellMatch {
    CgroupContains(String),
    CgroupRegex(Regex),
}

#[derive(Clone, Debug)]
struct CgroupEntry {
    path: PathBuf,
    path_string: String,
    cgid: u64,
    cpuset: Option<Cpumask>,
}

#[derive(Clone, Debug)]
struct MatchedCgroup {
    spec_idx: usize,
    cgid: u64,
    cpuset: Option<Cpumask>,
}

#[derive(Clone, Debug)]
pub struct ConfiguredCells {
    specs: Vec<CompiledCellSpec>,
    root_spec_idx: Option<usize>,
    cgroup_root: PathBuf,
    all_cpus: Cpumask,
    max_cells: u32,
    path_cell_ids: HashMap<PathBuf, u32>,
    free_cell_ids: Vec<u32>,
    next_cell_id: u32,
}

impl ConfiguredCells {
    pub fn load(path: &Path, max_cells: u32, all_cpus: Cpumask) -> Result<Self> {
        Self::load_with_root(path, PathBuf::from("/sys/fs/cgroup"), max_cells, all_cpus)
    }

    fn load_with_root(
        path: &Path,
        cgroup_root: PathBuf,
        max_cells: u32,
        all_cpus: Cpumask,
    ) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("reading cell config {}", path.display()))?;
        let specs: Vec<CellSpec> = serde_json::from_str(&contents)
            .with_context(|| format!("parsing cell config {}", path.display()))?;
        let specs = compile_specs(specs)?;
        let root_spec_idx = specs.iter().rposition(|spec| spec.matcher.is_none());
        if specs
            .iter()
            .enumerate()
            .any(|(idx, spec)| spec.matcher.is_none() && Some(idx) != root_spec_idx)
        {
            bail!("only the final catch-all cell spec may use an empty match");
        }

        Ok(Self {
            specs,
            root_spec_idx,
            cgroup_root,
            all_cpus,
            max_cells,
            path_cell_ids: HashMap::new(),
            free_cell_ids: Vec::new(),
            next_cell_id: 1,
        })
    }

    pub fn resolve(
        &mut self,
        cell_demands: Option<&HashMap<u32, f64>>,
    ) -> Result<ConfiguredCellResolution> {
        let cgroups = collect_cgroups(&self.cgroup_root)?;
        let matched = self.match_cgroups(&cgroups);
        self.reconcile_cell_ids(&matched)?;

        let mut cell_assignments = Vec::new();
        let mut cell_recipients = Vec::new();
        let mut cells = Vec::new();

        cells.push(ConfiguredCell {
            id: 0,
            subcells: self.root_subcells(),
        });
        cell_recipients.push(CpuRecipient {
            id: 0,
            weight: demand_weight(cell_demands, 0),
            allowed: None,
        });

        let mut matched_paths: Vec<_> = matched.keys().cloned().collect();
        matched_paths.sort();

        for path in matched_paths {
            let matched_cgroup = matched
                .get(&path)
                .expect("BUG: matched path disappeared during config resolution");
            let cell_id = *self
                .path_cell_ids
                .get(&path)
                .expect("BUG: matched path is missing a cell id");
            let spec = self
                .specs
                .get(matched_cgroup.spec_idx)
                .expect("BUG: matched cgroup references missing spec");

            cell_assignments.push((matched_cgroup.cgid, cell_id));
            cell_recipients.push(CpuRecipient {
                id: cell_id,
                weight: demand_weight(cell_demands, cell_id),
                allowed: matched_cgroup.cpuset.clone(),
            });
            cells.push(ConfiguredCell {
                id: cell_id,
                subcells: spec.subcells.clone(),
            });
        }

        Ok(ConfiguredCellResolution {
            cell_assignments,
            cell_recipients,
            cells,
        })
    }

    pub fn format_cell_config(&self, assignments: &[crate::cell_manager::CpuAssignment]) -> String {
        let names: HashMap<u32, String> = self
            .path_cell_ids
            .iter()
            .map(|(path, id)| {
                let name = path
                    .strip_prefix(&self.cgroup_root)
                    .ok()
                    .and_then(|rel| rel.to_str())
                    .filter(|rel| !rel.is_empty())
                    .map(|rel| format!("/{}", rel.trim_start_matches('/')))
                    .unwrap_or_else(|| path.display().to_string());
                (*id, name)
            })
            .collect();

        assignments
            .iter()
            .map(|assignment| {
                let name = names
                    .get(&assignment.id)
                    .cloned()
                    .unwrap_or_else(|| "root".to_string());
                format!(
                    "cell{}({})={}",
                    assignment.id,
                    name,
                    assignment.primary.to_cpulist()
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn match_cgroups(&self, cgroups: &[CgroupEntry]) -> HashMap<PathBuf, MatchedCgroup> {
        let mut raw_matches = HashMap::new();

        for cgroup in cgroups {
            if cgroup.path == self.cgroup_root {
                continue;
            }

            for (spec_idx, spec) in self.specs.iter().enumerate() {
                if Some(spec_idx) == self.root_spec_idx {
                    continue;
                }
                if !spec.matches(&cgroup.path_string) {
                    continue;
                }

                raw_matches.insert(
                    cgroup.path.clone(),
                    MatchedCgroup {
                        spec_idx,
                        cgid: cgroup.cgid,
                        cpuset: cgroup.cpuset.clone(),
                    },
                );
                break;
            }
        }

        let mut paths: Vec<_> = raw_matches.keys().cloned().collect();
        paths.sort_by_key(|path| path.components().count());

        let mut matched: HashMap<PathBuf, MatchedCgroup> = HashMap::new();
        for path in paths {
            let raw_match = raw_matches
                .get(&path)
                .expect("BUG: raw matched path disappeared");
            let covered_by_ancestor = path.ancestors().skip(1).any(|ancestor| {
                matched
                    .get(ancestor)
                    .is_some_and(|ancestor_match| ancestor_match.spec_idx <= raw_match.spec_idx)
            });
            if covered_by_ancestor {
                continue;
            }

            matched.insert(path.clone(), raw_match.clone());
        }

        matched
    }

    fn reconcile_cell_ids(&mut self, matched: &HashMap<PathBuf, MatchedCgroup>) -> Result<()> {
        let matched_paths: HashSet<_> = matched.keys().cloned().collect();
        let removed: Vec<_> = self
            .path_cell_ids
            .keys()
            .filter(|path| !matched_paths.contains(*path))
            .cloned()
            .collect();

        for path in removed {
            if let Some(cell_id) = self.path_cell_ids.remove(&path) {
                debug!("Removed configured cell {} for {}", cell_id, path.display());
                self.free_cell_ids.push(cell_id);
            }
        }

        let mut paths: Vec<_> = matched.keys().cloned().collect();
        paths.sort();
        for path in paths {
            if self.path_cell_ids.contains_key(&path) {
                continue;
            }
            let cell_id = self.allocate_cell_id()?;
            debug!("Created configured cell {} for {}", cell_id, path.display());
            self.path_cell_ids.insert(path, cell_id);
        }

        Ok(())
    }

    fn allocate_cell_id(&mut self) -> Result<u32> {
        if let Some(id) = self.free_cell_ids.pop() {
            return Ok(id);
        }
        if self.next_cell_id >= self.max_cells {
            bail!("Cell ID space exhausted (max_cells={})", self.max_cells);
        }
        let id = self.next_cell_id;
        self.next_cell_id += 1;
        Ok(id)
    }

    fn root_subcells(&self) -> Vec<ConfiguredSubcell> {
        self.root_spec_idx
            .and_then(|idx| self.specs.get(idx))
            .map(|spec| spec.subcells.clone())
            .unwrap_or_else(default_configured_subcells)
    }

    pub fn all_cpus(&self) -> &Cpumask {
        &self.all_cpus
    }
}

impl CompiledCellSpec {
    fn matches(&self, cgroup_path: &str) -> bool {
        match &self.matcher {
            Some(CompiledCellMatch::CgroupContains(substr)) => cgroup_path.contains(substr),
            Some(CompiledCellMatch::CgroupRegex(regex)) => regex.is_match(cgroup_path),
            None => true,
        }
    }
}

fn compile_specs(specs: Vec<CellSpec>) -> Result<Vec<CompiledCellSpec>> {
    if specs.is_empty() {
        bail!("cell config must contain at least one cell spec");
    }

    specs
        .into_iter()
        .map(|spec| {
            let matcher = match spec.matches {
                Some(CellMatch::CgroupContains(substr)) => {
                    Some(CompiledCellMatch::CgroupContains(substr))
                }
                Some(CellMatch::CgroupRegex(expr)) => Some(CompiledCellMatch::CgroupRegex(
                    Regex::new(&expr).with_context(|| {
                        format!("invalid CgroupRegex '{}' for cell '{}'", expr, spec.name)
                    })?,
                )),
                None => None,
            };

            Ok(CompiledCellSpec {
                matcher,
                subcells: normalize_subcells(spec.subcells)?,
            })
        })
        .collect()
}

fn normalize_subcells(subcells: Vec<SubcellSpec>) -> Result<Vec<ConfiguredSubcell>> {
    if subcells.is_empty() {
        return Ok(default_configured_subcells());
    }

    let mut normalized = Vec::new();
    let mut next_id = 1;
    let mut catch_all = None;

    for subcell in subcells {
        if is_catch_all_subcell(&subcell) {
            if catch_all.is_some() {
                bail!("cell config contains multiple catch-all subcells");
            }
            catch_all = Some(ConfiguredSubcell {
                id: 0,
                matches: subcell.matches,
            });
            continue;
        }

        normalized.push(ConfiguredSubcell {
            id: next_id,
            matches: subcell.matches,
        });
        next_id += 1;
    }

    let mut result = vec![catch_all.unwrap_or_else(default_catch_all_subcell)];
    result.extend(normalized);

    if result.len() > crate::MAX_SUBCELLS_PER_CELL {
        bail!(
            "cell config has too many subcells: {} > {}",
            result.len(),
            crate::MAX_SUBCELLS_PER_CELL
        );
    }

    Ok(result)
}

fn is_catch_all_subcell(subcell: &SubcellSpec) -> bool {
    subcell.matches.iter().any(|ands| ands.is_empty())
}

fn default_configured_subcells() -> Vec<ConfiguredSubcell> {
    vec![default_catch_all_subcell()]
}

fn default_catch_all_subcell() -> ConfiguredSubcell {
    ConfiguredSubcell {
        id: 0,
        matches: vec![Vec::new()],
    }
}

fn default_subcell_matches() -> Vec<Vec<SubcellMatch>> {
    vec![Vec::new()]
}

fn demand_weight(cell_demands: Option<&HashMap<u32, f64>>, cell_id: u32) -> f64 {
    cell_demands
        .and_then(|demands| demands.get(&cell_id).copied())
        .unwrap_or(1.0)
        .max(0.0)
}

fn collect_cgroups(root: &Path) -> Result<Vec<CgroupEntry>> {
    let mut cgroups = Vec::new();
    collect_cgroups_inner(root, &mut cgroups)?;
    cgroups.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(cgroups)
}

fn collect_cgroups_inner(path: &Path, cgroups: &mut Vec<CgroupEntry>) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| format!("reading metadata for {}", path.display()))
        }
    };

    if !metadata.is_dir() {
        return Ok(());
    }

    cgroups.push(CgroupEntry {
        path: path.to_path_buf(),
        path_string: path.display().to_string(),
        cgid: metadata.ino(),
        cpuset: read_cpuset(path)?,
    });

    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry =
            entry.with_context(|| format!("reading directory entry in {}", path.display()))?;
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("reading file type for {}", entry.path().display()))
            }
        };
        if file_type.is_dir() {
            collect_cgroups_inner(&entry.path(), cgroups)?;
        }
    }

    Ok(())
}

fn read_cpuset(cgroup_path: &Path) -> Result<Option<Cpumask>> {
    let cpuset_path = cgroup_path.join("cpuset.cpus");
    match fs::read_to_string(&cpuset_path) {
        Ok(content) => {
            let content = content.trim();
            if content.is_empty() {
                Ok(None)
            } else {
                Cpumask::from_cpulist(content)
                    .with_context(|| {
                        format!(
                            "failed to parse cpuset '{}' from {}",
                            content,
                            cpuset_path.display()
                        )
                    })
                    .map(Some)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", cpuset_path.display())),
    }
}

fn deserialize_optional_cell_match<'de, D>(deserializer: D) -> Result<Option<CellMatch>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    if value.as_object().is_some_and(|obj| obj.is_empty()) {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    fn write_config(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn parses_example_config_and_makes_rest_subcell_zero() {
        let config = write_config(
            r#"
            [
              {
                "name": "allotment",
                "matches": { "CgroupRegex": "workload-tw-[^/]+\\.allotment\\.slice" },
                "subcells": [
                  { "name": "hhvmworker", "matches": [[{ "CommPrefix": "hhvmworker" }]] },
                  { "name": "mcrpxy-web", "matches": [[{ "CommPrefix": "mcrpxy-web" }]] },
                  { "name": "rest", "matches": [[]] }
                ]
              },
              { "name": "workload.slice", "matches": { "CgroupContains": "workload.slice" } },
              { "name": "rest", "matches": {} }
            ]
            "#,
        );
        let configured = ConfiguredCells::load_with_root(
            config.path(),
            PathBuf::from("/tmp"),
            256,
            Cpumask::new(),
        )
        .unwrap();

        assert_eq!(configured.root_spec_idx, Some(2));
        let subcells = &configured.specs[0].subcells;
        assert_eq!(subcells[0].id, 0);
        assert_eq!(subcells[1].id, 1);
        assert_eq!(subcells[2].id, 2);
    }

    #[test]
    fn descendant_inherits_same_matching_cell_spec() {
        let config = write_config(
            r#"
            [
              { "name": "parent", "matches": { "CgroupContains": "parent.slice" } },
              { "name": "rest", "matches": {} }
            ]
            "#,
        );
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("parent.slice")).unwrap();
        fs::create_dir(root.path().join("parent.slice/child.scope")).unwrap();

        let mut configured = ConfiguredCells::load_with_root(
            config.path(),
            root.path().to_path_buf(),
            256,
            Cpumask::new(),
        )
        .unwrap();
        let resolution = configured.resolve(None).unwrap();

        assert_eq!(resolution.cell_assignments.len(), 1);
    }

    #[test]
    fn higher_priority_descendant_gets_own_cell() {
        let config = write_config(
            r#"
            [
              { "name": "child", "matches": { "CgroupContains": "child.scope" } },
              { "name": "parent", "matches": { "CgroupContains": "parent.slice" } },
              { "name": "rest", "matches": {} }
            ]
            "#,
        );
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("parent.slice")).unwrap();
        fs::create_dir(root.path().join("parent.slice/child.scope")).unwrap();

        let mut configured = ConfiguredCells::load_with_root(
            config.path(),
            root.path().to_path_buf(),
            256,
            Cpumask::new(),
        )
        .unwrap();
        let resolution = configured.resolve(None).unwrap();

        assert_eq!(resolution.cell_assignments.len(), 2);
    }
}
