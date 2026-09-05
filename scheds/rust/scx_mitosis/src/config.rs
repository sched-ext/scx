// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use regex::Regex;
use scx_utils::Cpumask;
use serde::Deserialize;
use serde::de;
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct ConfiguredSubcell {
    pub id: u32,
    pub name: String,
    pub matches: Vec<Vec<SubcellMatch>>,
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
    name: String,
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
pub struct ConfiguredCells {
    specs: Vec<CompiledCellSpec>,
    root_spec_idx: Option<usize>,
    cgroup_root: PathBuf,
    all_cpus: Cpumask,
    max_cells: u32,
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
        })
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
                name: subcell.name,
                matches: subcell.matches,
            });
            continue;
        }

        normalized.push(ConfiguredSubcell {
            id: next_id,
            name: subcell.name,
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
        name: "rest".to_string(),
        matches: vec![Vec::new()],
    }
}

fn default_subcell_matches() -> Vec<Vec<SubcellMatch>> {
    vec![Vec::new()]
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
        assert_eq!(subcells[0].name, "rest");
        assert_eq!(subcells[1].id, 1);
        assert_eq!(subcells[1].name, "hhvmworker");
        assert_eq!(subcells[2].id, 2);
        assert_eq!(subcells[2].name, "mcrpxy-web");
    }
}
