use anyhow::bail;
use csv::Reader;
use procfs::CpuInfo;
use procfs::FromBufRead;
use regex::Regex;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use std::env;
use std::env::consts::ARCH;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::Result;

use std::collections::HashMap;

fn hex_to_u64<'de, D>(de: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    let s = s.to_lowercase();
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

// Intel offcore (OCR) events return two event codes, because
// codes represent event slots and not the events themselves.
fn hexlist<'de, D>(de: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut result = vec![];
    let s: &str = Deserialize::deserialize(de)?;
    for token in s.split(',') {
        let radix = if token.to_lowercase().starts_with("0x") {
            16
        } else {
            10
        };
        let event = u64::from_str_radix(token.to_lowercase().trim_start_matches("0x"), radix)
            .map_err(serde::de::Error::custom)?;

        result.push(event);
    }

    Ok(result)
}

fn num_to_bool<'de, D>(de: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    let num = u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
    Ok(num != 0)
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PMUSpec {
    // There's a typo in the AMD Zen4/5 JSON for
    // one of the PMUs.
    #[serde(alias = "BriefDescription", alias = "BriefDescript6ion")]
    desc: Option<String>,

    #[serde(alias = "PublicDescription")]
    desc_public: Option<String>,

    #[serde(alias = "EventCode")]
    #[serde(deserialize_with = "hexlist")]
    pub event: Vec<u64>,

    #[serde(alias = "EventName")]
    pub name: String,

    #[serde(alias = "UMask")]
    #[serde(deserialize_with = "hex_to_u64")]
    pub umask: u64,

    #[serde(alias = "Unit")]
    pmu: Option<String>,

    #[serde(alias = "ConfigCode")]
    #[serde(deserialize_with = "hex_to_u64")]
    config: u64,

    // Derived fields
    #[serde(alias = "MetricExpr")]
    metric_expr: Option<String>,

    #[serde(alias = "MetricName")]
    metric_name: Option<String>,

    #[serde(alias = "MetricGroup")]
    metric_group: Option<String>,

    #[serde(alias = "MetricConstraint")]
    metric_constraint: Option<String>,

    #[serde(alias = "PerPkg")]
    #[serde(deserialize_with = "num_to_bool")]
    per_pkg: bool,

    #[serde(alias = "Invert")]
    #[serde(deserialize_with = "num_to_bool")]
    invert: bool,

    #[serde(alias = "MSRIndex")]
    #[serde(deserialize_with = "hexlist", default)]
    msr_index: Vec<u64>,

    #[serde(alias = "MSRValue")]
    #[serde(deserialize_with = "hex_to_u64")]
    msr_value: u64,

    #[serde(alias = "Counter")]
    counter: Option<String>,

    #[serde(alias = "CounterNumFixed")]
    counters_num_fixed: Option<u64>,

    #[serde(alias = "CounterNumGeneric")]
    counters_num_generic: Option<u64>,
}

pub struct PMUManager {
    pub dataroot: PathBuf,
    pub arch: String,
    pub tuple: String,
    pub codename: String,
    pub pmus: HashMap<String, PMUSpec>,
}

impl PMUManager {
    /// Identify the architecture of the local machine and
    /// retrieve the paths to the relevant JSON files.
    fn identify_architecture() -> Result<String> {
        let file = File::open("/proc/cpuinfo")?;
        let bufreader = BufReader::new(file);

        let cpuinfo = CpuInfo::from_buf_read(bufreader)?;
        Ok(format!(
            "{}-{}-{:X}",
            cpuinfo.fields["vendor_id"],
            cpuinfo.fields["cpu family"],
            cpuinfo.fields["model"].parse::<i32>().unwrap()
        ))
    }

    /// List all available counters for the current machine.
    pub fn list_counters(&self) -> Result<()> {
        for pmu in self.pmus.iter() {
            println!("{}", serde_json::to_string_pretty(&pmu)?);
        }

        Ok(())
    }

    pub fn list_metadata(&self) -> () {
        println!("Dataroot {}", self.dataroot.display());
        println!("Arch: {}", self.arch);
        println!("Tuple: {}", self.tuple);
        println!("Codename: {}", self.codename);
    }

    fn read_file_counters(jsonfile: PathBuf) -> Result<Vec<PMUSpec>> {
        let content = fs::read_to_string(jsonfile)?;

        Ok(serde_json::from_str(&content)?)
    }

    fn read_all_counters(jsondir: PathBuf) -> Result<HashMap<String, PMUSpec>> {
        let mut pmuspecs = HashMap::new();
        for entry in fs::read_dir(jsondir)? {
            let filename = entry?.path().as_path().canonicalize()?;
            // metricgroups.json isn't actually PMU definitions.
            if filename
                .to_str()
                .expect("no filename")
                .ends_with("metricgroups.json")
            {
                continue;
            }

            let counters = Self::read_file_counters(filename)?;

            for counter in counters.iter() {
                pmuspecs.insert(String::from(&counter.name), counter.clone());
            }
        }
        Ok(pmuspecs)
    }

    fn arch_code() -> String {
        String::from(match ARCH {
            "x86" => "x86",
            "x86_64" => "x86",
            "aarch64" => "arm64",
            "powerpc" => "powerpc",
            "powerpc64" => "powerpc",
            "riscv32" => "riscv",
            "riscv64" => "riscv",
            "s390x" => "s390",
            "loongarch32" => "x86",
            "loongarch64" => "x86",
            _ => panic!("unsupported architecture"),
        })
    }

    fn spec_dir(basedir: PathBuf, arch: &str, tuple: &str) -> Result<(String, String)> {
        let path = basedir.clone().join("arch").join(arch).join("mapfile.csv");

        let csv = File::open(path)?;
        for record in Reader::from_reader(csv).records() {
            let record = record?;

            let regex = record.get(0).expect("no regex found in csv");
            let codename = record.get(2).expect("no codename found in csv");
            let re = Regex::new(regex)?;

            if re.is_match(tuple) {
                let path = basedir.clone().join("arch").join(arch).join(&codename);
                return Ok((path.to_string_lossy().into_owned(), String::from(codename)));
            }
        }

        println!("{}", line!());
        bail!("No matching config for tuple")
    }

    pub fn new(dataroot: Option<&str>) -> Result<Self> {
        let dataroot = match dataroot {
            Some(path) => fs::canonicalize(path)?,
            None => env::current_dir()?.to_path_buf(),
        };

        let tuple = Self::identify_architecture()?;
        let arch = Self::arch_code();
        let (path, codename) = Self::spec_dir(dataroot.clone(), &arch, tuple.as_str())?;

        let jsondir = dataroot.join(&tuple).join(&arch).join(&path);

        let pmus = Self::read_all_counters(jsondir)?;

        Ok(Self {
            dataroot,
            arch,
            tuple,
            codename,
            pmus,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test() {
        let dataroot = env!("CARGO_MANIFEST_DIR");
        let manager = PMUManager::new(Some(dataroot)).expect("could not create PMU manager");

        manager.list_metadata();
        manager.list_counters().expect("could not list counters");
    }
}
