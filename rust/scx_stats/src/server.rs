use crate::{Meta, ScxStatsMeta};
use anyhow::{anyhow, Context, Result};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::spawn;

pub trait StatsReader: FnMut(&BTreeMap<String, String>) -> Result<Value> {}
impl<T: FnMut(&BTreeMap<String, String>) -> Result<Value>> StatsReader for T {}

pub trait StatsReaderSend: FnMut(&BTreeMap<String, String>) -> Result<Value> + Send {}
impl<T: FnMut(&BTreeMap<String, String>) -> Result<Value> + Send> StatsReaderSend for T {}

pub trait StatsReaderSync: Fn(&BTreeMap<String, String>) -> Result<Value> + Send + Sync {}
impl<T: Fn(&BTreeMap<String, String>) -> Result<Value> + Send + Sync> StatsReaderSync for T {}

pub trait StatsOpener: FnMut() -> Result<Box<dyn StatsReader>> + Send {}
impl<T: FnMut() -> Result<Box<dyn StatsReader>> + Send> StatsOpener for T {}

pub trait StatsCloser: FnOnce() + Send {}
impl<T: FnOnce() + Send> StatsCloser for T {}

pub struct ScxStatsOps {
    open: Box<dyn StatsOpener>,
    close: Option<Box<dyn StatsCloser>>,
}

#[derive(Default)]
struct ScxStatsOpenOps {
    map: BTreeMap<String, (Arc<Mutex<ScxStatsOps>>, Box<dyn StatsReader>)>,
}

impl std::ops::Drop for ScxStatsOpenOps {
    fn drop(&mut self) {
        for (_, (ops, _)) in self.map.iter_mut() {
            if let Some(close) = ops.lock().unwrap().close.take() {
                close();
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatsRequest {
    pub req: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

impl ScxStatsRequest {
    pub fn new(req: &str, args: Vec<(String, String)>) -> Self {
        Self {
            req: req.to_string(),
            args: args.into_iter().collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatsResponse {
    pub errno: i32,
    pub args: BTreeMap<String, Value>,
}

pub struct ScxStatsErrno(pub i32);

impl std::fmt::Display for ScxStatsErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", std::io::Error::from_raw_os_error(self.0))
    }
}

impl std::fmt::Debug for ScxStatsErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", std::io::Error::from_raw_os_error(self.0))
    }
}

struct ScxStatsServerData {
    stats_meta: BTreeMap<String, ScxStatsMeta>,
    stats_ops: BTreeMap<String, Arc<Mutex<ScxStatsOps>>>,
}

struct ScxStatsServerInner {
    listener: UnixListener,
    data: Arc<Mutex<ScxStatsServerData>>,
}

impl ScxStatsServerInner {
    fn new(
        listener: UnixListener,
        stats_meta: BTreeMap<String, ScxStatsMeta>,
        stats_ops: BTreeMap<String, Arc<Mutex<ScxStatsOps>>>,
    ) -> Self {
        Self {
            listener,
            data: Arc::new(Mutex::new(ScxStatsServerData {
                stats_meta,
                stats_ops,
            })),
        }
    }

    fn build_resp<T>(errno: i32, resp: &T) -> Result<ScxStatsResponse>
    where
        T: Serialize,
    {
        Ok(ScxStatsResponse {
            errno,
            args: [("resp".into(), serde_json::to_value(resp)?)]
                .into_iter()
                .collect(),
        })
    }

    fn handle_request(
        line: String,
        data: &Arc<Mutex<ScxStatsServerData>>,
    ) -> Result<ScxStatsResponse> {
        let req: ScxStatsRequest = serde_json::from_str(&line)?;
        let mut open_ops = ScxStatsOpenOps::default();

        match req.req.as_str() {
            "stats" => {
                let target = match req.args.get("target") {
                    Some(v) => v,
                    None => "top",
                };

                let ops = match data.lock().unwrap().stats_ops.get(target) {
                    Some(v) => v.clone(),
                    None => Err(anyhow!("unknown stat target {:?}", req)
                        .context(ScxStatsErrno(libc::EINVAL)))?,
                };

                if !open_ops.map.contains_key(target) {
                    let read = (ops.lock().unwrap().open)()?;
                    open_ops.map.insert(target.into(), (ops.clone(), read));
                }

                let read = &mut open_ops.map.get_mut(target).unwrap().1;

                let resp = read(&req.args)?;

                Self::build_resp(0, &resp)
            }
            "stats_meta" => Ok(Self::build_resp(0, &data.lock().unwrap().stats_meta)?),
            req => Err(anyhow!("unknown command {:?}", req).context(ScxStatsErrno(libc::EINVAL)))?,
        }
    }

    fn serve(mut stream: UnixStream, data: Arc<Mutex<ScxStatsServerData>>) -> Result<()> {
        let mut stream_reader = BufReader::new(stream.try_clone()?);

        loop {
            let mut line = String::new();
            stream_reader.read_line(&mut line)?;
            if line.len() == 0 {
                return Ok(());
            }

            let resp = match Self::handle_request(line, &data) {
                Ok(v) => v,
                Err(e) => {
                    let errno = match e.downcast_ref::<ScxStatsErrno>() {
                        Some(e) if e.0 != 0 => e.0,
                        _ => libc::EINVAL,
                    };
                    Self::build_resp(errno, &format!("{:?}", &e))?
                }
            };

            let output = serde_json::to_string(&resp)? + "\n";
            stream.write_all(output.as_bytes())?;
        }
    }

    fn listen(self) {
        loop {
            for stream in self.listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let data = self.data.clone();
                        spawn(move || {
                            if let Err(e) = Self::serve(stream, data) {
                                warn!("stat communication errored ({})", &e);
                            }
                        });
                    }
                    Err(e) => warn!("failed to accept stat connection ({})", &e),
                }
            }
        }
    }
}

pub struct ScxStatsServer {
    base_path: PathBuf,
    sched_path: PathBuf,
    stats_path: PathBuf,
    path: Option<PathBuf>,

    stats_meta_holder: BTreeMap<String, ScxStatsMeta>,
    stats_ops_holder: BTreeMap<String, Arc<Mutex<ScxStatsOps>>>,
}

impl ScxStatsServer {
    pub fn new() -> Self {
        Self {
            base_path: PathBuf::from("/var/run/scx"),
            sched_path: PathBuf::from("root"),
            stats_path: PathBuf::from("stats"),
            path: None,

            stats_meta_holder: BTreeMap::new(),
            stats_ops_holder: BTreeMap::new(),
        }
    }

    pub fn add_stats_meta(mut self, meta: ScxStatsMeta) -> Self {
        self.stats_meta_holder.insert(meta.name.clone(), meta);
        self
    }

    pub fn add_stats_ops(mut self, name: &str, ops: ScxStatsOps) -> Self {
        self.stats_ops_holder
            .insert(name.to_string(), Arc::new(Mutex::new(ops)));
        self
    }

    pub fn add_stats(self, name: &str, fetch: Box<dyn StatsReaderSend>) -> Self {
        let wrapped_fetch = Mutex::new(fetch);
        let read: Box<dyn StatsReaderSync> =
            Box::new(move |args| wrapped_fetch.lock().unwrap()(args));
        let wrapped_read = Arc::new(read);
        let ops = ScxStatsOps {
            open: Box::new(move || {
                let copy = wrapped_read.clone();
                Ok(Box::new(move |args| copy(args)))
            }),
            close: None,
        };

        self.add_stats_ops(name, ops)
    }

    pub fn set_base_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.base_path = PathBuf::from(path.as_ref());
        self
    }

    pub fn set_sched_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.sched_path = PathBuf::from(path.as_ref());
        self
    }

    pub fn set_stats_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.stats_path = PathBuf::from(path.as_ref());
        self
    }

    pub fn set_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.path = Some(PathBuf::from(path.as_ref()));
        self
    }

    pub fn launch(mut self) -> Result<Self> {
        if self.path.is_none() {
            self.path = Some(self.base_path.join(&self.sched_path).join(&self.stats_path));
        }
        let path = &self.path.as_ref().unwrap();

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {:?}", dir))?;
        }

        let res = std::fs::remove_file(path);
        if let std::io::Result::Err(e) = &res {
            if e.kind() != std::io::ErrorKind::NotFound {
                res.with_context(|| format!("deleting {:?}", path))?;
            }
        }

        let listener =
            UnixListener::bind(path).with_context(|| format!("creating UNIX socket {:?}", path))?;

        let mut stats_meta = BTreeMap::new();
        let mut stats = BTreeMap::new();
        std::mem::swap(&mut stats_meta, &mut self.stats_meta_holder);
        std::mem::swap(&mut stats, &mut self.stats_ops_holder);

        let inner = ScxStatsServerInner::new(listener, stats_meta, stats);

        spawn(move || inner.listen());
        Ok(self)
    }
}

pub trait ToJson {
    fn to_json(&self) -> Result<Value>;
}

impl<T> ToJson for T
where
    T: Meta + Serialize,
{
    fn to_json(&self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
    }
}
