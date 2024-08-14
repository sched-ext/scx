use crate::{ScxStatMeta, StatMeta};
use anyhow::{anyhow, Context, Result};
use log::warn;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::spawn;

type StatMap = BTreeMap<
    String,
    Arc<Mutex<Box<dyn FnMut(&BTreeMap<String, String>) -> Result<serde_json::Value> + Send>>>,
>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatRequest {
    pub req: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

impl ScxStatRequest {
    pub fn new(req: &str, args: Vec<(String, String)>) -> Self {
        Self {
            req: req.to_string(),
            args: args.into_iter().collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatResponse {
    pub errno: i32,
    pub args: BTreeMap<String, serde_json::Value>,
}

pub struct ScxStatErrno(pub i32);

impl std::fmt::Display for ScxStatErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", std::io::Error::from_raw_os_error(self.0))
    }
}

impl std::fmt::Debug for ScxStatErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", std::io::Error::from_raw_os_error(self.0))
    }
}

struct ScxStatServerData {
    stat_meta: Vec<ScxStatMeta>,
    stat: StatMap,
}

struct ScxStatServerInner {
    listener: UnixListener,
    data: Arc<Mutex<ScxStatServerData>>,
}

impl ScxStatServerInner {
    fn new(listener: UnixListener, stat_meta: Vec<ScxStatMeta>, stat: StatMap) -> Self {
        Self {
            listener,
            data: Arc::new(Mutex::new(ScxStatServerData { stat_meta, stat })),
        }
    }

    fn build_resp<T>(errno: i32, resp: &T) -> Result<ScxStatResponse>
    where
        T: Serialize,
    {
        Ok(ScxStatResponse {
            errno,
            args: [("resp".into(), serde_json::to_value(resp)?)]
                .into_iter()
                .collect(),
        })
    }

    fn handle_request(
        line: String,
        data: &Arc<Mutex<ScxStatServerData>>,
    ) -> Result<ScxStatResponse> {
        let req: ScxStatRequest = serde_json::from_str(&line)?;

        match req.req.as_str() {
            "stat" => {
                let target = match req.args.get("target") {
                    Some(v) => v,
                    None => "all",
                };

                let handler = match data.lock().unwrap().stat.get(target) {
                    Some(v) => v.clone(),
                    None => Err(anyhow!("unknown stat target {:?}", req)
                        .context(ScxStatErrno(libc::EINVAL)))?,
                };

                let resp = handler.lock().unwrap()(&req.args)?;

                Self::build_resp(0, &resp)
            }
            "stat_meta" => Ok(Self::build_resp(0, &data.lock().unwrap().stat_meta)?),
            req => Err(anyhow!("unknown command {:?}", req).context(ScxStatErrno(libc::EINVAL)))?,
        }
    }

    fn serve(mut stream: UnixStream, data: Arc<Mutex<ScxStatServerData>>) -> Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);

        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.len() == 0 {
                return Ok(());
            }

            let resp = match Self::handle_request(line, &data) {
                Ok(v) => v,
                Err(e) => {
                    let errno = match e.downcast_ref::<ScxStatErrno>() {
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

pub struct ScxStatServer {
    base_path: PathBuf,
    sched_path: PathBuf,
    stat_path: PathBuf,
    path: Option<PathBuf>,

    stat_meta_holder: Vec<ScxStatMeta>,
    stat_holder: StatMap,
}

impl ScxStatServer {
    pub fn new() -> Self {
        Self {
            base_path: PathBuf::from("/var/run/scx"),
            sched_path: PathBuf::from("root"),
            stat_path: PathBuf::from("stat"),
            path: None,

            stat_meta_holder: vec![],
            stat_holder: BTreeMap::new(),
        }
    }

    pub fn add_stat_meta(mut self, meta: ScxStatMeta) -> Self {
        self.stat_meta_holder.push(meta);
        self
    }

    pub fn add_stat(
        mut self,
        name: &str,
        fetch: Box<dyn FnMut(&BTreeMap<String, String>) -> Result<serde_json::Value> + Send>,
    ) -> Self {
        self.stat_holder
            .insert(name.to_string(), Arc::new(Mutex::new(Box::new(fetch))));
        self
    }

    pub fn set_base_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.base_path = PathBuf::from(path.as_ref());
        self
    }

    pub fn set_sched_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.sched_path = PathBuf::from(path.as_ref());
        self
    }

    pub fn set_stat_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.stat_path = PathBuf::from(path.as_ref());
        self
    }

    pub fn set_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.path = Some(PathBuf::from(path.as_ref()));
        self
    }

    pub fn launch(mut self) -> Result<Self> {
        if self.path.is_none() {
            self.path = Some(self.base_path.join(&self.sched_path).join(&self.stat_path));
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

        let mut stat_meta = vec![];
        let mut stat = BTreeMap::new();
        std::mem::swap(&mut stat_meta, &mut self.stat_meta_holder);
        std::mem::swap(&mut stat, &mut self.stat_holder);

        let inner = ScxStatServerInner::new(listener, stat_meta, stat);

        spawn(move || inner.listen());
        Ok(self)
    }
}

pub trait ScxStatOutput {
    fn output(&self) -> Result<serde_json::Value>;
}

impl<T> ScxStatOutput for T
where
    T: StatMeta + Serialize,
{
    fn output(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }
}
