use crate::{ScxStatErrno, ScxStatRequest, ScxStatResponse};
use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub struct ScxStatClient {
    base_path: PathBuf,
    sched_path: PathBuf,
    stat_path: PathBuf,
    path: Option<PathBuf>,

    stream: Option<UnixStream>,
    reader: Option<BufReader<UnixStream>>,
}

impl ScxStatClient {
    pub fn new() -> Self {
        Self {
            base_path: PathBuf::from("/var/run/scx"),
            sched_path: PathBuf::from("root"),
            stat_path: PathBuf::from("stat"),
            path: None,

            stream: None,
            reader: None,
        }
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

    pub fn connect(mut self) -> Result<Self> {
        if self.path.is_none() {
            self.path = Some(self.base_path.join(&self.sched_path).join(&self.stat_path));
        }
        let path = &self.path.as_ref().unwrap();

        let stream = UnixStream::connect(path)?;
        self.stream = Some(stream.try_clone()?);
        self.reader = Some(BufReader::new(stream));
        Ok(self)
    }

    pub fn send_request<T>(&mut self, req: &ScxStatRequest) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        if self.stream.is_none() {
            bail!("not connected");
        }

        let req = serde_json::to_string(&req)? + "\n";
        self.stream.as_ref().unwrap().write_all(req.as_bytes())?;

        let mut line = String::new();
        self.reader.as_mut().unwrap().read_line(&mut line)?;
        let mut resp: ScxStatResponse = serde_json::from_str(&line)?;

        let (errno, resp) = (
            resp.errno,
            resp.args.remove("resp").unwrap_or(serde_json::Value::Null),
        );

        if errno != 0 {
            Err(anyhow!("{}", &resp).context(ScxStatErrno(errno)))?;
        }

        Ok(serde_json::from_value(resp)?)
    }

    pub fn request<T>(&mut self, req: &str, args: Vec<(String, String)>) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        self.send_request(&ScxStatRequest::new(req, args))
    }
}
