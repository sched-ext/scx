use crate::StatsErrno;
use crate::StatsRequest;
use crate::StatsResponse;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use log::trace;
use serde::Deserialize;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::io::{self};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

pub struct StatsClient {
    base_path: PathBuf,
    sched_path: PathBuf,
    stats_path: PathBuf,
    path: Option<PathBuf>,

    stream: Option<UnixStream>,
    reader: Option<BufReader<UnixStream>>,
}

impl StatsClient {
    pub fn new() -> Self {
        Self {
            base_path: PathBuf::from("/var/run/scx"),
            sched_path: PathBuf::from("root"),
            stats_path: PathBuf::from("stats"),
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

    pub fn set_stats_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.stats_path = PathBuf::from(path.as_ref());
        self
    }

    pub fn set_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.path = Some(PathBuf::from(path.as_ref()));
        self
    }

    pub fn connect(mut self, timeout_ms: Option<u64>) -> Result<Self> {
        if self.path.is_none() {
            self.path = Some(self.base_path.join(&self.sched_path).join(&self.stats_path));
        }
        let path = self.path.as_ref().unwrap();

        let stream = UnixStream::connect(path)?;
        // Apply the same timeout to both writer and reader sides if provided
        if let Some(ms) = timeout_ms {
            let dur = Duration::from_millis(ms);
            stream.set_write_timeout(Some(dur))?;
            stream.set_read_timeout(Some(dur))?;
        }

        self.stream = Some(stream.try_clone()?);
        self.reader = Some(BufReader::new(stream));
        Ok(self)
    }

    pub fn send_request<T>(&mut self, req: &StatsRequest) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        if self.stream.is_none() {
            bail!("not connected");
        }

        let req = serde_json::to_string(&req)? + "\n";
        trace!("Sending: {}", req.trim());
        // Attempt write with timeout
        if let Err(e) = self.stream.as_ref().unwrap().write_all(req.as_bytes()) {
            if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                return Err(anyhow!("write timed out"));
            } else {
                return Err(e.into());
            }
        }

        let mut line = String::new();
        match self.reader.as_mut().unwrap().read_line(&mut line) {
            Ok(0) => return Err(anyhow!("connection closed")),
            Ok(_) => { /* proceed */ }
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                    return Err(anyhow!("read timed out"));
                } else {
                    return Err(e.into());
                }
            }
        }

        trace!("Received: {}", line.trim());
        let mut resp: StatsResponse = serde_json::from_str(&line)?;

        let (errno, resp) = (
            resp.errno,
            resp.args.remove("resp").unwrap_or(serde_json::Value::Null),
        );

        if errno != 0 {
            Err(anyhow!("{}", &resp).context(StatsErrno(errno)))?;
        }

        Ok(serde_json::from_value(resp)?)
    }

    pub fn request<T>(&mut self, req: &str, args: Vec<(String, String)>) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        self.send_request(&StatsRequest::new(req, args))
    }
}
