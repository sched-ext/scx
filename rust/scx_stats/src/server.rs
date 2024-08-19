use crate::ScxStatsClient;
use crate::{Meta, ScxStatsMeta};
use anyhow::{anyhow, Context, Result};
use crossbeam::channel::{unbounded, Receiver, RecvError, Select, SendError, Sender};
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::spawn;

pub trait StatsReader<Req, Res>:
    FnMut(&BTreeMap<String, String>, (&Sender<Req>, &Receiver<Res>)) -> Result<Value>
{
}
impl<
        Req,
        Res,
        T: FnMut(&BTreeMap<String, String>, (&Sender<Req>, &Receiver<Res>)) -> Result<Value>,
    > StatsReader<Req, Res> for T
{
}

pub trait StatsReaderSend<Req, Res>:
    FnMut(&BTreeMap<String, String>, (&Sender<Req>, &Receiver<Res>)) -> Result<Value> + Send
{
}
impl<
        Req,
        Res,
        T: FnMut(&BTreeMap<String, String>, (&Sender<Req>, &Receiver<Res>)) -> Result<Value> + Send,
    > StatsReaderSend<Req, Res> for T
{
}

pub trait StatsReaderSync<Req, Res>:
    Fn(&BTreeMap<String, String>, (&Sender<Req>, &Receiver<Res>)) -> Result<Value> + Send + Sync
{
}
impl<
        Req,
        Res,
        T: Fn(&BTreeMap<String, String>, (&Sender<Req>, &Receiver<Res>)) -> Result<Value>
            + Send
            + Sync,
    > StatsReaderSync<Req, Res> for T
{
}

pub trait StatsOpener<Req, Res>:
    FnMut((&Sender<Req>, &Receiver<Res>)) -> Result<Box<dyn StatsReader<Req, Res>>> + Send
{
}
impl<
        Req,
        Res,
        T: FnMut((&Sender<Req>, &Receiver<Res>)) -> Result<Box<dyn StatsReader<Req, Res>>> + Send,
    > StatsOpener<Req, Res> for T
{
}

pub trait StatsCloser<Req, Res>: FnOnce((&Sender<Req>, &Receiver<Res>)) + Send {}
impl<Req, Res, T: FnOnce((&Sender<Req>, &Receiver<Res>)) + Send> StatsCloser<Req, Res> for T {}

pub struct ScxStatsOps<Req, Res> {
    pub open: Box<dyn StatsOpener<Req, Res>>,
    pub close: Option<Box<dyn StatsCloser<Req, Res>>>,
}

struct ScxStatsOpenOps<Req, Res> {
    map: BTreeMap<
        String,
        (
            Arc<Mutex<ScxStatsOps<Req, Res>>>,
            Box<dyn StatsReader<Req, Res>>,
            ChannelPair<Req, Res>,
        ),
    >,
}

impl<Req, Res> ScxStatsOpenOps<Req, Res> {
    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl<Req, Res> std::ops::Drop for ScxStatsOpenOps<Req, Res> {
    fn drop(&mut self) {
        for (_, (ops, _, ch)) in self.map.iter_mut() {
            if let Some(close) = ops.lock().unwrap().close.take() {
                close((&ch.req, &ch.res));
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

struct ChannelPair<Req, Res> {
    req: Sender<Req>,
    res: Receiver<Res>,
}

impl<Req, Res> ChannelPair<Req, Res> {
    fn bidi() -> (ChannelPair<Req, Res>, ChannelPair<Res, Req>) {
        let (req, res) = (unbounded::<Req>(), unbounded::<Res>());
        (
            ChannelPair {
                req: req.0,
                res: res.1,
            },
            ChannelPair {
                req: res.0,
                res: req.1,
            },
        )
    }
}

impl<Req, Res> Clone for ChannelPair<Req, Res> {
    fn clone(&self) -> Self {
        Self {
            req: self.req.clone(),
            res: self.res.clone(),
        }
    }
}

struct ScxStatsServerData<Req, Res> {
    stats_meta: BTreeMap<String, ScxStatsMeta>,
    stats_ops: BTreeMap<String, Arc<Mutex<ScxStatsOps<Req, Res>>>>,
}

struct ScxStatsServerInner<Req, Res>
where
    Req: Send + 'static,
    Res: Send + 'static,
{
    listener: UnixListener,
    data: Arc<Mutex<ScxStatsServerData<Req, Res>>>,
    inner_ch: ChannelPair<Req, Res>,
    exit: Arc<AtomicBool>,
}

impl<Req, Res> ScxStatsServerInner<Req, Res>
where
    Req: Send + 'static,
    Res: Send + 'static,
{
    fn new(
        listener: UnixListener,
        stats_meta: BTreeMap<String, ScxStatsMeta>,
        stats_ops: BTreeMap<String, Arc<Mutex<ScxStatsOps<Req, Res>>>>,
        inner_ch: ChannelPair<Req, Res>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        Self {
            listener,
            data: Arc::new(Mutex::new(ScxStatsServerData {
                stats_meta,
                stats_ops,
            })),
            inner_ch,
            exit,
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
        data: &Arc<Mutex<ScxStatsServerData<Req, Res>>>,
        ch: &ChannelPair<Req, Res>,
    ) -> Result<ScxStatsResponse> {
        let req: ScxStatsRequest = serde_json::from_str(&line)?;
        let mut open_ops = ScxStatsOpenOps::new();

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
                    let read = (ops.lock().unwrap().open)((&ch.req, &ch.res))?;
                    open_ops
                        .map
                        .insert(target.into(), (ops.clone(), read, ch.clone()));
                }

                let read = &mut open_ops.map.get_mut(target).unwrap().1;

                let resp = read(&req.args, (&ch.req, &ch.res))?;

                Self::build_resp(0, &resp)
            }
            "stats_meta" => Ok(Self::build_resp(0, &data.lock().unwrap().stats_meta)?),
            req => Err(anyhow!("unknown command {:?}", req).context(ScxStatsErrno(libc::EINVAL)))?,
        }
    }

    fn serve(
        mut stream: UnixStream,
        data: Arc<Mutex<ScxStatsServerData<Req, Res>>>,
        inner_ch: ChannelPair<Req, Res>,
        exit: Arc<AtomicBool>,
    ) -> Result<()> {
        let mut stream_reader = BufReader::new(stream.try_clone()?);

        loop {
            let mut line = String::new();
            stream_reader.read_line(&mut line)?;
            if line.len() == 0 {
                return Ok(());
            }
            if exit.load(Ordering::Relaxed) {
                debug!("server exiting due to exit");
                return Ok(());
            }

            let resp = match Self::handle_request(line, &data, &inner_ch) {
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

    fn proxy(inner_ch: ChannelPair<Req, Res>, add_res: Receiver<ChannelPair<Res, Req>>) {
        let mut chs_cursor = 0;
        let mut chs = BTreeMap::<u64, ChannelPair<Res, Req>>::new();
        let mut ch_to_add: Option<ChannelPair<Res, Req>> = None;
        let mut idx_to_drop: Option<u64> = None;

        'outer: loop {
            if let Some(new_ch) = ch_to_add.take() {
                let idx = chs_cursor;
                chs_cursor += 1;
                chs.insert(idx, new_ch);
                debug!("proxy: added new channel idx={}, total={}", idx, chs.len());
            }

            if let Some(idx) = idx_to_drop.take() {
                debug!("proxy: dropping channel {}, total={}", idx, chs.len());
                chs.remove(&idx).unwrap();
            }

            let mut sel = Select::new();
            let inner_idx = sel.recv(&inner_ch.res);
            let add_idx = sel.recv(&add_res);

            let mut chs_sel_idx = BTreeMap::<usize, u64>::new();
            for (idx, cp) in chs.iter() {
                let sel_idx = sel.recv(&cp.res);
                chs_sel_idx.insert(sel_idx, *idx);
            }

            'select: loop {
                let oper = sel.select();
                match oper.index() {
                    sel_idx if sel_idx == add_idx => match oper.recv(&add_res) {
                        Ok(ch) => {
                            ch_to_add = Some(ch);
                            debug!("proxy: received new channel from add_res");
                            break 'select;
                        }
                        Err(RecvError) => {
                            debug!("proxy: add_res disconnected, terminating");
                            break 'outer;
                        }
                    },
                    sel_idx if sel_idx == inner_idx => match oper.recv(&inner_ch.res) {
                        Ok(_) => {
                            error!("proxy: unexpected data in ScxStatsServer.channels().0");
                            panic!();
                        }
                        Err(RecvError) => break 'outer,
                    },
                    sel_idx => {
                        let idx = chs_sel_idx.get(&sel_idx).unwrap();
                        let pair = chs.get(idx).unwrap();

                        let req = match oper.recv(&pair.res) {
                            Ok(v) => v,
                            Err(RecvError) => {
                                idx_to_drop = Some(*idx);
                                break 'select;
                            }
                        };

                        match inner_ch.req.send(req) {
                            Ok(()) => {}
                            Err(SendError(..)) => break 'outer,
                        }

                        let resp = match inner_ch.res.recv() {
                            Ok(v) => v,
                            Err(RecvError) => break 'outer,
                        };

                        match pair.req.send(resp) {
                            Ok(()) => {}
                            Err(SendError(..)) => {
                                idx_to_drop = Some(*idx);
                                break 'select;
                            }
                        }
                    }
                }
            }
        }
    }

    fn listen(self) {
        let inner_ch_copy = self.inner_ch.clone();
        let (add_req, add_res) = unbounded::<ChannelPair<Res, Req>>();

        spawn(move || Self::proxy(inner_ch_copy, add_res));

        for stream in self.listener.incoming() {
            if self.exit.load(Ordering::Relaxed) {
                debug!("listener exiting");
                break;
            }
            match stream {
                Ok(stream) => {
                    let data = self.data.clone();
                    let exit = self.exit.clone();

                    let (req_pair, res_pair) = ChannelPair::<Req, Res>::bidi();
                    match add_req.send(res_pair) {
                        Ok(()) => debug!("sent new channel to proxy"),
                        Err(e) => warn!("ScxStatsServer::proxy() failed ({})", &e),
                    }

                    spawn(move || {
                        if let Err(e) = Self::serve(stream, data, req_pair, exit) {
                            warn!("stat communication errored ({})", &e);
                        }
                    });
                }
                Err(e) => warn!("failed to accept stat connection ({})", &e),
            }
        }
    }
}

pub struct ScxStatsServer<Req, Res>
where
    Req: Send + 'static,
    Res: Send + 'static,
{
    base_path: PathBuf,
    sched_path: PathBuf,
    stats_path: PathBuf,
    path: Option<PathBuf>,

    stats_meta_holder: BTreeMap<String, ScxStatsMeta>,
    stats_ops_holder: BTreeMap<String, Arc<Mutex<ScxStatsOps<Req, Res>>>>,

    outer_ch: ChannelPair<Res, Req>,
    inner_ch: Option<ChannelPair<Req, Res>>,
    exit: Arc<AtomicBool>,
}

impl<Req, Res> ScxStatsServer<Req, Res>
where
    Req: Send + 'static,
    Res: Send + 'static,
{
    pub fn new() -> Self {
        let (ich, och) = ChannelPair::<Req, Res>::bidi();

        Self {
            base_path: PathBuf::from("/var/run/scx"),
            sched_path: PathBuf::from("root"),
            stats_path: PathBuf::from("stats"),
            path: None,

            stats_meta_holder: BTreeMap::new(),
            stats_ops_holder: BTreeMap::new(),

            outer_ch: och,
            inner_ch: Some(ich),
            exit: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn add_stats_meta(mut self, meta: ScxStatsMeta) -> Self {
        self.stats_meta_holder.insert(meta.name.clone(), meta);
        self
    }

    pub fn add_stats_ops(mut self, name: &str, ops: ScxStatsOps<Req, Res>) -> Self {
        self.stats_ops_holder
            .insert(name.to_string(), Arc::new(Mutex::new(ops)));
        self
    }

    pub fn add_stats(self, name: &str, fetch: Box<dyn StatsReaderSend<Req, Res>>) -> Self {
        let wrapped_fetch = Mutex::new(fetch);
        let read: Box<dyn StatsReaderSync<Req, Res>> =
            Box::new(move |args, chan| wrapped_fetch.lock().unwrap()(args, chan));
        let wrapped_read = Arc::new(read);
        let ops = ScxStatsOps {
            open: Box::new(move |_| {
                let copy = wrapped_read.clone();
                Ok(Box::new(move |args, chan| copy(args, chan)))
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

        let inner = ScxStatsServerInner::new(
            listener,
            stats_meta,
            stats,
            self.inner_ch.take().unwrap(),
            self.exit.clone(),
        );

        spawn(move || inner.listen());
        Ok(self)
    }

    pub fn channels(&self) -> (Sender<Res>, Receiver<Req>) {
        (self.outer_ch.req.clone(), self.outer_ch.res.clone())
    }
}

impl<Req, Res> std::ops::Drop for ScxStatsServer<Req, Res>
where
    Req: Send + 'static,
    Res: Send + 'static,
{
    fn drop(&mut self) {
        self.exit.store(true, Ordering::Relaxed);
        if let Some(path) = self.path.as_ref() {
            let _ = ScxStatsClient::new().set_path(path).connect();
        }
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
