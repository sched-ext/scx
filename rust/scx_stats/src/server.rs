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

pub trait StatsReader<Tx, Rx>:
    FnMut(&BTreeMap<String, String>, (&Sender<Tx>, &Receiver<Rx>)) -> Result<Value>
{
}
impl<
        Tx,
        Rx,
        T: FnMut(&BTreeMap<String, String>, (&Sender<Tx>, &Receiver<Rx>)) -> Result<Value>,
    > StatsReader<Tx, Rx> for T
{
}

pub trait StatsReaderSend<Tx, Rx>:
    FnMut(&BTreeMap<String, String>, (&Sender<Tx>, &Receiver<Rx>)) -> Result<Value> + Send
{
}
impl<
        Tx,
        Rx,
        T: FnMut(&BTreeMap<String, String>, (&Sender<Tx>, &Receiver<Rx>)) -> Result<Value> + Send,
    > StatsReaderSend<Tx, Rx> for T
{
}

pub trait StatsReaderSync<Tx, Rx>:
    Fn(&BTreeMap<String, String>, (&Sender<Tx>, &Receiver<Rx>)) -> Result<Value> + Send + Sync
{
}
impl<
        Tx,
        Rx,
        T: Fn(&BTreeMap<String, String>, (&Sender<Tx>, &Receiver<Rx>)) -> Result<Value> + Send + Sync,
    > StatsReaderSync<Tx, Rx> for T
{
}

pub trait StatsOpener<Tx, Rx>:
    FnMut((&Sender<Tx>, &Receiver<Rx>)) -> Result<Box<dyn StatsReader<Tx, Rx>>> + Send
{
}
impl<
        Tx,
        Rx,
        T: FnMut((&Sender<Tx>, &Receiver<Rx>)) -> Result<Box<dyn StatsReader<Tx, Rx>>> + Send,
    > StatsOpener<Tx, Rx> for T
{
}

pub trait StatsCloser<Tx, Rx>: FnOnce((&Sender<Tx>, &Receiver<Rx>)) + Send {}
impl<Tx, Rx, T: FnOnce((&Sender<Tx>, &Receiver<Rx>)) + Send> StatsCloser<Tx, Rx> for T {}

pub struct ScxStatsOps<Tx, Rx> {
    open: Box<dyn StatsOpener<Tx, Rx>>,
    close: Option<Box<dyn StatsCloser<Tx, Rx>>>,
}

struct ScxStatsOpenOps<Tx, Rx> {
    map: BTreeMap<
        String,
        (
            Arc<Mutex<ScxStatsOps<Tx, Rx>>>,
            Box<dyn StatsReader<Tx, Rx>>,
            ChannelPair<Tx, Rx>,
        ),
    >,
}

impl<Tx, Rx> ScxStatsOpenOps<Tx, Rx> {
    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl<Tx, Rx> std::ops::Drop for ScxStatsOpenOps<Tx, Rx> {
    fn drop(&mut self) {
        for (_, (ops, _, ch)) in self.map.iter_mut() {
            if let Some(close) = ops.lock().unwrap().close.take() {
                close((&ch.tx, &ch.rx));
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

struct ChannelPair<Tx, Rx> {
    tx: Sender<Tx>,
    rx: Receiver<Rx>,
}

impl<Tx, Rx> ChannelPair<Tx, Rx> {
    fn bidi() -> (ChannelPair<Tx, Rx>, ChannelPair<Rx, Tx>) {
        let (tx, rx) = (unbounded::<Tx>(), unbounded::<Rx>());
        (
            ChannelPair { tx: tx.0, rx: rx.1 },
            ChannelPair { tx: rx.0, rx: tx.1 },
        )
    }
}

impl<Tx, Rx> Clone for ChannelPair<Tx, Rx> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            rx: self.rx.clone(),
        }
    }
}

struct ScxStatsServerData<Tx, Rx> {
    stats_meta: BTreeMap<String, ScxStatsMeta>,
    stats_ops: BTreeMap<String, Arc<Mutex<ScxStatsOps<Tx, Rx>>>>,
}

struct ScxStatsServerInner<Tx, Rx>
where
    Tx: Send + 'static,
    Rx: Send + 'static,
{
    listener: UnixListener,
    data: Arc<Mutex<ScxStatsServerData<Tx, Rx>>>,
    inner_ch: ChannelPair<Tx, Rx>,
    exit: Arc<AtomicBool>,
}

impl<Tx, Rx> ScxStatsServerInner<Tx, Rx>
where
    Tx: Send + 'static,
    Rx: Send + 'static,
{
    fn new(
        listener: UnixListener,
        stats_meta: BTreeMap<String, ScxStatsMeta>,
        stats_ops: BTreeMap<String, Arc<Mutex<ScxStatsOps<Tx, Rx>>>>,
        inner_ch: ChannelPair<Tx, Rx>,
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
        data: &Arc<Mutex<ScxStatsServerData<Tx, Rx>>>,
        ch: &ChannelPair<Tx, Rx>,
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
                    let read = (ops.lock().unwrap().open)((&ch.tx, &ch.rx))?;
                    open_ops
                        .map
                        .insert(target.into(), (ops.clone(), read, ch.clone()));
                }

                let read = &mut open_ops.map.get_mut(target).unwrap().1;

                let resp = read(&req.args, (&ch.tx, &ch.rx))?;

                Self::build_resp(0, &resp)
            }
            "stats_meta" => Ok(Self::build_resp(0, &data.lock().unwrap().stats_meta)?),
            req => Err(anyhow!("unknown command {:?}", req).context(ScxStatsErrno(libc::EINVAL)))?,
        }
    }

    fn serve(
        mut stream: UnixStream,
        data: Arc<Mutex<ScxStatsServerData<Tx, Rx>>>,
        inner_ch: ChannelPair<Tx, Rx>,
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

    fn proxy(inner_ch: ChannelPair<Tx, Rx>, add_rx: Receiver<ChannelPair<Rx, Tx>>) {
        let mut chs_cursor = 0;
        let mut chs = BTreeMap::<u64, ChannelPair<Rx, Tx>>::new();
        let mut ch_to_add: Option<ChannelPair<Rx, Tx>> = None;
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
            let inner_idx = sel.recv(&inner_ch.rx);
            let add_idx = sel.recv(&add_rx);

            let mut chs_sel_idx = BTreeMap::<usize, u64>::new();
            for (idx, cp) in chs.iter() {
                let sel_idx = sel.recv(&cp.rx);
                chs_sel_idx.insert(sel_idx, *idx);
            }

            'select: loop {
                let oper = sel.select();
                match oper.index() {
                    sel_idx if sel_idx == add_idx => match oper.recv(&add_rx) {
                        Ok(ch) => {
                            ch_to_add = Some(ch);
                            debug!("proxy: received new channel from add_rx");
                            break 'select;
                        }
                        Err(RecvError) => {
                            debug!("proxy: add_rx disconnected, terminating");
                            break 'outer;
                        }
                    },
                    sel_idx if sel_idx == inner_idx => match oper.recv(&inner_ch.rx) {
                        Ok(_) => {
                            error!("proxy: unexpected data in ScxStatsServer.channels().0");
                            panic!();
                        }
                        Err(RecvError) => break 'outer,
                    },
                    sel_idx => {
                        let idx = chs_sel_idx.get(&sel_idx).unwrap();
                        let pair = chs.get(idx).unwrap();

                        let req = match oper.recv(&pair.rx) {
                            Ok(v) => v,
                            Err(RecvError) => {
                                idx_to_drop = Some(*idx);
                                break 'select;
                            }
                        };

                        match inner_ch.tx.send(req) {
                            Ok(()) => {}
                            Err(SendError(..)) => break 'outer,
                        }

                        let resp = match inner_ch.rx.recv() {
                            Ok(v) => v,
                            Err(RecvError) => break 'outer,
                        };

                        match pair.tx.send(resp) {
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
        let (add_tx, add_rx) = unbounded::<ChannelPair<Rx, Tx>>();

        spawn(move || Self::proxy(inner_ch_copy, add_rx));

        for stream in self.listener.incoming() {
            if self.exit.load(Ordering::Relaxed) {
                debug!("listener exiting");
                break;
            }
            match stream {
                Ok(stream) => {
                    let data = self.data.clone();
                    let exit = self.exit.clone();

                    let (tx_pair, rx_pair) = ChannelPair::<Tx, Rx>::bidi();
                    match add_tx.send(rx_pair) {
                        Ok(()) => debug!("sent new channel to proxy"),
                        Err(e) => warn!("ScxStatsServer::proxy() failed ({})", &e),
                    }

                    spawn(move || {
                        if let Err(e) = Self::serve(stream, data, tx_pair, exit) {
                            warn!("stat communication errored ({})", &e);
                        }
                    });
                }
                Err(e) => warn!("failed to accept stat connection ({})", &e),
            }
        }
    }
}

pub struct ScxStatsServer<Tx, Rx>
where
    Tx: Send + 'static,
    Rx: Send + 'static,
{
    base_path: PathBuf,
    sched_path: PathBuf,
    stats_path: PathBuf,
    path: Option<PathBuf>,

    stats_meta_holder: BTreeMap<String, ScxStatsMeta>,
    stats_ops_holder: BTreeMap<String, Arc<Mutex<ScxStatsOps<Tx, Rx>>>>,

    outer_ch: ChannelPair<Rx, Tx>,
    inner_ch: Option<ChannelPair<Tx, Rx>>,
    exit: Arc<AtomicBool>,
}

impl<Tx, Rx> ScxStatsServer<Tx, Rx>
where
    Tx: Send + 'static,
    Rx: Send + 'static,
{
    pub fn new() -> Self {
        let (ich, och) = ChannelPair::<Tx, Rx>::bidi();

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

    pub fn add_stats_ops(mut self, name: &str, ops: ScxStatsOps<Tx, Rx>) -> Self {
        self.stats_ops_holder
            .insert(name.to_string(), Arc::new(Mutex::new(ops)));
        self
    }

    pub fn add_stats(self, name: &str, fetch: Box<dyn StatsReaderSend<Tx, Rx>>) -> Self {
        let wrapped_fetch = Mutex::new(fetch);
        let read: Box<dyn StatsReaderSync<Tx, Rx>> =
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

    pub fn channels(&self) -> (Sender<Rx>, Receiver<Tx>) {
        (self.outer_ch.tx.clone(), self.outer_ch.rx.clone())
    }
}

impl<Tx, Rx> std::ops::Drop for ScxStatsServer<Tx, Rx>
where
    Tx: Send + 'static,
    Rx: Send + 'static,
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
