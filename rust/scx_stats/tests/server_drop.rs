use crossbeam::channel::RecvTimeoutError;
use scx_stats::prelude::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::spawn;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

fn sock_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("scx_stats_{}_{}", std::process::id(), name))
}

fn launch(path: &Path) -> StatsServer<(), u64> {
    let data = StatsServerData::<(), u64>::new().add_stats(
        "top",
        Box::new(|_args, (tx, rx)| {
            tx.send(())?;
            Ok(serde_json::to_value(rx.recv()?)?)
        }),
    );
    StatsServer::new(data).set_path(path).launch().unwrap()
}

fn connect(path: &Path) -> StatsClient {
    StatsClient::new().set_path(path).connect(None).unwrap()
}

// Issue a request from a separate thread, so that the test can act while it is
// in flight. The result arrives on the returned channel, None if the request
// failed, along with the still connected client.
fn request(mut client: StatsClient) -> mpsc::Receiver<(Option<u64>, StatsClient)> {
    let (tx, rx) = mpsc::channel();
    spawn(move || {
        let res = client.request::<u64>("stats", vec![]).ok();
        let _ = tx.send((res, client));
    });
    rx
}

// Run `f` in a separate thread and fail if it doesn't finish in time.
fn finish_in_time(what: &str, f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    spawn(move || {
        f();
        let _ = tx.send(());
    });
    if rx.recv_timeout(TIMEOUT).is_err() {
        panic!("{what} didn't finish in {TIMEOUT:?}");
    }
}

// The scheduler stopped answering, e.g. because it's exiting, while a
// request is in flight.
#[test]
fn drop_with_unanswered_request() {
    let path = sock_path("unanswered");
    let server = launch(&path);
    // `_res_ch` stays alive across the drop like a scheduler's sender. Were it
    // dropped, the proxy's wait would end on its own and the test would pass
    // without the fix.
    let (_res_ch, req_ch) = server.channels();

    let result = request(connect(&path));
    req_ch.recv_timeout(TIMEOUT).unwrap();

    finish_in_time("drop", move || drop(server));
    assert_eq!(
        req_ch.recv_timeout(TIMEOUT),
        Err(RecvTimeoutError::Disconnected)
    );
    assert_eq!(result.recv_timeout(TIMEOUT).unwrap().0, None);
    let _ = std::fs::remove_file(&path);
}

// A client that connects while the proxy waits for a response gets served once
// the response is delivered.
#[test]
fn client_connects_while_waiting() {
    let path = sock_path("waiting");
    let server = launch(&path);
    let (res_ch, req_ch) = server.channels();

    let first = request(connect(&path));
    req_ch.recv_timeout(TIMEOUT).unwrap();

    let second = connect(&path);
    // Give the listener time to hand the second client's channel to the proxy
    // while it still waits for the response.
    std::thread::sleep(Duration::from_millis(100));
    res_ch.send(1).unwrap();
    // Keep the first client connected. Its disconnection would make the proxy
    // pick up the second client's channel regardless.
    let (res, _first) = first.recv_timeout(TIMEOUT).unwrap();
    assert_eq!(res, Some(1));

    let second = request(second);
    req_ch.recv_timeout(TIMEOUT).unwrap();
    res_ch.send(2).unwrap();
    assert_eq!(second.recv_timeout(TIMEOUT).unwrap().0, Some(2));

    finish_in_time("drop", move || drop(server));
    let _ = std::fs::remove_file(&path);
}

// Another server bound the same path and went away. The socket path no
// longer leads to the first server.
#[test]
fn drop_after_path_taken_over() {
    let path = sock_path("taken");
    let server = launch(&path);
    let (_res_ch, req_ch) = server.channels();

    let other = launch(&path);
    finish_in_time("drop of the other server", move || drop(other));

    finish_in_time("drop", move || drop(server));
    assert_eq!(
        req_ch.recv_timeout(TIMEOUT),
        Err(RecvTimeoutError::Disconnected)
    );
    let _ = std::fs::remove_file(&path);
}

// A connected client that isn't sending anything gets disconnected.
#[test]
fn drop_with_idle_client() {
    let path = sock_path("idle");
    let server = launch(&path);
    let (res_ch, req_ch) = server.channels();
    let responder = spawn(move || {
        while req_ch.recv().is_ok() {
            let _ = res_ch.send(42);
        }
    });

    let mut stream = UnixStream::connect(&path).unwrap();
    stream.write_all(b"{\"req\":\"stats\"}\n").unwrap();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    let resp: StatsResponse = serde_json::from_str(&line).unwrap();
    assert_eq!(resp.errno, 0);
    assert_eq!(resp.args["resp"], 42);

    finish_in_time("drop", move || drop(server));
    finish_in_time("responder", move || responder.join().unwrap());

    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);
    let _ = std::fs::remove_file(&path);
}
