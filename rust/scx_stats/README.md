# Statistics transport library for sched_ext schedulers

[`sched_ext`](https://github.com/sched-ext/scx) is a Linux kernel feature
which enables implementing kernel thread schedulers in BPF and dynamically
loading them.

This library provides an easy way to define statistics and access them
through a UNIX domain socket. While this library is developed for SCX
schedulers, it can be used elsewhere as the only baked-in assumption is the
default UNIX domain socket path which can be overridden.

Statistics are defined as structs. A statistics struct can contain the
following fields:

- Numbers - i32, u32, i64, u64, f64.

- Strings.

- Structs containing allowed fields.

- `Vec`s and `BTreeMap`s containing the above.

The following is taken from [`examples/stats_defs.rs.h`](./examples/stats_defs.rs.h):

```rust
#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "domain statistics", _om_prefix="d_", _om_label="domain_name")]
struct DomainStats {
    pub name: String,
    #[stat(desc = "an event counter")]
    pub events: u64,
    #[stat(desc = "a gauge number")]
    pub pressure: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "cluster statistics", top)]
struct ClusterStats {
    pub name: String,
    #[stat(desc = "update timestamp")]
    pub at: u64,
    #[stat(desc = "some bitmap we want to report", _om_skip)]
    pub bitmap: Vec<u32>,
    #[stat(desc = "domain statistics")]
    pub doms_dict: BTreeMap<usize, DomainStats>,
}
```

`scx_stats_derive::Stats` is the derive macro which generates everything
necessary including the statistics metadata. The `stat` struct and field
attribute allows adding annotations. The following attributes are currently
defined:

*struct and field attributes*

- desc: Description.

*struct-only attributes*

- top: Marks the top-level statistics struct which is reported by default.
  Used by generic tools to find the starting point when processing the
  metadata.

In addition, arbitrary user attributes which start with "_" can be added to
both structs and fields. They are collected into the "user" dict of the
containing struct or field. When the value of such user attribute is not
specified, the string "true" is assigned by default. For example,
[scripts/scxstats_to_openmetrics.py](scripts/scxstats_to_openmetrics.py)
recognizes the following user attribute:

- `_om_prefix`: The value is prefixed to the field name to form the unique
  OpenMetrics metric name.

- `_om_label`: Labels are used to distinguish different members of a dict.
  This field attribute specifies the name of the label for a dict field.

- `_om_skip`: Not all fields might make sense to translate to OpenMetrics.
  This valueless field attribute marks the field to be skipped.

[`examples/stats_defs.rs.h`](./examples/stats_defs.rs.h) shows how the above
attributes can be used. See
[scx_layered](https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_layered/src/stats.rs)
for practical usage.

Note that scx_stats depends on [`serde`](https://crates.io/crates/serde) and
[`serde_json`](https://crates.io/crates/serde_json) and each statistics
struct must derive `Serialize` and `Deserialize`.

The statistics server which serves the above structs through a UNIX domain
socket can be launched as follows:

```rust
    let _server = ScxStatsServer::new()
        .set_path(&path)
        .add_stats_meta(ClusterStats::meta())
        .add_stats_meta(DomainStats::meta())
        .add_stats("top", Box::new(move |_| stats.to_json()))
        .launch()
        .unwrap();
```

The `scx_stats::Meta::meta()` trait function is automatically implemented by
the `scx_stats::Meta` derive macro for each statistics struct. Adding them
to the statistics server allows implementing generic clients which don't
have the definitions of the statistics structs - e.g. to relay the
statistics to another framework such as OpenMetrics.

`top` is the default statistics reported when no specific target is
specified and should always be added to the server. The closure should
return `serde_json::Value`. Note that `scx_stats::ToJson` automatically adds
`.to_json()` to structs which implement both `scx_stats::Meta` and
`serde::Serialize`.

The above will launch the statistics server listening on `@path`. Note that
the server will shutdown when `_server` variable is dropped. The client side
is also simple. Taken from [`examples/client.rs`](./examples/client.rs):

```rust
    let mut client = ScxStatsClient::new().set_path(path).connect(None).unwrap();
```

The above creates a client instance. Let's query the statistics:

```rust
    let resp = client.request::<ClusterStats>("stat", vec![]);
    println!("{:#?}", resp);
```

The above is equivalent to querying the `top` target:

```rust
    println!("\n===== Requesting \"stat\" with \"target\"=\"top\":");
    let resp = client.request::<ClusterStats>("stat", vec![("target".into(), "top".into())]);
    println!("{:#?}", resp);
```

If `("args", BTreeMap<String, String>)` is passed in as a part of the
`@args` vector, the `BTreeMap` will be passed as an argument to the handling
closure on the server side.

When implementing a generic client which does not have access to the
statistics struct definitions, the metadata can come handy:

```rust
    println!("\n===== Requesting \"stats_meta\" but receiving with serde_json::Value:");
    let resp = client.request::<serde_json::Value>("stats_meta", vec![]).unwrap();
    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
```

For this example, the output would look like the following:

```
{
  "ClusterStats": {
    "desc": "cluster statistics",
    "fields": {
      "at": {
        "datum": "u64",
        "desc": "update timestamp"
      },
      "bitmap": {
        "array": "u64",
        "desc": "some bitmap we want to report",
        "user": {
          "_om_skip": "true"
        }
      },
      "doms_dict": {
        "desc": "domain statistics",
        "dict": {
          "datum": {
            "struct": "DomainStats"
          },
          "key": "u64"
        }
      },
      "name": {
        "datum": "string"
      }
    },
    "name": "ClusterStats",
    "top": "true"
  },
  "DomainStats": {
    "desc": "domain statistics",
    "fields": {
      "events": {
        "datum": "u64",
        "desc": "an event counter"
      },
      "name": {
        "datum": "string"
      },
      "pressure": {
        "datum": "float",
        "desc": "a gauge number"
      }
    },
    "name": "DomainStats",
    "user": {
      "_om_label": "domain_name",
      "_om_prefix": "d_"
    }
  }
}
```

The protocol used for communication on the UNIX domain socket is line based
with each line containing a json and straightforward. Run `examples/client`
with `RUST_LOG=trace` set to see what get sent on the wire:

```
> cargo run --example server -- ~/tmp/socket
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.02s
     Running `target/debug/examples/server /home/htejun/tmp/socket`
Server listening. Run `client "/home/htejun/tmp/socket"`.
Use `socat - UNIX-CONNECT:"/home/htejun/tmp/socket"` for raw connection.
Press any key to exit.
```

```
$ RUST_LOG=trace cargo run --example client -- ~/tmp/socket
...
===== Requesting "stats" but receiving with serde_json::Value:
2024-08-15T22:13:23.769Z TRACE [scx_stats::client] Sending: {"req":"stats","args":{"target":"top"}}
2024-08-15T22:13:23.769Z TRACE [scx_stats::client] Received: {"errno":0,"args":{"resp":{"at":12345,"bitmap":[3735928559,3203391149],"doms_dict":{"0":{"events":1234,"name":"domain 0","pressure":1.234},"3":{"events":5678,"name":"domain 3","pressure":5.678}},"name":"test cluster"}}}
Ok(
    Object {
        "at": Number(12345),
        "bitmap": Array [
            Number(3735928559),
            Number(3203391149),
        ],
        "doms_dict": Object {
            "0": Object {
                "events": Number(1234),
                "name": String("domain 0"),
                "pressure": Number(1.234),
            },
            "3": Object {
                "events": Number(5678),
                "name": String("domain 3"),
                "pressure": Number(5.678),
            },
        },
        "name": String("test cluster"),
    },
```
