// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use ratatui::{Terminal, backend::TestBackend};
use scxtop::{Action, App, AppState, config::Config};
use std::collections::BTreeSet;
use std::{env, fs, path::Path, process::Command};
use tokio::sync::mpsc;

fn write_sysfs(root: &Path, path: &str, contents: &str) {
    let path = root.join("sys/devices/system").join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn with_sysfs(test_name: &str, setup: impl FnOnce(&Path), test: impl FnOnce()) {
    const CHILD_ENV: &str = "SCXTOP_TEST_NUMA_CHILD";

    // Set the sysfs prefix in a child process because scx_utils caches it.
    if env::var_os(CHILD_ENV).is_none() {
        let root = tempfile::tempdir().unwrap();
        setup(root.path());

        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env("SCX_SYSFS_PREFIX", root.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }
    test();
}

#[test]
fn render_cpu_views_with_memory_only_numa_nodes() {
    with_sysfs(
        "render_cpu_views_with_memory_only_numa_nodes",
        |root| {
            write_sysfs(root, "cpu/online", "0-3\n");
            for node in 0..5 {
                write_sysfs(
                    root,
                    &format!("node/node{node}/distance"),
                    "10 20 20 20 20\n",
                );
            }
            // Nodes 0 and 4 represent GPU memory. Node 2 has only an offline CPU.
            for (cpu, node) in [(0, 1), (1, 1), (2, 3), (3, 3), (4, 2)] {
                for (name, value) in [
                    ("core_id", cpu),
                    ("physical_package_id", node),
                    ("cluster_id", node),
                ] {
                    write_sysfs(
                        root,
                        &format!("cpu/cpu{cpu}/topology/{name}"),
                        &value.to_string(),
                    );
                }
                fs::create_dir_all(
                    root.join(format!("sys/devices/system/node/node{node}/cpu{cpu}")),
                )
                .unwrap();
            }
        },
        || render_cpu_views(&[1, 3], &[0, 2, 4]),
    );
}

#[test]
fn grace_cpu_and_memory_numa_nodes() {
    with_sysfs(
        "grace_cpu_and_memory_numa_nodes",
        |root| {
            write_sysfs(root, "cpu/online", "0-143\n");
            for node in 0..34 {
                let distances = (0..34)
                    .map(|other| if other == node { "10" } else { "20" })
                    .collect::<Vec<_>>()
                    .join(" ");
                write_sysfs(root, &format!("node/node{node}/distance"), &distances);
                let cpulist = match node {
                    0 => "0-71\n",
                    1 => "72-143\n",
                    _ => "\n",
                };
                write_sysfs(root, &format!("node/node{node}/cpulist"), cpulist);
            }
            for cpu in 0..144 {
                let node = cpu / 72;
                for (name, value) in [
                    ("core_id", cpu % 72),
                    ("physical_package_id", node),
                    ("cluster_id", node),
                ] {
                    write_sysfs(
                        root,
                        &format!("cpu/cpu{cpu}/topology/{name}"),
                        &value.to_string(),
                    );
                }
                fs::create_dir_all(
                    root.join(format!("sys/devices/system/node/node{node}/cpu{cpu}")),
                )
                .unwrap();
                for (index, level, kind, id, size) in [
                    (0, 1, "Data", cpu, "64K"),
                    (1, 1, "Instruction", cpu, "64K"),
                    (2, 2, "Unified", cpu, "1024K"),
                    (3, 3, "Unified", node, "116736K"),
                ] {
                    let shared_cpus = if level == 3 {
                        format!("{}-{}", node * 72, node * 72 + 71)
                    } else {
                        cpu.to_string()
                    };
                    for (name, value) in [
                        ("level", level.to_string()),
                        ("type", kind.to_string()),
                        ("id", id.to_string()),
                        ("size", size.to_string()),
                        ("shared_cpu_list", shared_cpus),
                    ] {
                        write_sysfs(
                            root,
                            &format!("cpu/cpu{cpu}/cache/index{index}/{name}"),
                            &value,
                        );
                    }
                }
            }
        },
        || {
            render_cpu_views(&[0, 1], &(2..34).collect::<Vec<_>>());
            let rb_cnt = scxtop::topology::calculate_default_ringbuf_count(144);
            assert_eq!(rb_cnt, 9);
            let mapping = scxtop::topology::setup_cpu_to_ringbuf_mapping(rb_cnt, 144).unwrap();
            assert_eq!(mapping.len(), 144);
            assert!(
                mapping.iter().all(|&ring| ring < rb_cnt as u32),
                "invalid mapping: {mapping:?}"
            );
            assert_eq!(mapping.iter().collect::<BTreeSet<_>>().len(), rb_cnt);
            let socket0: BTreeSet<_> = mapping[..72].iter().collect();
            let socket1: BTreeSet<_> = mapping[72..].iter().collect();
            assert!(socket0.is_disjoint(&socket1));
            let mut loads = vec![0; rb_cnt];
            for ring in mapping {
                loads[ring as usize] += 1;
            }
            assert!(
                loads.iter().all(|&cpus| cpus <= 32),
                "unbalanced mapping: {loads:?}"
            );
        },
    );
}

fn render_cpu_views(cpu_nodes: &[usize], empty_nodes: &[usize]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (action_tx, _action_rx) = mpsc::unbounded_channel();
        let mut app = App::new_without_bpf(
            Config::default_config(),
            String::new(),
            100,
            -1,
            false,
            action_tx,
        )
        .unwrap();
        let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();

        app.set_state(AppState::Default);
        terminal.draw(|frame| app.render(frame).unwrap()).unwrap();
        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        for node in cpu_nodes {
            assert!(rendered.contains(&format!("Node{node}")));
        }
        for node in empty_nodes {
            assert!(!rendered.contains(&format!("Node{node}")));
        }

        for state in [AppState::Node, AppState::Default, AppState::Llc] {
            app.set_state(state);
            // Exercise bar charts, line gauges and sparklines.
            for _ in 0..3 {
                terminal.draw(|frame| app.render(frame).unwrap()).unwrap();
                app.handle_action(&Action::NextViewState).unwrap();
            }
        }
        app.handle_action(&Action::Quit).unwrap();
    });
}
