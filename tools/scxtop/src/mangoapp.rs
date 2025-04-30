// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::anyhow;
use anyhow::Result;
use libc::{ftok, msgget, msgrcv, IPC_NOWAIT};
use log::info;
use scx_utils::mangoapp::{mangoapp_msg_v1, MANGOAPP_PROJ_ID};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Duration;

use crate::Action;
use crate::MangoAppAction;

use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{ffi::CString, io};

pub async fn poll_mangoapp(
    mangoapp_path: CString,
    poll_intvl_ms: u64,
    action_tx: UnboundedSender<Action>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let key = unsafe { ftok(mangoapp_path.as_ptr(), MANGOAPP_PROJ_ID) };
    if key == -1 {
        return Err(anyhow!("failed to ftok: {}", io::Error::last_os_error()));
    }

    // Get the key from the queue
    let msgid = unsafe { msgget(key, 0) };
    if msgid == -1 {
        return Err(anyhow!(
            "msgget failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    loop {
        let mut raw_msg: mangoapp_msg_v1 = unsafe { mem::zeroed() };
        let msg_size = unsafe {
            msgrcv(
                msgid,
                &mut raw_msg as *mut _ as *mut libc::c_void,
                mem::size_of::<mangoapp_msg_v1>() - mem::size_of::<i64>(),
                0,
                IPC_NOWAIT, // XXX: this should probably use MSG_COPY as it pulls messages off the
                            // queue and may mess with mangohud or other mangoapp uses.
            )
        };
        if msg_size as isize == -1 {
            info!(
                "mangoapp: msgrcv returned -1 with error {}",
                io::Error::last_os_error()
            );
            tokio::time::sleep(Duration::from_millis(poll_intvl_ms)).await;
            continue;
        }

        let vis_frametime = raw_msg.visible_frametime_ns;
        let fsr_upscale = raw_msg.fsr_upscale;
        let fsr_sharpness = raw_msg.fsr_sharpness;
        let app_frametime = raw_msg.app_frametime_ns;
        let pid = raw_msg.pid;
        let latency_ns = raw_msg.latency_ns;
        let output_width = raw_msg.output_width;
        let output_height = raw_msg.output_height;
        let display_refresh = raw_msg.display_refresh;
        let action = MangoAppAction {
            pid,
            vis_frametime,
            app_frametime,
            fsr_upscale,
            fsr_sharpness,
            latency_ns,
            output_width,
            output_height,
            display_refresh,
        };

        action_tx.send(Action::MangoApp(action))?;
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(poll_intvl_ms)).await;
    }
}
