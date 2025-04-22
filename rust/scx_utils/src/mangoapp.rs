// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub const MANGOAPP_PROJ_ID: i32 = 65;

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct mangoapp_msg_header {
    pub msg_type: libc::c_long,
    pub version: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct mangoapp_msg_v1 {
    pub header: mangoapp_msg_header,
    pub pid: u32,
    pub app_frametime_ns: u64,
    pub fsr_upscale: u8,
    pub fsr_sharpness: u8,
    pub visible_frametime_ns: u64,
    pub latency_ns: u64,
    pub output_width: u32,
    pub output_height: u32,
    pub display_refresh: u16,
    b_app_wants_hdr_steam_focused: u8, // Packs bAppWantsHDR and bSteamFocused
    pub engine_name: [libc::c_char; 40],
}

impl mangoapp_msg_v1 {
    const B_APP_WANTS_HDR_MASK: u8 = 0b0000_0001;
    const B_STEAM_FOCUSED_MASK: u8 = 0b0000_0010;

    #[inline]
    pub fn wants_hdr(&self) -> bool {
        (self.b_app_wants_hdr_steam_focused & Self::B_APP_WANTS_HDR_MASK) != 0
    }

    #[inline]
    pub fn set_wants_hdr(&mut self, value: bool) {
        if value {
            self.b_app_wants_hdr_steam_focused |= Self::B_APP_WANTS_HDR_MASK;
        } else {
            self.b_app_wants_hdr_steam_focused &= !Self::B_APP_WANTS_HDR_MASK;
        }
    }

    #[inline]
    pub fn steam_focused(&self) -> bool {
        (self.b_app_wants_hdr_steam_focused & Self::B_STEAM_FOCUSED_MASK) != 0
    }

    #[inline]
    pub fn set_steam_focused(&mut self, value: bool) {
        if value {
            self.b_app_wants_hdr_steam_focused |= Self::B_STEAM_FOCUSED_MASK;
        } else {
            self.b_app_wants_hdr_steam_focused &= !Self::B_STEAM_FOCUSED_MASK;
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct mangoapp_ctrl_header {
    pub msg_type: libc::c_long,
    pub ctrl_msg_type: u32,
    pub version: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct mangoapp_ctrl_msgid1_v1 {
    pub hdr: mangoapp_ctrl_header,
    pub no_display: u8,
    pub log_session: u8,
    pub log_session_name: [libc::c_char; 64],
    pub reload_config: u8,
}
