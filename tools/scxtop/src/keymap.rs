// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::Action;
use crate::AppState;
use anyhow::anyhow;
use anyhow::Result;
use crossterm::event::KeyCode;
use crossterm::event::MediaKeyCode;
use crossterm::event::ModifierKeyCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Eq, Hash, PartialOrd, PartialEq)]
pub enum Key {
    Char(char),
    Code(KeyCode),
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Key::Char(c) => write!(f, "{c}"),
            Key::Code(c) => write!(f, "{c}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMap {
    bindings: HashMap<Key, Action>,
}

impl Default for KeyMap {
    /// Returns the default keymap.
    fn default() -> Self {
        let mut bindings = HashMap::new();
        bindings.insert(Key::Char('b'), Action::SetState(AppState::BpfPrograms));
        bindings.insert(Key::Char('d'), Action::SetState(AppState::Default));
        bindings.insert(Key::Char(' '), Action::SetState(AppState::Pause));
        bindings.insert(Key::Char('e'), Action::SetState(AppState::PerfEvent));
        bindings.insert(Key::Char('K'), Action::SetState(AppState::KprobeEvent));
        bindings.insert(Key::Char('p'), Action::SetState(AppState::Process));
        bindings.insert(Key::Char('T'), Action::SetState(AppState::PerfTop));
        bindings.insert(Key::Char('f'), Action::Filter);
        bindings.insert(Key::Char('u'), Action::ToggleUncoreFreq);
        bindings.insert(Key::Char('F'), Action::ToggleCpuFreq);
        bindings.insert(Key::Char('L'), Action::ToggleLocalization);
        bindings.insert(Key::Char('P'), Action::ToggleHwPressure);
        bindings.insert(Key::Char('h'), Action::SetState(AppState::Help));
        bindings.insert(Key::Char('m'), Action::SetState(AppState::MangoApp));
        bindings.insert(Key::Char('M'), Action::SetState(AppState::Memory));
        bindings.insert(Key::Char('?'), Action::SetState(AppState::Help));
        bindings.insert(Key::Char('l'), Action::SetState(AppState::Llc));
        bindings.insert(Key::Char('n'), Action::SetState(AppState::Node));
        bindings.insert(Key::Char('N'), Action::SetState(AppState::Network));
        bindings.insert(Key::Char('w'), Action::SetState(AppState::Power));
        bindings.insert(Key::Char('s'), Action::SetState(AppState::Scheduler));
        bindings.insert(Key::Char('S'), Action::SaveConfig);
        bindings.insert(Key::Char('a'), Action::RequestTrace);
        bindings.insert(Key::Char('x'), Action::ClearEvent);
        bindings.insert(Key::Char('j'), Action::PrevEvent);
        bindings.insert(Key::Char('k'), Action::NextEvent);
        bindings.insert(Key::Char('q'), Action::Quit);
        bindings.insert(Key::Char('Q'), Action::Quit);
        bindings.insert(Key::Char('t'), Action::ChangeTheme);
        bindings.insert(Key::Char('-'), Action::DecTickRate);
        bindings.insert(Key::Char('+'), Action::IncTickRate);
        bindings.insert(Key::Char('['), Action::DecBpfSampleRate);
        bindings.insert(Key::Char(']'), Action::IncBpfSampleRate);
        bindings.insert(Key::Char('v'), Action::NextViewState);
        bindings.insert(Key::Code(KeyCode::Down), Action::Down);
        bindings.insert(Key::Code(KeyCode::Up), Action::Up);
        bindings.insert(Key::Code(KeyCode::PageDown), Action::PageDown);
        bindings.insert(Key::Code(KeyCode::PageUp), Action::PageUp);
        bindings.insert(Key::Code(KeyCode::Enter), Action::Enter);
        bindings.insert(Key::Code(KeyCode::Esc), Action::Esc);
        bindings.insert(Key::Code(KeyCode::Backspace), Action::Backspace);

        Self { bindings }
    }
}

impl KeyMap {
    /// Returns an empty KeyMap.
    pub fn empty() -> KeyMap {
        let bindings = HashMap::new();
        KeyMap { bindings }
    }

    /// Returns if the KeyMap is empty.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    // Returns an Action for a Key.
    pub fn get(&self, key: &Key) -> Option<&Action> {
        self.bindings.get(key)
    }

    /// Maps the Key to an Action.
    pub fn action(&self, key: &Key) -> Action {
        self.bindings.get(key).cloned().unwrap_or(Action::None)
    }

    /// Inserts a Key mapping for an Action.
    pub fn insert(&mut self, key: Key, action: Action) {
        self.bindings.insert(key, action);
    }

    /// Returns the Keys for an Action.
    pub fn action_keys(&self, action: Action) -> Vec<Key> {
        let mut keys = Vec::new();
        for (key, key_action) in &self.bindings {
            if *key_action == action {
                keys.push(key.clone());
            }
        }
        keys
    }

    /// Returns a String of the keys for an Action.
    pub fn action_keys_string(&self, action: Action) -> String {
        let action_keys = self.action_keys(action);
        action_keys
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join("/")
    }

    pub fn to_hashmap(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (key, action) in &self.bindings {
            map.insert(format!("{key}"), format!("{action}"));
        }
        map
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialOrd, PartialEq, Serialize, Deserialize)]
pub enum KeyCodeWrapper {
    Backspace,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Tab,
    BackTab,
    Enter,
    Esc,
    Delete,
    Insert,
    F(u8),
    Null,
    CapsLock,
    ScrollLock,
    NumLock,
    PrintScreen,
    Pause,
    Menu,
    KeypadBegin,
    Media(MediaKeyCodeWrapper),
    Modifier(ModifierKeyCodeWrapper),
}

#[derive(Clone, Debug, Eq, Hash, PartialOrd, PartialEq, Serialize, Deserialize)]
pub enum MediaKeyCodeWrapper {
    FastForward,
    LowerVolume,
    MuteVolume,
    Pause,
    Play,
    PlayPause,
    RaiseVolume,
    Record,
    Reverse,
    Rewind,
    Stop,
    TrackNext,
    TrackPrevious,
}

#[derive(Clone, Debug, Eq, Hash, PartialOrd, PartialEq, Serialize, Deserialize)]
pub enum ModifierKeyCodeWrapper {
    LeftShift,
    LeftControl,
    LeftAlt,
    LeftSuper,
    LeftHyper,
    LeftMeta,
    RightShift,
    RightControl,
    RightAlt,
    RightSuper,
    RightHyper,
    RightMeta,
    IsoLevel3Shift,
    IsoLevel5Shift,
}

impl From<KeyCode> for KeyCodeWrapper {
    fn from(keycode: KeyCode) -> Self {
        match keycode {
            KeyCode::Backspace => KeyCodeWrapper::Backspace,
            KeyCode::Left => KeyCodeWrapper::Left,
            KeyCode::Right => KeyCodeWrapper::Right,
            KeyCode::Up => KeyCodeWrapper::Up,
            KeyCode::Down => KeyCodeWrapper::Down,
            KeyCode::Home => KeyCodeWrapper::Home,
            KeyCode::End => KeyCodeWrapper::End,
            KeyCode::PageUp => KeyCodeWrapper::PageUp,
            KeyCode::PageDown => KeyCodeWrapper::PageDown,
            KeyCode::Tab => KeyCodeWrapper::Tab,
            KeyCode::BackTab => KeyCodeWrapper::BackTab,
            KeyCode::Enter => KeyCodeWrapper::Enter,
            KeyCode::Esc => KeyCodeWrapper::Esc,
            KeyCode::Delete => KeyCodeWrapper::Delete,
            KeyCode::Insert => KeyCodeWrapper::Insert,
            KeyCode::F(n) => KeyCodeWrapper::F(n),
            KeyCode::Null => KeyCodeWrapper::Null,
            KeyCode::CapsLock => KeyCodeWrapper::CapsLock,
            KeyCode::ScrollLock => KeyCodeWrapper::ScrollLock,
            KeyCode::NumLock => KeyCodeWrapper::NumLock,
            KeyCode::PrintScreen => KeyCodeWrapper::PrintScreen,
            KeyCode::Pause => KeyCodeWrapper::Pause,
            KeyCode::Menu => KeyCodeWrapper::Menu,
            KeyCode::KeypadBegin => KeyCodeWrapper::KeypadBegin,
            KeyCode::Media(media) => KeyCodeWrapper::Media(match media {
                crossterm::event::MediaKeyCode::FastForward => MediaKeyCodeWrapper::FastForward,
                crossterm::event::MediaKeyCode::PlayPause => MediaKeyCodeWrapper::PlayPause,
                crossterm::event::MediaKeyCode::Play => MediaKeyCodeWrapper::Play,
                crossterm::event::MediaKeyCode::Pause => MediaKeyCodeWrapper::Pause,
                crossterm::event::MediaKeyCode::Rewind => MediaKeyCodeWrapper::Rewind,
                crossterm::event::MediaKeyCode::Reverse => MediaKeyCodeWrapper::Reverse,
                crossterm::event::MediaKeyCode::Stop => MediaKeyCodeWrapper::Stop,
                crossterm::event::MediaKeyCode::TrackNext => MediaKeyCodeWrapper::TrackNext,
                crossterm::event::MediaKeyCode::TrackPrevious => MediaKeyCodeWrapper::TrackPrevious,
                crossterm::event::MediaKeyCode::Record => MediaKeyCodeWrapper::Record,
                crossterm::event::MediaKeyCode::LowerVolume => MediaKeyCodeWrapper::LowerVolume,
                crossterm::event::MediaKeyCode::RaiseVolume => MediaKeyCodeWrapper::RaiseVolume,
                crossterm::event::MediaKeyCode::MuteVolume => MediaKeyCodeWrapper::MuteVolume,
            }),
            KeyCode::Modifier(modifier) => KeyCodeWrapper::Modifier(match modifier {
                crossterm::event::ModifierKeyCode::LeftShift => ModifierKeyCodeWrapper::LeftShift,
                crossterm::event::ModifierKeyCode::LeftControl => {
                    ModifierKeyCodeWrapper::LeftControl
                }
                crossterm::event::ModifierKeyCode::LeftAlt => ModifierKeyCodeWrapper::LeftAlt,
                crossterm::event::ModifierKeyCode::LeftSuper => ModifierKeyCodeWrapper::LeftSuper,
                crossterm::event::ModifierKeyCode::LeftHyper => ModifierKeyCodeWrapper::LeftHyper,
                crossterm::event::ModifierKeyCode::LeftMeta => ModifierKeyCodeWrapper::LeftMeta,
                crossterm::event::ModifierKeyCode::RightShift => ModifierKeyCodeWrapper::RightShift,
                crossterm::event::ModifierKeyCode::RightControl => {
                    ModifierKeyCodeWrapper::RightControl
                }
                crossterm::event::ModifierKeyCode::RightAlt => ModifierKeyCodeWrapper::RightAlt,
                crossterm::event::ModifierKeyCode::RightSuper => ModifierKeyCodeWrapper::RightSuper,
                crossterm::event::ModifierKeyCode::RightHyper => ModifierKeyCodeWrapper::RightHyper,
                crossterm::event::ModifierKeyCode::RightMeta => ModifierKeyCodeWrapper::RightMeta,
                crossterm::event::ModifierKeyCode::IsoLevel3Shift => {
                    ModifierKeyCodeWrapper::IsoLevel3Shift
                }
                crossterm::event::ModifierKeyCode::IsoLevel5Shift => {
                    ModifierKeyCodeWrapper::IsoLevel5Shift
                }
            }),
            _ => todo!(),
        }
    }
}

impl From<KeyCodeWrapper> for KeyCode {
    fn from(keycode_wrapper: KeyCodeWrapper) -> Self {
        match keycode_wrapper {
            KeyCodeWrapper::Backspace => KeyCode::Backspace,
            KeyCodeWrapper::Left => KeyCode::Left,
            KeyCodeWrapper::Right => KeyCode::Right,
            KeyCodeWrapper::Up => KeyCode::Up,
            KeyCodeWrapper::Down => KeyCode::Down,
            KeyCodeWrapper::Home => KeyCode::Home,
            KeyCodeWrapper::End => KeyCode::End,
            KeyCodeWrapper::PageUp => KeyCode::PageUp,
            KeyCodeWrapper::PageDown => KeyCode::PageDown,
            KeyCodeWrapper::Tab => KeyCode::Tab,
            KeyCodeWrapper::BackTab => KeyCode::BackTab,
            KeyCodeWrapper::Enter => KeyCode::Enter,
            KeyCodeWrapper::Esc => KeyCode::Esc,
            KeyCodeWrapper::Delete => KeyCode::Delete,
            KeyCodeWrapper::Insert => KeyCode::Insert,
            KeyCodeWrapper::F(n) => KeyCode::F(n),
            KeyCodeWrapper::Null => KeyCode::Null,
            KeyCodeWrapper::CapsLock => KeyCode::CapsLock,
            KeyCodeWrapper::ScrollLock => KeyCode::ScrollLock,
            KeyCodeWrapper::NumLock => KeyCode::NumLock,
            KeyCodeWrapper::PrintScreen => KeyCode::PrintScreen,
            KeyCodeWrapper::Pause => KeyCode::Pause,
            KeyCodeWrapper::Menu => KeyCode::Menu,
            KeyCodeWrapper::KeypadBegin => KeyCode::KeypadBegin,
            KeyCodeWrapper::Media(media) => KeyCode::Media(match media {
                MediaKeyCodeWrapper::PlayPause => MediaKeyCode::PlayPause,
                MediaKeyCodeWrapper::Play => MediaKeyCode::Play,
                MediaKeyCodeWrapper::Pause => MediaKeyCode::Pause,
                MediaKeyCodeWrapper::Stop => MediaKeyCode::Stop,
                MediaKeyCodeWrapper::TrackNext => MediaKeyCode::TrackNext,
                MediaKeyCodeWrapper::TrackPrevious => MediaKeyCode::TrackPrevious,
                MediaKeyCodeWrapper::Record => MediaKeyCode::Record,
                MediaKeyCodeWrapper::Reverse => MediaKeyCode::Reverse,
                MediaKeyCodeWrapper::Rewind => MediaKeyCode::Rewind,
                MediaKeyCodeWrapper::FastForward => MediaKeyCode::FastForward,
                MediaKeyCodeWrapper::LowerVolume => MediaKeyCode::LowerVolume,
                MediaKeyCodeWrapper::RaiseVolume => MediaKeyCode::RaiseVolume,
                MediaKeyCodeWrapper::MuteVolume => MediaKeyCode::MuteVolume,
            }),
            KeyCodeWrapper::Modifier(modifier) => KeyCode::Modifier(match modifier {
                ModifierKeyCodeWrapper::LeftShift => ModifierKeyCode::LeftShift,
                ModifierKeyCodeWrapper::LeftControl => ModifierKeyCode::LeftControl,
                ModifierKeyCodeWrapper::LeftAlt => ModifierKeyCode::LeftAlt,
                ModifierKeyCodeWrapper::LeftSuper => ModifierKeyCode::LeftSuper,
                ModifierKeyCodeWrapper::LeftHyper => ModifierKeyCode::LeftHyper,
                ModifierKeyCodeWrapper::LeftMeta => ModifierKeyCode::LeftMeta,
                ModifierKeyCodeWrapper::RightShift => ModifierKeyCode::RightShift,
                ModifierKeyCodeWrapper::RightControl => ModifierKeyCode::RightControl,
                ModifierKeyCodeWrapper::RightAlt => ModifierKeyCode::RightAlt,
                ModifierKeyCodeWrapper::RightSuper => ModifierKeyCode::RightSuper,
                ModifierKeyCodeWrapper::RightHyper => ModifierKeyCode::RightHyper,
                ModifierKeyCodeWrapper::RightMeta => ModifierKeyCode::RightMeta,
                ModifierKeyCodeWrapper::IsoLevel3Shift => ModifierKeyCode::IsoLevel3Shift,
                ModifierKeyCodeWrapper::IsoLevel5Shift => ModifierKeyCode::IsoLevel5Shift,
            }),
        }
    }
}

/// Parses a key from a string.
pub fn parse_key(key_str: &str) -> Result<Key> {
    if key_str.len() == 1 {
        Ok(Key::Char(key_str.chars().next().unwrap()))
    } else if let Ok(keycode_wrapper) = toml::from_str::<KeyCodeWrapper>(&format!("\"{key_str}\""))
    {
        Ok(Key::Code(keycode_wrapper.into()))
    } else {
        match key_str.to_lowercase().as_str() {
            "page up" | "pageup" => Ok(Key::Code(KeyCode::PageUp)),
            "page down" | "pagedown" => Ok(Key::Code(KeyCode::PageDown)),
            "up" => Ok(Key::Code(KeyCode::Up)),
            "down" => Ok(Key::Code(KeyCode::Down)),
            "enter" => Ok(Key::Code(KeyCode::Enter)),
            "backspace" => Ok(Key::Code(KeyCode::Backspace)),
            "esc" | "escape" => Ok(Key::Code(KeyCode::Esc)),
            _ => Err(anyhow!("Invalid key: {}", key_str)),
        }
    }
}

/// Parses an Action from a string.
pub fn parse_action(action_str: &str) -> Result<Action> {
    match action_str {
        "AppStateBpfPrograms" | "SetState(BpfPrograms)" => {
            Ok(Action::SetState(AppState::BpfPrograms))
        }
        "AppStateDefault" | "SetState(Default)" => Ok(Action::SetState(AppState::Default)),
        "AppStatePause" | "SetState(Pause)" => Ok(Action::SetState(AppState::Pause)),
        "AppStatePerfEvent" | "SetState(PerfEvent)" => Ok(Action::SetState(AppState::PerfEvent)),
        "AppStateProcess" | "SetState(Process)" => Ok(Action::SetState(AppState::Process)),
        "AppStatePerfTop" | "SetState(PerfTop)" => Ok(Action::SetState(AppState::PerfTop)),
        "AppStateKprobeEvent" | "SetState(KprobeEvent)" => {
            Ok(Action::SetState(AppState::KprobeEvent))
        }
        "Filter" => Ok(Action::Filter),
        "ToggleCpuFreq" => Ok(Action::ToggleCpuFreq),
        "ToggleUncoreFreq" => Ok(Action::ToggleUncoreFreq),
        "ToggleLocalization" => Ok(Action::ToggleLocalization),
        "ToggleHwPressure" => Ok(Action::ToggleHwPressure),
        "AppStateHelp" | "SetState(Help)" => Ok(Action::SetState(AppState::Help)),
        "AppStateLlc" | "SetState(Llc)" => Ok(Action::SetState(AppState::Llc)),
        "AppStateMangoApp" | "SetState(MangoApp)" => Ok(Action::SetState(AppState::MangoApp)),
        "AppStateMemory" | "SetState(Memory)" => Ok(Action::SetState(AppState::Memory)),
        "AppStateNode" | "SetState(Node)" => Ok(Action::SetState(AppState::Node)),
        "AppStateScheduler" | "SetState(Scheduler)" => Ok(Action::SetState(AppState::Scheduler)),
        "AppStateNetwork" | "SetState(Network)" => Ok(Action::SetState(AppState::Network)),
        "SaveConfig" => Ok(Action::SaveConfig),
        "RequestTrace" => Ok(Action::RequestTrace),
        "ClearEvent" => Ok(Action::ClearEvent),
        "PrevEvent" => Ok(Action::PrevEvent),
        "NextEvent" => Ok(Action::NextEvent),
        "Quit" => Ok(Action::Quit),
        "ChangeTheme" => Ok(Action::ChangeTheme),
        "DecTickRate" => Ok(Action::DecTickRate),
        "IncTickRate" => Ok(Action::IncTickRate),
        "DecBpfSampleRate" => Ok(Action::DecBpfSampleRate),
        "IncBpfSampleRate" => Ok(Action::IncBpfSampleRate),
        "PerfSampleRateIncrease" => Ok(Action::PerfSampleRateIncrease),
        "PerfSampleRateDecrease" => Ok(Action::PerfSampleRateDecrease),
        "NextViewState" => Ok(Action::NextViewState),
        "Down" => Ok(Action::Down),
        "Up" => Ok(Action::Up),
        "PageDown" => Ok(Action::PageDown),
        "PageUp" => Ok(Action::PageUp),
        "Enter" => Ok(Action::Enter),
        "Esc" => Ok(Action::Esc),
        "Backspace" => Ok(Action::Backspace),
        _ => Err(anyhow!("Invalid action: {}", action_str)),
    }
}
