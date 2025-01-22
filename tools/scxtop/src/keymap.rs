// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::Action;
use crate::AppState;
use crossterm::event::KeyCode;
use std::collections::HashMap;

#[derive(Clone, Debug, Eq, Hash, PartialOrd, PartialEq)]
pub enum Key {
    Char(char),
    Code(KeyCode),
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Key::Char(c) => write!(f, "{}", c),
            Key::Code(c) => write!(f, "{}", c),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMap {
    bindings: HashMap<Key, Action>,
}

impl KeyMap {
    /// Returns the default keymap.
    pub fn default() -> Self {
        let mut bindings = HashMap::new();
        bindings.insert(
            Key::Char('d'),
            Action::SetState {
                state: AppState::Default,
            },
        );
        bindings.insert(
            Key::Char('e'),
            Action::SetState {
                state: AppState::Event,
            },
        );
        bindings.insert(Key::Char('f'), Action::ToggleCpuFreq);
        bindings.insert(Key::Char('u'), Action::ToggleUncoreFreq);
        bindings.insert(
            Key::Char('h'),
            Action::SetState {
                state: AppState::Help,
            },
        );
        bindings.insert(
            Key::Char('?'),
            Action::SetState {
                state: AppState::Help,
            },
        );
        bindings.insert(
            Key::Char('l'),
            Action::SetState {
                state: AppState::Llc,
            },
        );
        bindings.insert(
            Key::Char('n'),
            Action::SetState {
                state: AppState::Node,
            },
        );
        bindings.insert(
            Key::Char('s'),
            Action::SetState {
                state: AppState::Scheduler,
            },
        );
        bindings.insert(Key::Char('a'), Action::RecordTrace);
        bindings.insert(Key::Char('P'), Action::RecordTrace);
        bindings.insert(Key::Char('x'), Action::ClearEvent);
        bindings.insert(Key::Char('j'), Action::PrevEvent);
        bindings.insert(Key::Char('k'), Action::NextEvent);
        bindings.insert(Key::Char('q'), Action::Quit);
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

        Self { bindings }
    }

    /// Maps the Key to an Action.
    pub fn action(&self, key: &Key) -> Action {
        self.bindings.get(key).cloned().unwrap_or(Action::None)
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
        format!(
            "{}",
            action_keys
                .iter()
                .map(|k| k.to_string())
                .collect::<Vec<_>>()
                .join("/")
        )
    }
}
