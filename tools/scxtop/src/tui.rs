// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::{
    io::{stderr, Stderr},
    ops::{Deref, DerefMut},
    time::Duration,
};

use crate::Action;
use crate::Key as TuiKey;
use crate::KeyMap;
use anyhow::anyhow;
use anyhow::Result;
use futures::{FutureExt, StreamExt};
use ratatui::crossterm::event::KeyCode::Char;
use ratatui::{
    backend::CrosstermBackend,
    crossterm::{
        cursor,
        event::{
            DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
            Event as CrosstermEvent, KeyEvent, KeyEventKind, MouseEvent,
        },
        terminal::{EnterAlternateScreen, LeaveAlternateScreen},
    },
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Backspace,
    Init,
    Quit,
    Error,
    Closed,
    Tick,
    TickRateChange(u64),
    Render,
    FocusGained,
    FocusLost,
    Paste(String),
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
}

pub struct Tui {
    pub terminal: ratatui::Terminal<CrosstermBackend<Stderr>>,
    pub task: JoinHandle<()>,
    pub cancellation_token: CancellationToken,
    pub event_rx: UnboundedReceiver<Event>,
    pub event_tx: UnboundedSender<Event>,
    pub frame_rate_ms: usize,
    pub tick_rate_ms: usize,
    pub mouse: bool,
    pub paste: bool,
    pub keymap: KeyMap,
}

impl Tui {
    /// Returns a new Tui.
    pub fn new(keymap: KeyMap, tick_rate_ms: usize, frame_rate_ms: usize) -> Result<Self> {
        let terminal = ratatui::Terminal::new(CrosstermBackend::new(stderr()))?;
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let cancellation_token = CancellationToken::new();
        let task = tokio::spawn(async {});
        let mouse = false;
        let paste = false;
        Ok(Self {
            terminal,
            task,
            cancellation_token,
            event_rx,
            event_tx,
            frame_rate_ms,
            tick_rate_ms,
            mouse,
            paste,
            keymap,
        })
    }

    #[allow(dead_code)]
    pub fn mouse(mut self, mouse: bool) -> Self {
        self.mouse = mouse;
        self
    }

    #[allow(dead_code)]
    pub fn paste(mut self, paste: bool) -> Self {
        self.paste = paste;
        self
    }

    /// Starts the tui.
    pub fn start(&mut self) {
        let mut tick_delay = std::time::Duration::from_millis(self.tick_rate_ms as u64);
        self.frame_rate_ms = self.frame_rate_ms.clamp(15, 5000);
        let render_delay = std::time::Duration::from_millis(self.frame_rate_ms as u64);
        self.cancel();
        self.cancellation_token = CancellationToken::new();
        let _cancellation_token = self.cancellation_token.clone();
        let _event_tx = self.event_tx.clone();
        let keymap = self.keymap.clone();
        self.task = tokio::spawn(async move {
            let mut reader = crossterm::event::EventStream::new();
            let mut tick_interval = tokio::time::interval(tick_delay);
            let mut render_interval = tokio::time::interval(render_delay);
            _event_tx
                .send(Event::Init)
                .expect("Failed to send init event");
            loop {
                let tick = tick_interval.tick();
                let render_delay = render_interval.tick();
                let crossterm_event = reader.next().fuse();
                tokio::select! {
                      _ = _cancellation_token.cancelled() => {
                        break;
                      }
                      maybe_event = crossterm_event => {
                        match maybe_event {
                          Some(Ok(evt)) => {
                            match evt {
                              CrosstermEvent::Key(key) => {
                                if key.kind == KeyEventKind::Press {
                                        let action = match key.code {
                                            Char(c) =>keymap.action(&TuiKey::Char(c)),
                                            _ => keymap.action(&TuiKey::Code(key.code)),
                                        };
                                        match action{
                                            Action::DecTickRate => {
                                                 let new_tick_delay = if tick_delay.as_millis() >= 200 {
                                                     tick_delay -= std::time::Duration::from_millis(100);
                                                     tick_delay
                                                 } else {
                                                     let delay_ms = tick_delay.as_millis() as u64;
                                                     tick_delay = std::time::Duration::from_millis(std::cmp::max(delay_ms.saturating_div(2), 10));
                                                     tick_delay
                                                 };
                                                 _event_tx.send(Event::TickRateChange(new_tick_delay.as_millis() as u64)).expect("Failed to send tick rate change event");
                                                 tick_interval = tokio::time::interval(new_tick_delay);
                                            }
                                            Action::IncTickRate => {
                                                 let new_tick_delay = if tick_delay.as_millis() > 100 {
                                                     tick_delay += std::time::Duration::from_millis(100);
                                                     tick_delay
                                                 } else {
                                                     let delay_ms = tick_delay.as_millis() as u64;
                                                     tick_delay = std::time::Duration::from_millis(delay_ms *2);
                                                     tick_delay
                                                 };
                                                 _event_tx.send(Event::TickRateChange(new_tick_delay.as_millis() as u64)).expect("Failed to send tick rate change event");
                                                 tick_interval = tokio::time::interval(new_tick_delay);
                                            }
                                            _ => {}
                                        }
                                    _event_tx.send(Event::Key(key)).expect("Failed to send key event");
                                }
                          },
                          CrosstermEvent::Mouse(mouse) => {
                            _event_tx.send(Event::Mouse(mouse)).expect("Failed to send mouse event");
                          },
                          CrosstermEvent::Resize(x, y) => {
                            _event_tx.send(Event::Resize(x, y)).expect("Failed to send resize event");
                          },
                          CrosstermEvent::FocusLost => {
                            _event_tx.send(Event::FocusLost).expect("Failed to send focus lost event");
                          },
                          CrosstermEvent::FocusGained => {
                            _event_tx.send(Event::FocusGained).expect("Failed to send focus event");
                          },
                          CrosstermEvent::Paste(s) => {
                            _event_tx.send(Event::Paste(s)).expect("Failed to send paste event");
                          },
                        }
                      }
                      Some(Err(_)) => {
                        _event_tx.send(Event::Error).expect("Failed to send error event");
                      }
                      None => {},
                    }
                  },
                  _ = tick => {
                      _event_tx.send(Event::Tick).expect("Failed to send tick event");
                  },
                  _ = render_delay => {
                      _event_tx.send(Event::Render).expect("Failed to send render event");
                  },
                }
            }
        });
    }

    /// Stops the Tui
    pub fn stop(&self) -> Result<()> {
        self.cancel();
        let mut counter = 0;
        while !self.task.is_finished() {
            std::thread::sleep(Duration::from_millis(1));
            counter += 1;
            if counter > 50 {
                self.task.abort();
            }
            if counter > 100 {
                log::error!("Failed to abort task in 100 milliseconds for unknown reason");
                break;
            }
        }
        Ok(())
    }

    /// Enters the Tui interface.
    pub fn enter(&mut self) -> Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(std::io::stderr(), EnterAlternateScreen, cursor::Hide)?;
        if self.mouse {
            crossterm::execute!(std::io::stderr(), EnableMouseCapture)?;
        }
        if self.paste {
            crossterm::execute!(std::io::stderr(), EnableBracketedPaste)?;
        }
        self.start();
        Ok(())
    }

    /// Exits the Tui interface.
    pub fn exit(&mut self) -> Result<()> {
        self.stop()?;
        if crossterm::terminal::is_raw_mode_enabled()? {
            self.flush()?;
            if self.paste {
                crossterm::execute!(std::io::stderr(), DisableBracketedPaste)?;
            }
            if self.mouse {
                crossterm::execute!(std::io::stderr(), DisableMouseCapture)?;
            }
            crossterm::execute!(std::io::stderr(), LeaveAlternateScreen, cursor::Show)?;
            crossterm::terminal::disable_raw_mode()?;
        }
        Ok(())
    }

    pub fn cancel(&self) {
        self.cancellation_token.cancel();
    }

    #[allow(dead_code)]
    pub fn suspend(&mut self) -> Result<()> {
        self.exit()?;
        #[cfg(not(windows))]
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGTSTP)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn resume(&mut self) -> Result<()> {
        self.enter()?;
        Ok(())
    }

    pub async fn next(&mut self) -> Result<Event> {
        self.event_rx
            .recv()
            .await
            .ok_or(anyhow!("Unable to get event"))
    }
}

impl Deref for Tui {
    type Target = ratatui::Terminal<CrosstermBackend<Stderr>>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

impl DerefMut for Tui {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.exit().expect("Failed to drop Tui");
    }
}
