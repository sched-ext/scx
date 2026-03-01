// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use ratatui::layout::Rect;

/// Scroll state for a single pane.
#[derive(Debug, Clone, Default)]
pub struct PaneScrollState {
    /// Current scroll offset (number of items scrolled past).
    pub offset: usize,
    /// Total number of items in the pane's content.
    pub content_len: usize,
    /// Number of items that fit in the visible area.
    pub visible_len: usize,
}

impl PaneScrollState {
    /// Scrolls down by `amount` items, clamping to the maximum offset.
    pub fn scroll_down(&mut self, amount: usize) {
        let max = self.max_offset();
        self.offset = (self.offset + amount).min(max);
    }

    /// Scrolls up by `amount` items, clamping to 0.
    pub fn scroll_up(&mut self, amount: usize) {
        self.offset = self.offset.saturating_sub(amount);
    }

    /// Scrolls down by one page.
    pub fn page_down(&mut self) {
        self.scroll_down(self.visible_len.saturating_sub(1).max(1));
    }

    /// Scrolls up by one page.
    pub fn page_up(&mut self) {
        self.scroll_up(self.visible_len.saturating_sub(1).max(1));
    }

    /// Returns the maximum scroll offset.
    pub fn max_offset(&self) -> usize {
        self.content_len.saturating_sub(self.visible_len)
    }

    /// Returns true if the content exceeds the visible area.
    pub fn needs_scroll(&self) -> bool {
        self.content_len > self.visible_len
    }

    /// Updates the content and visible lengths, clamping offset if needed.
    pub fn set_content_and_visible(&mut self, content_len: usize, visible_len: usize) {
        self.content_len = content_len;
        self.visible_len = visible_len;
        // Clamp offset to valid range
        let max = self.max_offset();
        if self.offset > max {
            self.offset = max;
        }
    }
}

/// Manages pane focus and per-pane scroll state within a view.
#[derive(Debug, Clone)]
pub struct PaneFocusManager {
    /// Total number of panes in the current view.
    pub pane_count: usize,
    /// Index of the currently focused pane (0-based).
    pub focused: usize,
    /// Screen area of each pane (updated each render frame).
    pub areas: Vec<Rect>,
    /// Per-pane scroll state.
    pub scroll_states: Vec<PaneScrollState>,
}

impl PaneFocusManager {
    /// Creates a new PaneFocusManager with `pane_count` panes.
    pub fn new(pane_count: usize) -> Self {
        Self {
            pane_count,
            focused: 0,
            areas: vec![Rect::default(); pane_count],
            scroll_states: (0..pane_count).map(|_| PaneScrollState::default()).collect(),
        }
    }

    /// Cycles focus to the next pane (wraps around).
    pub fn focus_next(&mut self) {
        if self.pane_count > 0 {
            self.focused = (self.focused + 1) % self.pane_count;
        }
    }

    /// Sets focus to a specific pane index.
    pub fn focus_pane(&mut self, index: usize) {
        if index < self.pane_count {
            self.focused = index;
        }
    }

    /// Hit-tests a screen position and focuses the pane under it.
    /// Returns true if a pane was found at the position.
    pub fn focus_at_position(&mut self, col: u16, row: u16) -> bool {
        for (i, area) in self.areas.iter().enumerate() {
            if col >= area.x
                && col < area.x + area.width
                && row >= area.y
                && row < area.y + area.height
            {
                self.focused = i;
                return true;
            }
        }
        false
    }

    /// Registers the screen area for a pane during rendering.
    pub fn register_area(&mut self, pane_index: usize, area: Rect) {
        if pane_index < self.areas.len() {
            self.areas[pane_index] = area;
        }
    }

    /// Returns a reference to the focused pane's scroll state.
    pub fn focused_scroll(&self) -> &PaneScrollState {
        &self.scroll_states[self.focused]
    }

    /// Returns a mutable reference to the focused pane's scroll state.
    pub fn focused_scroll_mut(&mut self) -> &mut PaneScrollState {
        &mut self.scroll_states[self.focused]
    }

    /// Returns true if the pane at `index` is focused.
    pub fn is_focused(&self, index: usize) -> bool {
        self.focused == index
    }

    /// Reconfigures for a new view with `pane_count` panes.
    /// Resets focus to pane 0 and clears all scroll offsets.
    pub fn reconfigure(&mut self, pane_count: usize) {
        self.pane_count = pane_count;
        self.focused = 0;
        self.areas.clear();
        self.areas.resize(pane_count, Rect::default());
        self.scroll_states.clear();
        self.scroll_states
            .resize_with(pane_count, PaneScrollState::default);
    }
}
