//! Switchable color themes + modern egui styling.
//!
//! Each [`Theme`] maps to a [`Palette`] of surfaces, text, an accent, and
//! semantic byte/data colors. [`apply`] turns a palette into an egui `Visuals`
//! with rounded, accent-driven widgets and roomier spacing.

use eframe::egui::{self, Color32};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Theme {
    Carbon,
    Amber,
    Phosphor,
    Violet,
}

impl Theme {
    pub const ALL: [Theme; 4] = [Theme::Carbon, Theme::Amber, Theme::Phosphor, Theme::Violet];

    /// Human-readable name for the menu.
    pub fn name(self) -> &'static str {
        match self {
            Theme::Carbon => "Carbon · cyan",
            Theme::Amber => "Charcoal · amber",
            Theme::Phosphor => "Slate · green",
            Theme::Violet => "Midnight · violet",
        }
    }

    /// Stable id for persistence.
    pub fn id(self) -> &'static str {
        match self {
            Theme::Carbon => "carbon",
            Theme::Amber => "amber",
            Theme::Phosphor => "phosphor",
            Theme::Violet => "violet",
        }
    }

    pub fn from_id(s: &str) -> Option<Theme> {
        Theme::ALL.into_iter().find(|t| t.id() == s.trim())
    }
}

/// A full color set. All fields are `Color32`, so `Palette` is `Copy`.
#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub card: Color32,
    pub raise: Color32,
    pub line: Color32,
    pub line2: Color32,
    pub text: Color32,
    pub dim: Color32,
    pub faint: Color32,
    pub accent: Color32,
    pub accent_ink: Color32,
    /// Selection highlight (accent, semi-transparent) painted behind bytes.
    pub sel: Color32,
    // semantic byte classes
    pub b_zero: Color32,
    pub b_print: Color32,
    pub b_ctrl: Color32,
    pub b_high: Color32,
    pub b_other: Color32,
    // status/severity
    pub ok: Color32,
    pub warn: Color32,
    pub crit: Color32,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}
/// A translucent color (not premultiplied — blends as a proper wash).
fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(r, g, b, a)
}

pub fn palette(t: Theme) -> Palette {
    // Shared semantic byte + status colors (legible on every ground).
    let base = Palette {
        bg: rgb(0x0e, 0x11, 0x16),
        panel: rgb(0x15, 0x1b, 0x22),
        card: rgb(0x1b, 0x23, 0x2c),
        raise: rgb(0x21, 0x2b, 0x35),
        line: rgb(0x29, 0x33, 0x3d),
        line2: rgb(0x20, 0x27, 0x2f),
        text: rgb(0xd8, 0xde, 0xe6),
        dim: rgb(0x77, 0x89, 0x9a),
        faint: rgb(0x4a, 0x55, 0x61),
        accent: rgb(0x37, 0xc6, 0xd8),
        accent_ink: rgb(0x06, 0x22, 0x29),
        sel: rgba(0x37, 0xc6, 0xd8, 64),
        b_zero: rgb(0x5b, 0x65, 0x70),
        b_print: rgb(0x8f, 0xce, 0x9b),
        b_ctrl: rgb(0x7a, 0xa6, 0xdd),
        b_high: rgb(0xe0, 0x91, 0x7f),
        b_other: rgb(0xae, 0xb6, 0xbf),
        ok: rgb(0x63, 0xcf, 0x8e),
        warn: rgb(0xe6, 0xa9, 0x4b),
        crit: rgb(0xe5, 0x7a, 0x6a),
    };
    match t {
        Theme::Carbon => base,
        Theme::Amber => Palette {
            bg: rgb(0x15, 0x12, 0x0c),
            panel: rgb(0x1d, 0x19, 0x0f),
            card: rgb(0x25, 0x1f, 0x13),
            raise: rgb(0x2d, 0x26, 0x17),
            line: rgb(0x35, 0x2c, 0x1c),
            line2: rgb(0x2a, 0x23, 0x16),
            text: rgb(0xec, 0xe3, 0xd2),
            dim: rgb(0x9c, 0x8e, 0x75),
            faint: rgb(0x6a, 0x5f, 0x49),
            accent: rgb(0xf0, 0xa7, 0x3e),
            accent_ink: rgb(0x24, 0x17, 0x01),
            sel: rgba(0xf0, 0xa7, 0x3e, 56),
            ..base
        },
        Theme::Phosphor => Palette {
            bg: rgb(0x0c, 0x10, 0x12),
            panel: rgb(0x13, 0x1a, 0x1b),
            card: rgb(0x19, 0x22, 0x23),
            raise: rgb(0x1f, 0x2a, 0x2a),
            line: rgb(0x24, 0x30, 0x30),
            line2: rgb(0x1c, 0x25, 0x25),
            text: rgb(0xcf, 0xda, 0xd5),
            dim: rgb(0x77, 0x89, 0x83),
            faint: rgb(0x4c, 0x5b, 0x57),
            accent: rgb(0x4f, 0xd4, 0x8c),
            accent_ink: rgb(0x04, 0x23, 0x1a),
            sel: rgba(0x4f, 0xd4, 0x8c, 56),
            ..base
        },
        Theme::Violet => Palette {
            bg: rgb(0x10, 0x0e, 0x1a),
            panel: rgb(0x17, 0x15, 0x26),
            card: rgb(0x1e, 0x1b, 0x32),
            raise: rgb(0x26, 0x22, 0x3d),
            line: rgb(0x2c, 0x28, 0x48),
            line2: rgb(0x22, 0x1f, 0x39),
            text: rgb(0xdf, 0xdc, 0xee),
            dim: rgb(0x89, 0x85, 0xab),
            faint: rgb(0x58, 0x54, 0x76),
            accent: rgb(0x8e, 0x7d, 0xf8),
            accent_ink: rgb(0x0f, 0x0a, 0x26),
            sel: rgba(0x8e, 0x7d, 0xf8, 64),
            ..base
        },
    }
}

/// Apply a theme to the egui context: colors + rounded, accent-driven widgets.
pub fn apply(ctx: &egui::Context, t: Theme) {
    let p = palette(t);
    let mut v = egui::Visuals::dark();
    let stroke = |w: f32, c: Color32| egui::Stroke::new(w, c);

    v.dark_mode = true;
    v.override_text_color = Some(p.text);
    v.panel_fill = p.panel;
    v.window_fill = p.bg;
    v.window_stroke = stroke(1.0, p.line);
    v.extreme_bg_color = p.bg; // text-edit / code background
    v.faint_bg_color = p.card; // striped rows
    v.code_bg_color = p.card;
    v.hyperlink_color = p.accent;
    v.warn_fg_color = p.warn;
    v.error_fg_color = p.crit;

    v.selection.bg_fill = p.sel;
    v.selection.stroke = stroke(1.0, p.accent);

    let r: egui::CornerRadius = 7.into();
    let w = &mut v.widgets;
    // non-interactive surfaces (labels, separators, panels)
    w.noninteractive.bg_fill = p.panel;
    w.noninteractive.weak_bg_fill = p.panel;
    w.noninteractive.bg_stroke = stroke(1.0, p.line2);
    w.noninteractive.fg_stroke = stroke(1.0, p.dim);
    w.noninteractive.corner_radius = r;
    // idle buttons
    w.inactive.bg_fill = p.raise;
    w.inactive.weak_bg_fill = p.card;
    w.inactive.bg_stroke = stroke(1.0, p.line);
    w.inactive.fg_stroke = stroke(1.0, p.text);
    w.inactive.corner_radius = r;
    // hovered
    w.hovered.bg_fill = p.card;
    w.hovered.weak_bg_fill = p.card;
    w.hovered.bg_stroke = stroke(1.0, p.accent);
    w.hovered.fg_stroke = stroke(1.5, p.text);
    w.hovered.corner_radius = r;
    // pressed / active
    w.active.bg_fill = p.accent;
    w.active.weak_bg_fill = p.accent;
    w.active.bg_stroke = stroke(1.0, p.accent);
    w.active.fg_stroke = stroke(1.5, p.accent_ink);
    w.active.corner_radius = r;
    // open (combo/menu)
    w.open.bg_fill = p.card;
    w.open.weak_bg_fill = p.card;
    w.open.bg_stroke = stroke(1.0, p.line);
    w.open.fg_stroke = stroke(1.0, p.text);
    w.open.corner_radius = r;

    v.window_corner_radius = 12.into();
    v.menu_corner_radius = 8.into();
    // Each collapsing section gets a rounded framed header (card-like chip);
    // drop the indent guide-line for cleaner bodies.
    v.collapsing_header_frame = true;
    v.indent_has_left_vline = false;

    // Force a fixed dark theme — otherwise egui follows the OS appearance and
    // re-resolves default (light) visuals on the first frame, wiping ours.
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.set_visuals_of(egui::Theme::Dark, v);
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 5.0);
        s.spacing.menu_margin = egui::Margin::same(6);
    });
}
