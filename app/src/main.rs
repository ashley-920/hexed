//! hexed — a XOR-decode-oriented hex viewer.
//!
//! View hex + ASCII across multiple file tabs, drag-select a byte range, XOR it
//! with a repeating key (live preview + single-byte brute force), inspect,
//! hash, transform, search, and browse extracted strings.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Align2, Color32, FontId, Rect, Sense};
use egui::{pos2, vec2};
use hexed_core::disasm::disassemble;
use hexed_core::{
    apply_block_op, brute_force_single_byte, entropy_profile, find_pattern, find_strings,
    find_text, hash_all, inspect, parse_hex_pattern, parse_key, parse_pe, shannon_entropy,
    to_base64, to_c_array, to_hex_string, to_text, to_yara_hex, to_yara_rule, xor_preview,
    yara_file_magic, yara_scan, BlockOp, Buffer, Endian, FoundString, Hashes, PeInfo, ScoredKey,
    StringKind, YaraMatch,
};
use hexed_core::{
    byte_histogram, defang, diff_aligned, extract_iocs, find_embedded, imphash, md5_hex,
    scan_signatures, sha256_hex, suspicious_apis, ApiFlag, Embedded, Histogram, Ioc, IocKind,
    SigHit,
};

mod ai;
mod highlight;
mod openwith;
mod theme;
mod vt;

/// egui frame-cache that memoizes the Text-view syntax-highlight [`LayoutJob`]
/// so it is only re-tokenized when the text (or language/colours/font) changes,
/// not every frame. Keyed by `(colours, text, language, font-size-bits)`.
#[derive(Default)]
struct Highlighter;
impl
    egui::util::cache::ComputerMut<
        (highlight::SyntaxColors, &str, highlight::Lang, u32),
        egui::text::LayoutJob,
    > for Highlighter
{
    fn compute(
        &mut self,
        (colors, text, lang, font_bits): (highlight::SyntaxColors, &str, highlight::Lang, u32),
    ) -> egui::text::LayoutJob {
        highlight::layout_job(
            text,
            lang,
            &colors,
            FontId::monospace(f32::from_bits(font_bits)),
        )
    }
}
type HighlightCache = egui::util::cache::FrameCache<egui::text::LayoutJob, Highlighter>;

/// Only syntax-highlight text up to this size; larger files render plain so the
/// per-frame key hash / tokenization can't cost anything noticeable.
const HL_LIMIT: usize = 512 * 1024;
use ai::Ai;
use theme::{Palette, Theme};
use vt::Vt;

const BYTES_PER_ROW: usize = 16;

/// IOC kinds in the order the IOCs panel groups them.
const IOC_KINDS: &[IocKind] = &[
    IocKind::Url,
    IocKind::Domain,
    IocKind::Ipv4,
    IocKind::Email,
    IocKind::WinPath,
    IocKind::UnixPath,
    IocKind::Registry,
    IocKind::Wallet,
];

/// The app icon, embedded so it's available for the window icon, the About box,
/// and export-to-PNG.
const LOGO_PNG: &[u8] = include_bytes!("../../assets/logo.png");

/// Use the macOS system faces (San Francisco + SF Mono) instead of egui's
/// bundled font, matching a native look. Falls back silently if unavailable.
fn install_fonts(ctx: &egui::Context) {
    use std::sync::Arc;
    let mut fonts = egui::FontDefinitions::default();
    if let Ok(d) = std::fs::read("/System/Library/Fonts/SFNS.ttf") {
        fonts
            .font_data
            .insert("ui".to_owned(), Arc::new(egui::FontData::from_owned(d)));
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "ui".to_owned());
    }
    if let Ok(d) = std::fs::read("/System/Library/Fonts/SFNSMono.ttf") {
        fonts
            .font_data
            .insert("mono".to_owned(), Arc::new(egui::FontData::from_owned(d)));
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .insert(0, "mono".to_owned());
    }
    ctx.set_fonts(fonts);
}

fn load_icon() -> Option<egui::IconData> {
    let img = image::load_from_memory(LOGO_PNG).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

/// Wrap a raw RT_ICON DIB in a single-entry `.ico` container so the image crate
/// can decode it (RT_ICON stores a headerless BITMAPINFOHEADER + pixels + mask).
fn wrap_dib_as_ico(dib: &[u8]) -> Vec<u8> {
    let width = i32::from_le_bytes([dib[4], dib[5], dib[6], dib[7]]);
    let height = i32::from_le_bytes([dib[8], dib[9], dib[10], dib[11]]) / 2; // color + mask
    let bit_count = u16::from_le_bytes([dib[14], dib[15]]);
    let to_byte = |v: i32| if (1..=255).contains(&v) { v as u8 } else { 0 }; // 0 = 256
    let mut v = vec![0, 0, 1, 0, 1, 0]; // ICONDIR: reserved, type=1, count=1
    v.push(to_byte(width));
    v.push(to_byte(height));
    v.push(0); // color count
    v.push(0); // reserved
    v.extend_from_slice(&1u16.to_le_bytes()); // planes
    v.extend_from_slice(&bit_count.to_le_bytes());
    v.extend_from_slice(&(dib.len() as u32).to_le_bytes()); // bytesInRes
    v.extend_from_slice(&22u32.to_le_bytes()); // image offset (6 + 16)
    v.extend_from_slice(dib);
    v
}

/// Decode a raw RT_ICON blob (DIB or PNG) to `(width, height, png_bytes, rgba)`.
fn icon_to_png(raw: &[u8]) -> Option<(u32, u32, Vec<u8>, Vec<u8>)> {
    let dynimg = if raw.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        image::load_from_memory(raw).ok()? // Vista+ PNG-in-icon
    } else if raw.len() >= 16 {
        let ico = wrap_dib_as_ico(raw);
        image::load_from_memory_with_format(&ico, image::ImageFormat::Ico).ok()?
    } else {
        return None;
    };
    let (w, h) = (dynimg.width(), dynimg.height());
    let rgba = dynimg.to_rgba8().into_raw();
    let mut png = Vec::new();
    dynimg
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .ok()?;
    Some((w, h, png, rgba))
}

/// Force the native macOS window chrome (title bar + traffic-light area) to the
/// dark appearance so it matches the app's dark theme instead of following the
/// system light/dark setting. No-op on other platforms.
#[cfg(target_os = "macos")]
fn set_dark_titlebar() {
    use objc2_app_kit::{NSAppearance, NSAppearanceNameDarkAqua, NSApplication};
    use objc2_foundation::MainThreadMarker;
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    // App-wide dark appearance darkens the title bar, menus, and native dialogs.
    let dark = unsafe { NSAppearance::appearanceNamed(NSAppearanceNameDarkAqua) };
    app.setAppearance(dark.as_deref());
}
#[cfg(not(target_os = "macos"))]
fn set_dark_titlebar() {}

fn main() -> eframe::Result<()> {
    // Register the macOS "Open With" ('odoc') handler FIRST — before eframe spins
    // up NSApplication — so its willFinishLaunching observer is in place to catch
    // a cold-launch document (delivered during app launch, before our UI exists).
    openwith::install();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1180.0, 780.0])
        .with_min_inner_size([760.0, 480.0])
        .with_title("hexed");
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let initial_paths: Vec<String> = std::env::args().skip(1).collect();
    eframe::run_native(
        "hexed",
        options,
        Box::new(move |cc| {
            let mut app = HexedApp::default();
            install_fonts(&cc.egui_ctx);
            theme::apply(&cc.egui_ctx, app.theme);
            // Wire egui so the (already-installed) 'odoc' handler can nudge repaints.
            openwith::set_context(&cc.egui_ctx);
            // Darken the native macOS title bar to match the dark theme.
            set_dark_titlebar();
            for p in &initial_paths {
                app.open_path(std::path::PathBuf::from(p));
            }
            app.active = 0;
            Ok(Box::new(app))
        }),
    )
}

/// A requested change to the selection coming out of the hex grid.
enum SelUpdate {
    /// Start a fresh selection anchored at this byte.
    Set(usize),
    /// Extend the current selection to this byte.
    Extend(usize),
}

/// Which encoding to copy the current selection as.
#[derive(Clone, Copy, Debug)]
enum CopyKind {
    Hex,
    Text,
    Yara,
    CArray,
    Base64,
}

/// How the central pane renders the file: the hex+ASCII grid or a text view.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Hex,
    Text,
}

/// All state tied to one open file (one tab).
struct Document {
    buffer: Buffer,
    file_name: String,
    sel_anchor: Option<usize>,
    sel_cursor: Option<usize>,
    strings: Vec<FoundString>,
    strings_dirty: bool,
    hashes: Option<(String, Hashes)>,
    xor_key: String,
    brute_results: Vec<ScoredKey>,
    search_query: String,
    search_hex: bool,
    search_ci: bool,
    search_hits: Vec<usize>,
    search_hit_len: usize,
    search_idx: usize,
    scroll_to: Option<usize>,
    /// Frames remaining to keep re-applying `scroll_to` (lets egui's scroll
    /// settle on a huge virtualized buffer instead of missing on one frame).
    scroll_ttl: u8,
    /// A pending "reveal this byte range in the Text view" request (offset, len),
    /// set by `goto` alongside the hex scroll/selection. The hex grid uses
    /// `scroll_to`/`sel_*`; the Text view consumes this to scroll + select the
    /// match, so Find / Goto / click-to-jump work in Text view too.
    text_reveal: Option<(usize, usize)>,
    /// Frames left to keep re-applying `text_reveal`. Focusing the field makes
    /// egui scroll the whole widget to the top; re-asserting our scroll for a few
    /// frames wins that race and lands on the match (mirrors `scroll_ttl`).
    text_reveal_ttl: u8,
    /// Parsed PE structure, if this file is a PE (cached; recomputed on edit).
    pe: Option<PeInfo>,
    /// Named offset bookmarks for this file.
    bookmarks: Vec<(usize, String)>,
    /// Whole-file entropy minimap (cached; recomputed on edit).
    entropy_profile: Vec<f32>,
    /// Last `.bt` template run: the results tree / error message.
    bt_result: Option<Result<hexed_bt::Template, String>>,
    /// Colored byte spans from the last template run (start, end, color),
    /// in pre-order so a nested field's color overrides its parent's.
    bt_spans: Vec<(usize, usize, Color32)>,
    /// Differing byte runs (start, end) from the last binary compare.
    diff_ranges: Vec<(usize, usize)>,
    /// Cursor into `diff_ranges` for step-to-next-difference.
    diff_idx: usize,
    /// One-line summary of the last compare.
    diff_summary: Option<String>,
    /// Whole-file byte-frequency histogram (cached; recomputed on edit).
    histogram: Histogram,
    /// The analyzed file's embedded icon (largest RT_ICON), as PNG + a texture.
    icon_png: Option<Vec<u8>>,
    icon_dims: (u32, u32),
    icon_tex: Option<egui::TextureHandle>,
    /// Extracted network/host indicators (cached; recomputed on edit).
    iocs: Vec<Ioc>,
    /// Embedded files found by magic-signature scan (cached).
    embedded: Vec<Embedded>,
    /// Crypto-constant / packer signature hits (cached).
    sig_hits: Vec<SigHit>,
    /// Flagged suspicious imports (cached; empty for non-PE).
    api_flags: Vec<ApiFlag>,
    /// Import hash of the PE (cached; empty for non-PE / no imports).
    imphash: String,
    /// Whether to render IOCs defanged (hxxp, 1[.]2[.]3[.]4).
    ioc_defang: bool,
    /// Auto-scan results: (rule-file name, match) from the YARA library (cached).
    yara_lib_matches: Vec<(String, YaraMatch)>,
    /// YARA library rules that failed to compile: (file name, error).
    yara_lib_errors: Vec<(String, String)>,
    /// SHA-256 of the whole file (cached; used for VirusTotal lookups).
    file_sha256: String,
    /// Editable text-view buffer (the file decoded as UTF-8-lossy). Rebuilt from
    /// `buffer` whenever `buffer.generation()` no longer matches `text_gen`, so
    /// *any* byte mutation (edit, undo/redo, XOR, block-op, …) refreshes it.
    text_buf: String,
    /// The `buffer.generation()` that `text_buf` was decoded from. `u64::MAX`
    /// means "never built" so the first view always rebuilds.
    text_gen: u64,
    /// Whether `text_buf` has edits not yet committed to the byte buffer.
    text_dirty: bool,
    /// Which nibble the hex-edit caret is on (false = high, true = low).
    hex_low_nibble: bool,
    /// Whether hex-view typing edits the ASCII pane (true) or hex pane (false).
    edit_ascii: bool,
    /// Frames remaining until the heavy re-analysis fires after a byte edit.
    /// Reset on each keystroke so rapid typing coalesces into one rescan once
    /// typing stops (0 = idle). See the debounce tick in `update`.
    derived_ttl: u32,
}

impl Document {
    fn new(buffer: Buffer, file_name: String) -> Self {
        Document {
            buffer,
            file_name,
            sel_anchor: None,
            sel_cursor: None,
            strings: Vec::new(),
            strings_dirty: true,
            hashes: None,
            xor_key: String::new(),
            brute_results: Vec::new(),
            search_query: String::new(),
            search_hex: false,
            search_ci: false,
            search_hits: Vec::new(),
            search_hit_len: 0,
            search_idx: 0,
            scroll_to: Some(0),
            scroll_ttl: 4,
            text_reveal: None,
            text_reveal_ttl: 0,
            pe: None,
            bookmarks: Vec::new(),
            entropy_profile: Vec::new(),
            bt_result: None,
            bt_spans: Vec::new(),
            diff_ranges: Vec::new(),
            diff_idx: 0,
            diff_summary: None,
            histogram: Histogram::default(),
            icon_png: None,
            icon_dims: (0, 0),
            icon_tex: None,
            iocs: Vec::new(),
            embedded: Vec::new(),
            sig_hits: Vec::new(),
            api_flags: Vec::new(),
            imphash: String::new(),
            ioc_defang: true,
            yara_lib_matches: Vec::new(),
            yara_lib_errors: Vec::new(),
            file_sha256: String::new(),
            text_buf: String::new(),
            text_gen: u64::MAX,
            text_dirty: false,
            hex_low_nibble: false,
            edit_ascii: false,
            derived_ttl: 0,
        }
    }

    fn selection_range(&self) -> Option<(usize, usize)> {
        match (self.sel_anchor, self.sel_cursor) {
            (Some(a), Some(c)) => Some((a.min(c), a.max(c) + 1)),
            _ => None,
        }
    }

    /// Scroll to `off` and select `len` bytes there (used by search, the
    /// strings list, and Goto).
    fn goto(&mut self, off: usize, len: usize) {
        self.scroll_to = Some(off);
        self.scroll_ttl = 4;
        self.sel_anchor = Some(off);
        self.sel_cursor = Some((off + len).saturating_sub(1));
        // Mirror the jump into the Text view (consumed by draw_text): scroll to
        // and select the same range, so Find / Goto / click-to-jump land there
        // too, not only in the hex grid.
        self.text_reveal = Some((off, len.max(1)));
        self.text_reveal_ttl = 4;
    }
}

/// Largest char boundary `<= i` (clamped to `s.len()`). Lets the Text view turn a
/// byte offset (from a Find hit / Goto) into a slice index that never panics on a
/// multi-byte UTF-8 boundary before counting chars for egui's char-based cursor.
fn char_boundary_floor(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Invalidate derived state after a length-changing edit: all offset-based
/// caches (strings/PE/entropy/histogram rebuild via `strings_dirty`; search,
/// diff, and template overlays become stale and are cleared).
fn invalidate_derived(d: &mut Document) {
    d.strings_dirty = true;
    d.search_hits.clear();
    d.search_idx = 0;
    d.diff_ranges.clear();
    d.diff_summary = None;
    d.bt_spans.clear();
    d.bt_result = None;
    // Note: the text-view cache invalidates itself via buffer.generation(), so
    // it needs no signal here — every byte mutation is covered, not just these.
}

/// YARA "scan all" results: per file, its `(doc index, name, matches-or-error)`.
type YaraScanResults = Vec<(usize, String, Result<Vec<YaraMatch>, String>)>;

struct HexedApp {
    docs: Vec<Document>,
    active: usize,
    /// The `active` index seen on the previous frame; when it changes we drop the
    /// hex grid's keyboard focus so a keystroke can't land on a doc the user
    /// never clicked into (see the focus reset in `update`).
    last_active: usize,
    /// Set when a document is removed: closing the active (non-last) tab shifts a
    /// *different* doc into the same index, so an index compare alone misses it —
    /// this forces the grid-focus drop regardless of index.
    grid_focus_stale: bool,
    /// Clipboard-copy feedback: which button flashed and until when (egui time).
    copy_flash_id: &'static str,
    copy_flash_until: f64,
    // global view preferences (shared across tabs)
    strings_min_len: usize,
    strings_ascii: bool,
    strings_utf16: bool,
    inspect_endian: Endian,
    goto_query: String,
    replace_query: String,
    bookmark_name: String,
    strings_filter: String,
    yara_source: String,
    /// Per-tab scan results: (doc index, file name, matches-or-error).
    yara_result: Option<YaraScanResults>,
    /// Current `.bt` template source (shared editing surface across tabs).
    bt_source: String,
    /// Auto-load + run the matching built-in template when a file is opened.
    auto_run_template: bool,
    /// Saved YARA templates (name, path) from ~/.hexed_yara_templates.
    yara_templates: Vec<(String, std::path::PathBuf)>,
    /// The YARA rule library (file name, source) — auto-scanned on every open.
    yara_rules: Vec<(String, String)>,
    /// VirusTotal hash-lookup state (opt-in enrichment).
    vt: Vt,
    /// Disassembly bitness: 0 = auto (from PE), else 16/32/64.
    disasm_bits: u32,
    /// Bytes shown per row in the hex grid (8/16/32).
    bytes_per_row: usize,
    /// Central-pane view: hex grid or text.
    view: ViewMode,
    /// Number of zero bytes the "Insert" button adds.
    insert_count: usize,
    /// Byte width for the inspector's number-base converter (1/2/4/8).
    base_width: usize,
    /// Editable value for the base converter (parsed as 0x../0b../0o../dec).
    base_edit: String,
    /// Recently-used XOR keys (most recent first, deduped, max 5), persisted.
    xor_key_history: Vec<String>,
    recent: Vec<std::path::PathBuf>,
    bookmarks_store: BookmarkStore,
    status: String,
    /// AI assistant bridge (codex exec).
    ai: Ai,
    /// Whether the `codex` CLI was found at startup.
    ai_available: bool,
    /// About window visibility + lazily-decoded logo texture.
    show_about: bool,
    logo_tex: Option<egui::TextureHandle>,
    /// The action of the in-flight AI run, for routing its result on completion.
    ai_last_action: Option<AiAction>,
    /// Where a Decode run should write its output (opened as a tab when done).
    ai_pending_open: Option<std::path::PathBuf>,
    /// Active color theme + its resolved palette.
    theme: Theme,
    palette: Palette,
}

fn theme_file_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".hexed_theme.txt"))
}

fn load_theme() -> Theme {
    theme_file_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| Theme::from_id(&s))
        .unwrap_or(Theme::Carbon)
}

fn save_theme(t: Theme) {
    if let Some(p) = theme_file_path() {
        let _ = std::fs::write(p, t.id());
    }
}

/// Remember the central-pane view mode across launches (`~/.hexed_view.txt`).
fn load_view() -> ViewMode {
    std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".hexed_view.txt"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| {
            if s.trim() == "text" {
                ViewMode::Text
            } else {
                ViewMode::Hex
            }
        })
        .unwrap_or(ViewMode::Hex)
}

fn save_view(v: ViewMode) {
    if let Some(h) = std::env::var_os("HOME") {
        let p = std::path::PathBuf::from(h).join(".hexed_view.txt");
        let _ = std::fs::write(p, if v == ViewMode::Text { "text" } else { "hex" });
    }
}

/// A canned AI action triggered from the panel.
#[derive(Clone, Copy)]
enum AiAction {
    Explain,
    Ask,
    Decode,
    Yara,
    Triage,
    Disasm,
    Bt,
}

/// Built-in `.bt` templates bundled into the binary. PE is first so it's the
/// default (this tool leans toward EXE/DLL analysis).
const BUILTIN_TEMPLATES: &[(&str, &str)] = &[
    ("PE", include_str!("../templates/pe.bt")),
    ("PNG", include_str!("../templates/png.bt")),
    ("BMP", include_str!("../templates/bmp.bt")),
    ("GIF", include_str!("../templates/gif.bt")),
    ("ELF", include_str!("../templates/elf.bt")),
    ("ZIP", include_str!("../templates/zip.bt")),
    ("WAV", include_str!("../templates/wav.bt")),
];

/// Today's date as `YYYY-MM-DD` (UTC), for stamping generated artifacts.
fn today_ymd() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    hexed_core::ymd_utc(secs)
}

/// Starter YARA rule scaffold ("New template"): the standard meta block (author
/// and today's date) plus example hex/string patterns and a composite condition.
/// Modeled on the style of well-formed threat-intel rules.
fn yara_template() -> String {
    format!(
        r#"rule RENAME_family_or_capability
{{
    meta:
        author = "Chi-en (Ashley) Shen"
        description = "what this rule detects"
        date = "{date}"
        version = "1.0"
        hash = "<sha256 of a reference sample>"
        reference = "<report or blog url>"

    strings:
        // hex byte pattern: ?? = any byte, [1-4] = 1..4 wildcard bytes
        $code = {{ c1 e0 04 8b d7 c1 ea 04 0b d0 83 e2 3f 8a 82 ?? ?? ?? ?? }}
        // ascii + wide text
        $s1 = "RunPE" ascii wide
        $s2 = "DownLoad" ascii wide

    condition:
        $code or 2 of ($s*)
}}
"#,
        date = today_ymd()
    )
}

/// Strip a leading/trailing Markdown code fence (```lang … ```) so AI-generated
/// rules/templates paste cleanly into the editors.
fn strip_fences(s: &str) -> String {
    let t = s.trim();
    if let (Some(a), Some(b)) = (t.find("```"), t.rfind("```")) {
        if b > a + 3 {
            let inner = &t[a + 3..b];
            // Drop an optional language tag on the fence's first line.
            let inner = match inner.split_once('\n') {
                Some((first, rest)) if !first.contains(' ') && first.len() < 12 => rest,
                _ => inner,
            };
            return inner.trim().to_string();
        }
    }
    t.to_string()
}

// Instruction prompts for the canned AI actions.
const AI_EXPLAIN: &str = "You are a malware reverse-engineering assistant helping a threat analyst. Given the file context and selected bytes, explain what the selection most likely is: its structure, any encoding/encryption, and its purpose. If it looks like x86 code, summarize behavior. Be concise and concrete. You may read the file at the given path and run read-only tools to verify.";
const AI_YARA: &str = "You are a threat-intel analyst. Based on the file context (you may read the file at the given path), write a robust YARA rule that detects this sample and close variants. Prefer stable strings and code patterns over volatile bytes; add a file-type magic guard in the condition when appropriate. Include a meta block with author \"Chi-en (Ashley) Shen\" and today's date. Output ONLY the rule text — no prose, no Markdown fences.";
const AI_TRIAGE: &str = "You are a malware triage analyst. Using the file context and PE report below (you may also read the file at the given path), produce a concise triage: likely family/classification, capabilities, notable APIs/behaviors, MITRE ATT&CK technique IDs, and key IOCs. State uncertainty where relevant.";
const AI_DISASM: &str = "Explain the x86 disassembly in the context below: summarize the behavior in plain language and as short pseudo-C, and note any API calls or notable constructs. Be concise.";
const AI_BT: &str = "Write a 010 Editor binary template (.bt) that parses this file's format based on the context (you may read the file at the given path). Use struct/typedef, arrays sized by earlier fields, and <bgcolor=...>/<format=...> annotations where helpful. Output ONLY the template code — no prose, no Markdown fences.";

/// Sniff the file's format by magic bytes; returns the matching built-in
/// template name, if any.
fn detect_builtin_name(data: &[u8]) -> Option<&'static str> {
    let starts = |sig: &[u8]| data.len() >= sig.len() && &data[..sig.len()] == sig;
    // PE: "MZ" then a valid e_lfanew pointing at a "PE\0\0" signature.
    if starts(b"MZ") && data.len() >= 0x40 {
        let e_lfanew =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if e_lfanew + 4 <= data.len() && &data[e_lfanew..e_lfanew + 2] == b"PE" {
            return Some("PE");
        }
    }
    if starts(&[0x89, 0x50, 0x4E, 0x47]) {
        Some("PNG")
    } else if starts(b"BM") {
        Some("BMP")
    } else if starts(b"GIF8") {
        Some("GIF")
    } else if starts(&[0x7F, 0x45, 0x4C, 0x46]) {
        Some("ELF")
    } else if starts(b"PK\x03\x04") {
        Some("ZIP")
    } else if starts(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WAVE" {
        Some("WAV")
    } else {
        None
    }
}

/// The index into [`BUILTIN_TEMPLATES`] whose format matches this data.
fn detect_builtin_index(data: &[u8]) -> Option<usize> {
    let name = detect_builtin_name(data)?;
    BUILTIN_TEMPLATES.iter().position(|(n, _)| *n == name)
}

fn recent_file_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".hexed_recent.txt"))
}

type BookmarkStore = std::collections::HashMap<std::path::PathBuf, Vec<(usize, String)>>;

fn bookmarks_file_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".hexed_bookmarks.tsv"))
}

fn load_bookmarks() -> BookmarkStore {
    let mut map = BookmarkStore::new();
    if let Some(s) = bookmarks_file_path().and_then(|p| std::fs::read_to_string(p).ok()) {
        for line in s.lines() {
            let mut parts = line.splitn(3, '\t');
            if let (Some(path), Some(off), Some(name)) = (parts.next(), parts.next(), parts.next())
            {
                if let Ok(o) = off.parse::<usize>() {
                    map.entry(std::path::PathBuf::from(path))
                        .or_default()
                        .push((o, name.to_string()));
                }
            }
        }
    }
    map
}

fn save_bookmarks(map: &BookmarkStore) {
    use std::fmt::Write as _;
    if let Some(p) = bookmarks_file_path() {
        let mut body = String::new();
        for (path, bms) in map {
            for (off, name) in bms {
                let name = name.replace(['\t', '\n'], " ");
                let _ = writeln!(body, "{}\t{}\t{}", path.to_string_lossy(), off, name);
            }
        }
        let _ = std::fs::write(p, body);
    }
}

/// Shorten a path for display by replacing the home dir with `~`.
fn abbrev_home(p: &std::path::Path) -> String {
    let s = p.to_string_lossy();
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy();
        if let Some(rest) = s.strip_prefix(home.as_ref()) {
            return format!("~{rest}");
        }
    }
    s.into_owned()
}

fn load_recent() -> Vec<std::path::PathBuf> {
    recent_file_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| {
            s.lines()
                .filter(|l| !l.trim().is_empty())
                .map(std::path::PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn save_recent(recent: &[std::path::PathBuf]) {
    if let Some(p) = recent_file_path() {
        let body = recent
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write(p, body);
    }
}

fn xor_keys_file_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".hexed_xor_keys.txt"))
}

fn load_xor_keys() -> Vec<String> {
    xor_keys_file_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| {
            s.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.to_string())
                .take(5)
                .collect()
        })
        .unwrap_or_default()
}

fn save_xor_keys(keys: &[String]) {
    if let Some(p) = xor_keys_file_path() {
        let _ = std::fs::write(p, keys.join("\n"));
    }
}

/// Directory where saved YARA templates live (`~/.hexed_yara_templates`).
fn yara_template_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".hexed_yara_templates"))
}

/// List saved YARA templates as (display name, path), sorted by name.
fn list_yara_templates() -> Vec<(String, std::path::PathBuf)> {
    let mut out = Vec::new();
    if let Some(dir) = yara_template_dir() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let is_yar = p.extension().is_some_and(|x| x == "yar" || x == "yara");
                if is_yar {
                    let name = p
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    out.push((name, p));
                }
            }
        }
    }
    out.sort_by_key(|a| a.0.to_lowercase());
    out
}

/// Load every rule in the YARA library (`~/.hexed_yara_templates`) as
/// (file name, source), for auto-scanning opened files.
fn load_yara_rules() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, path) in list_yara_templates() {
        if let Ok(src) = std::fs::read_to_string(&path) {
            out.push((name, src));
        }
    }
    out
}

/// Whether VirusTotal enrichment is enabled (persisted in `~/.hexed_vt_on`).
fn load_vt_enabled() -> bool {
    std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".hexed_vt_on"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn save_vt_enabled(on: bool) {
    if let Some(h) = std::env::var_os("HOME") {
        let p = std::path::PathBuf::from(h).join(".hexed_vt_on");
        let _ = std::fs::write(p, if on { "1" } else { "0" });
    }
}

/// Record a just-used XOR key: move it to the front, dedup, cap at 5.
fn push_xor_key(history: &mut Vec<String>, key: &str) {
    let key = key.trim();
    if key.is_empty() {
        return;
    }
    history.retain(|k| k != key);
    history.insert(0, key.to_string());
    history.truncate(5);
    save_xor_keys(history);
}

impl Default for HexedApp {
    fn default() -> Self {
        Self {
            docs: Vec::new(),
            active: 0,
            last_active: 0,
            grid_focus_stale: false,
            copy_flash_id: "",
            copy_flash_until: 0.0,
            strings_min_len: 4,
            strings_ascii: true,
            strings_utf16: true,
            inspect_endian: Endian::Little,
            goto_query: String::new(),
            replace_query: String::new(),
            bookmark_name: String::new(),
            strings_filter: String::new(),
            yara_source: yara_template(),
            yara_result: None,
            bt_source: BUILTIN_TEMPLATES[0].1.to_string(),
            auto_run_template: true,
            yara_templates: list_yara_templates(),
            yara_rules: load_yara_rules(),
            vt: Vt::new(load_vt_enabled()),
            disasm_bits: 0,
            bytes_per_row: BYTES_PER_ROW,
            view: load_view(),
            insert_count: 1,
            base_width: 4,
            base_edit: String::new(),
            xor_key_history: load_xor_keys(),
            recent: load_recent(),
            bookmarks_store: load_bookmarks(),
            status: "Open a file (Ctrl+O) or drop one onto the window to begin.".to_string(),
            ai: Ai::default(),
            ai_available: Ai::available(),
            show_about: false,
            logo_tex: None,
            ai_last_action: None,
            ai_pending_open: None,
            theme: load_theme(),
            palette: theme::palette(load_theme()),
        }
    }
}

impl HexedApp {
    fn active_doc(&self) -> Option<&Document> {
        self.docs.get(self.active)
    }

    fn open_path(&mut self, path: std::path::PathBuf) {
        match Buffer::from_file(&path) {
            Ok(buf) => {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                self.status = format!("Opened {} ({} bytes)", name, buf.len());
                self.docs.push(Document::new(buf, name));
                self.active = self.docs.len() - 1;
                if let Some(bms) = self.bookmarks_store.get(&path) {
                    if let Some(d) = self.docs.last_mut() {
                        d.bookmarks = bms.clone();
                    }
                }
                self.push_recent(path);
                self.maybe_autorun_template();
            }
            Err(e) => self.status = format!("Open failed: {e}"),
        }
    }

    /// If enabled and the just-opened file's magic matches a built-in template,
    /// load + run it so the results tree and colored spans are ready immediately.
    fn maybe_autorun_template(&mut self) {
        if !self.auto_run_template {
            return;
        }
        let detected = self
            .docs
            .last()
            .and_then(|d| detect_builtin_index(d.buffer.data()));
        let Some(i) = detected else { return };
        let src = BUILTIN_TEMPLATES[i].1;
        let res = self
            .docs
            .last()
            .map(|d| hexed_bt::run(src, d.buffer.data()));
        if let (Some(res), Some(d)) = (res, self.docs.last_mut()) {
            d.bt_spans.clear();
            if let Ok(t) = &res {
                collect_bt_spans(&t.root, &mut d.bt_spans);
            }
            d.bt_result = Some(res);
        }
        self.bt_source = src.to_string();
    }

    /// Run the whole YARA rule library against document `a`'s bytes, caching the
    /// matches (and any compile errors) so the panel can show + jump to them.
    fn rescan_yara_active(&mut self, a: usize) {
        let mut matches = Vec::new();
        let mut errors = Vec::new();
        if let Some(d) = self.docs.get(a) {
            for (name, src) in &self.yara_rules {
                match yara_scan(src, d.buffer.data()) {
                    Ok(hits) => matches.extend(hits.into_iter().map(|h| (name.clone(), h))),
                    Err(e) => errors.push((name.clone(), e)),
                }
            }
        }
        if let Some(d) = self.docs.get_mut(a) {
            d.yara_lib_matches = matches;
            d.yara_lib_errors = errors;
        }
    }

    /// Reload the library from disk and re-scan every open tab (after a rule is
    /// added/removed).
    fn reload_yara_library(&mut self) {
        self.yara_rules = load_yara_rules();
        self.yara_templates = list_yara_templates();
        for i in 0..self.docs.len() {
            self.rescan_yara_active(i);
        }
    }

    fn push_recent(&mut self, path: std::path::PathBuf) {
        // Don't remember scratch/temp files (e.g. UPX output).
        if path.starts_with(std::env::temp_dir()) {
            return;
        }
        self.recent.retain(|p| p != &path);
        self.recent.insert(0, path);
        self.recent.truncate(12);
        save_recent(&self.recent);
    }

    /// Persist the given doc's bookmarks under its file path.
    fn sync_bookmarks(&mut self, i: usize) {
        let entry = self.docs.get(i).and_then(|d| {
            d.buffer
                .path()
                .map(|p| (p.to_path_buf(), d.bookmarks.clone()))
        });
        if let Some((path, bms)) = entry {
            if bms.is_empty() {
                self.bookmarks_store.remove(&path);
            } else {
                self.bookmarks_store.insert(path, bms);
            }
            save_bookmarks(&self.bookmarks_store);
        }
    }

    fn close_doc(&mut self, i: usize) {
        if i >= self.docs.len() {
            return;
        }
        self.docs.remove(i);
        // A remove can slide a different document into `active`'s slot without
        // changing the index, so force a grid-focus drop (see update()).
        self.grid_focus_stale = true;
        if self.active > i {
            self.active -= 1;
        }
        if self.active >= self.docs.len() {
            self.active = self.docs.len().saturating_sub(1);
        }
        // YARA "scan all" results hold absolute doc indices used for click-to-
        // jump; drop the closed doc's group and shift the rest so a later click
        // still lands on the right file instead of a shifted-in one.
        if let Some(groups) = &mut self.yara_result {
            groups.retain(|(di, _, _)| *di != i);
            for (di, _, _) in groups.iter_mut() {
                if *di > i {
                    *di -= 1;
                }
            }
        }
    }
}

impl eframe::App for HexedApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ---- AI worker: drain results; route them on completion ----
        match self.ai.poll() {
            ai::Poll::Running => ctx.request_repaint(),
            ai::Poll::JustDone => self.on_ai_done(),
            ai::Poll::Idle => {}
        }

        // ---- flush + drop editor focus when the active document changed ----
        // The hex grid and the Text-view field both use constant focus ids, so
        // focus would otherwise persist across tab switch / open / close onto a
        // document the user never clicked into. A pointer-driven switch (clicking
        // a tab) blurs them via egui's press-elsewhere rule, but a keyboard one
        // (⌘W / ⌘O) has no such press, so a stray keystroke would silently edit
        // the incoming document. Surrender both here to require a fresh click.
        // `grid_focus_stale` covers closes that swap a new doc into the same
        // index (where the index compare alone would miss it).
        //
        // Crucially, commit the OUTGOING doc's pending text edit first. Dropping
        // focus without committing would leave that doc `text_dirty` yet
        // unfocused — a state where draw_text's `!text_dirty` rebuild gate freezes
        // text_buf at the stale edit while the byte buffer can still move (undo,
        // XOR, block-op, …), so the next commit_text would replace_all the stale
        // text over those bytes and save the wrong file. commit_text only ever
        // writes docs[i].text_buf into docs[i].buffer and no-ops unless that doc
        // is dirty, so committing last_active is safe even when a close has since
        // shifted a different (clean) doc into that slot.
        if self.active != self.last_active || self.grid_focus_stale {
            if self.last_active < self.docs.len() {
                self.commit_text(self.last_active);
            }
            ctx.memory_mut(|m| {
                m.surrender_focus(egui::Id::new(HEX_GRID_ID));
                m.surrender_focus(egui::Id::new(TEXT_EDIT_ID));
            });
            self.last_active = self.active;
            self.grid_focus_stale = false;
        }

        // ---- files opened via Finder "Open With" (macOS 'odoc' events) ----
        for path in openwith::take_pending() {
            self.open_path(path);
        }

        let now = ctx.input(|i| i.time);

        // ---- launch splash (first ~1.6s), drawn on a foreground layer ----
        let splash_t = now as f32;
        if splash_t < 1.6 {
            self.draw_splash(ctx, splash_t);
            ctx.request_repaint();
        }
        // Keep repainting while a "Copied!" flash is active so it reverts.
        if now < self.copy_flash_until {
            ctx.request_repaint();
        }
        let flash = |id: &str| self.copy_flash_id == id && now < self.copy_flash_until;
        let flash_triage = flash("triage");
        let flash_iocs = flash("iocs");
        let flash_pe = flash("pe_report");

        // ---- keyboard shortcuts ----
        let mut action_open = false;
        let mut action_open_recent: Option<std::path::PathBuf> = None;
        let mut action_save = false;
        let mut action_save_as = false;
        let mut action_undo = false;
        let mut action_redo = false;
        let mut action_close = false;
        let mut goto_focus = false;
        let mut action_add_bookmark = false;
        let mut action_select_all = false;
        let mut action_about = false;
        let mut action_set_theme: Option<Theme> = None;
        // Don't hijack ⌘A / shortcuts while a text field (Find, key, …) is focused.
        // The hex grid is also focusable (for byte-editing) but is NOT a text
        // field, so exclude it — otherwise clicking the grid would disable ⌘A.
        let typing = ctx.memory(|m| {
            m.focused()
                .is_some_and(|id| id != egui::Id::new(HEX_GRID_ID))
        });
        ctx.input(|i| {
            if i.modifiers.command {
                if i.key_pressed(egui::Key::O) {
                    action_open = true;
                }
                if i.key_pressed(egui::Key::A) && !typing {
                    action_select_all = true;
                }
                if i.key_pressed(egui::Key::G) {
                    goto_focus = true;
                }
                if i.key_pressed(egui::Key::B) {
                    action_add_bookmark = true;
                }
                if i.key_pressed(egui::Key::S) {
                    action_save = true;
                }
                if i.key_pressed(egui::Key::W) {
                    action_close = true;
                }
                // Don't fire buffer undo/redo while a text field owns focus —
                // the field (e.g. the editable Text view, Find, Goto) runs its
                // OWN undo, and doing both would diverge text_buf from the buffer.
                // (`typing` excludes the hex grid, so Cmd+Z still works there.)
                if i.key_pressed(egui::Key::Z) && !typing {
                    if i.modifiers.shift {
                        action_redo = true;
                    } else {
                        action_undo = true;
                    }
                }
                if i.key_pressed(egui::Key::Y) && !typing {
                    action_redo = true;
                }
            }
        });

        // ---- drag-and-drop opens a new tab ----
        if let Some(path) = ctx.input(|i| i.raw.dropped_files.iter().find_map(|f| f.path.clone())) {
            self.open_path(path);
        }
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let screen = ctx.screen_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop_overlay"),
            ));
            painter.rect_filled(screen, 0.0, Color32::from_black_alpha(160));
            painter.text(
                screen.center(),
                Align2::CENTER_CENTER,
                "Drop file to open",
                FontId::proportional(28.0),
                Color32::WHITE,
            );
        }

        let a = self.active;
        let has_doc = self.docs.get(a).is_some();

        // ---- select all (⌘A) ----
        if action_select_all {
            if let Some(d) = self.docs.get_mut(a) {
                let len = d.buffer.len();
                if len > 0 {
                    d.sel_anchor = Some(0);
                    d.sel_cursor = Some(len - 1);
                }
            }
        }

        // ---- debounce heavy re-analysis while byte-editing ----
        // Byte edits (draw_hex) set derived_ttl instead of strings_dirty so that
        // rapid typing doesn't re-hash + re-scan + re-run YARA over the whole
        // file every keystroke; the rescan fires once, a few frames after the
        // last keystroke. (The text-view cache updates immediately via
        // buffer.generation(); only the expensive analyses are deferred.)
        if let Some(d) = self.docs.get_mut(a) {
            if d.derived_ttl > 0 {
                d.derived_ttl -= 1;
                if d.derived_ttl == 0 {
                    d.strings_dirty = true;
                } else {
                    ctx.request_repaint(); // keep frames coming until it settles
                }
            }
        }

        // ---- rescan strings for the active doc if needed ----
        let mut rebuilt_derived = false;
        if let Some(d) = self.docs.get_mut(a) {
            if d.strings_dirty {
                d.strings = find_strings(
                    d.buffer.data(),
                    self.strings_min_len,
                    self.strings_ascii,
                    self.strings_utf16,
                );
                d.pe = parse_pe(d.buffer.data());
                d.entropy_profile = entropy_profile(d.buffer.data(), 512);
                d.histogram = byte_histogram(d.buffer.data());
                // Triage scans: IOCs, embedded files, crypto signatures.
                d.iocs = extract_iocs(d.buffer.data());
                d.embedded = find_embedded(d.buffer.data());
                d.sig_hits = scan_signatures(d.buffer.data());
                d.api_flags = d.pe.as_ref().map(suspicious_apis).unwrap_or_default();
                d.imphash = d.pe.as_ref().map(imphash).unwrap_or_default();
                d.file_sha256 = sha256_hex(d.buffer.data());
                // Extract the file's embedded icon (largest RT_ICON), if any.
                d.icon_png = None;
                d.icon_dims = (0, 0);
                d.icon_tex = None;
                if d.pe.is_some() {
                    let best = hexed_core::pe::icon_resources(d.buffer.data())
                        .iter()
                        .filter_map(|r| icon_to_png(r))
                        .max_by_key(|(w, h, _, _)| (*w as u64) * (*h as u64));
                    if let Some((w, h, png, rgba)) = best {
                        let ci = egui::ColorImage::from_rgba_unmultiplied(
                            [w as usize, h as usize],
                            &rgba,
                        );
                        d.icon_tex =
                            Some(ctx.load_texture("file_icon", ci, egui::TextureOptions::LINEAR));
                        d.icon_png = Some(png);
                        d.icon_dims = (w, h);
                    }
                }
                d.strings_dirty = false;
                rebuilt_derived = true;
            }
        }
        // Auto-scan the just-(re)built file with the whole YARA rule library,
        // and (if enrichment is on) queue a VirusTotal lookup for its hash.
        if rebuilt_derived {
            self.rescan_yara_active(a);
            // Only look a file up on VirusTotal when it is unmodified. Editing a
            // byte changes the hash to one VT can't know, so a lookup would just
            // burn quota and leak that we're mutating the sample.
            if self.vt.enabled {
                let sha = self
                    .docs
                    .get(a)
                    .filter(|d| !d.buffer.is_dirty())
                    .map(|d| d.file_sha256.clone());
                if let Some(sha) = sha {
                    self.vt.request(&sha);
                }
            }
        }
        // Drain any finished VT lookup.
        if self.vt.poll() {
            ctx.request_repaint();
        }

        let sel = self.active_doc().and_then(|d| d.selection_range());
        let cur = self.active_doc().and_then(|d| d.sel_cursor);
        let sel_entropy = sel.and_then(|(s, e)| {
            self.docs.get(a).map(|d| {
                let cap = (e - s).min(256 * 1024); // cap the live scan
                shannon_entropy(d.buffer.slice(s, s + cap))
            })
        });

        // snapshot editable per-doc fields into locals (widgets edit these; we
        // write them back after the panels so closures never mutate `self`).
        let mut xor_key = self
            .docs
            .get(a)
            .map(|d| d.xor_key.clone())
            .unwrap_or_default();
        let mut search_query = self
            .docs
            .get(a)
            .map(|d| d.search_query.clone())
            .unwrap_or_default();
        let mut search_hex = self.docs.get(a).map(|d| d.search_hex).unwrap_or(false);
        let mut search_ci = self.docs.get(a).map(|d| d.search_ci).unwrap_or(false);
        let search_hits_len = self.docs.get(a).map(|d| d.search_hits.len()).unwrap_or(0);
        let search_idx = self.docs.get(a).map(|d| d.search_idx).unwrap_or(0);
        // snapshot global view prefs
        let mut strings_ascii = self.strings_ascii;
        let mut strings_utf16 = self.strings_utf16;
        let mut strings_min_len = self.strings_min_len;
        let mut inspect_endian = self.inspect_endian;
        let mut base_width = self.base_width;
        let mut base_edit = self.base_edit.clone();
        let mut action_base_write: Option<(usize, Vec<u8>)> = None;
        let mut goto_query = self.goto_query.clone();
        let mut bookmark_name = self.bookmark_name.clone();
        let mut strings_filter = self.strings_filter.clone();
        let mut yara_source = self.yara_source.clone();
        let mut action_yara_scan = false;
        let mut action_yara_scan_all = false;
        let mut action_yara_export = false;
        let mut action_yara_import = false;
        let mut action_yara_new = false;
        let mut action_yara_save_template = false;
        let mut action_yara_reload = false;
        let mut action_yara_add_file = false;
        let mut action_yara_open_dir = false;
        let mut yara_load_template: Option<std::path::PathBuf> = None;
        // Cross-tab jump from a YARA hit: (doc index, offset, len).
        let mut cross_jump: Option<(usize, usize, usize)> = None;
        let mut bt_source = self.bt_source.clone();
        let mut action_bt_run = false;
        let mut action_bt_load = false;
        let mut bt_load_builtin: Option<usize> = None;
        let mut auto_run_template = self.auto_run_template;
        let mut ai_prompt = self.ai.prompt.clone();
        let mut ai_allow_write = self.ai.allow_write;
        let mut ai_action: Option<AiAction> = None;
        let mut disasm_bits = self.disasm_bits;
        let mut bytes_per_row = self.bytes_per_row;
        let mut view_mode = self.view;
        let mut action_compare: Option<usize> = None;
        let mut action_diff_first = false;
        let mut action_diff_next = false;
        let mut action_diff_clear = false;
        let mut insert_count = self.insert_count.max(1);
        let mut action_insert: Option<(usize, usize)> = None;
        let mut action_delete: Option<(usize, usize)> = None;

        // ---- top menu bar ----
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("Open", |ui| {
                    if ui.button("Open file…  (⌘O)").clicked() {
                        action_open = true;
                        ui.close_menu();
                    }
                    if !self.recent.is_empty() {
                        ui.separator();
                        ui.label(egui::RichText::new("Recent").weak());
                        for p in &self.recent {
                            let name = p
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| p.to_string_lossy().into_owned());
                            let mut job = egui::text::LayoutJob::default();
                            job.append(
                                name.as_str(),
                                0.0,
                                egui::TextFormat {
                                    font_id: egui::FontId::proportional(14.0),
                                    color: ui.visuals().text_color(),
                                    ..Default::default()
                                },
                            );
                            job.append(
                                &format!("\n{}", abbrev_home(p)),
                                0.0,
                                egui::TextFormat {
                                    font_id: egui::FontId::proportional(10.0),
                                    color: egui::Color32::from_gray(140),
                                    ..Default::default()
                                },
                            );
                            if ui.button(job).clicked() {
                                action_open_recent = Some(p.clone());
                                ui.close_menu();
                            }
                        }
                    }
                });
                if ui.add_enabled(has_doc, egui::Button::new("Save")).clicked() {
                    action_save = true;
                }
                if ui
                    .add_enabled(has_doc, egui::Button::new("Save As"))
                    .clicked()
                {
                    action_save_as = true;
                }
                ui.separator();
                if ui.add_enabled(has_doc, egui::Button::new("Undo")).clicked() {
                    action_undo = true;
                }
                if ui.add_enabled(has_doc, egui::Button::new("Redo")).clicked() {
                    action_redo = true;
                }
                ui.separator();
                ui.menu_button("Theme", |ui| {
                    for t in Theme::ALL {
                        if ui.selectable_label(self.theme == t, t.name()).clicked() {
                            action_set_theme = Some(t);
                            ui.close_menu();
                        }
                    }
                });
                if ui.button("About").clicked() {
                    action_about = true;
                }
                ui.separator();
                if let Some((s, e)) = sel {
                    ui.label(
                        egui::RichText::new(format!("sel 0x{:X}–0x{:X}  ({} bytes)", s, e, e - s))
                            .monospace(),
                    );
                }
                if let Some(h) = sel_entropy {
                    ui.label(egui::RichText::new(format!("H={h:.2}")).monospace().weak())
                        .on_hover_text(
                            "Shannon entropy of selection (0–8 bits/byte; >7 ≈ packed/encrypted)",
                        );
                }
                // Bytes-per-row selector (right-aligned).
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.selectable_value(&mut bytes_per_row, 0, "Fit")
                        .on_hover_text("fit as many bytes per row as the window allows");
                    ui.selectable_value(&mut bytes_per_row, 32, "32");
                    ui.selectable_value(&mut bytes_per_row, 16, "16");
                    ui.selectable_value(&mut bytes_per_row, 8, "8");
                    ui.label("Row:");
                    ui.separator();
                    ui.selectable_value(&mut view_mode, ViewMode::Text, "Text")
                        .on_hover_text("view the file as text (lines, with a byte-offset gutter)");
                    ui.selectable_value(&mut view_mode, ViewMode::Hex, "Hex")
                        .on_hover_text("view the file as a hex + ASCII grid");
                    ui.label("View:");
                });
            });
        });

        // ---- tab bar ----
        let mut switch_to: Option<usize> = None;
        let mut close_idx: Option<usize> = None;
        if !self.docs.is_empty() {
            egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
                let pal = self.palette;
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        for (i, d) in self.docs.iter().enumerate() {
                            let active = i == a;
                            // Uncommitted text-view edits (text_dirty) count too —
                            // they aren't in the byte buffer yet but are unsaved.
                            let dirty = if d.buffer.is_dirty() || d.text_dirty {
                                " *"
                            } else {
                                ""
                            };
                            let name = format!("{}{}", d.file_name, dirty);
                            // Each tab is a distinct rounded chip: filled when
                            // active, faintly outlined otherwise, so they read
                            // as separate tabs.
                            let frame = egui::Frame::new()
                                .fill(if active { pal.card } else { pal.bg })
                                .stroke(egui::Stroke::new(
                                    1.0,
                                    if active { pal.line } else { pal.line2 },
                                ))
                                .corner_radius(8)
                                .inner_margin(egui::Margin::symmetric(10, 5));
                            let inner = frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let (chip, _) =
                                        ui.allocate_exact_size(vec2(9.0, 9.0), Sense::hover());
                                    ui.painter().rect_filled(
                                        chip,
                                        2.0,
                                        if active { pal.accent } else { pal.faint },
                                    );
                                    let lbl = ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&name).color(if active {
                                                pal.text
                                            } else {
                                                pal.dim
                                            }),
                                        )
                                        .selectable(false)
                                        .sense(Sense::click()),
                                    );
                                    if lbl.clicked() {
                                        switch_to = Some(i);
                                    }
                                    ui.add_space(4.0);
                                    let x = ui.add(
                                        egui::Label::new(
                                            egui::RichText::new("×").color(pal.faint).size(11.0),
                                        )
                                        .selectable(false)
                                        .sense(Sense::click()),
                                    );
                                    if x.on_hover_text("close tab").clicked() {
                                        close_idx = Some(i);
                                    }
                                });
                            });
                            if active {
                                let r = inner.response.rect;
                                ui.painter().hline(
                                    (r.left() + 6.0)..=(r.right() - 6.0),
                                    r.bottom() - 1.0,
                                    egui::Stroke::new(2.0, pal.accent),
                                );
                            }
                            ui.add_space(6.0);
                        }
                    });
                });
            });
        }

        // ---- find bar ----
        let mut action_find = false;
        let mut action_nav: i32 = 0;
        let mut action_goto = false;
        let mut replace_query = self.replace_query.clone();
        let mut action_replace_next = false;
        let mut action_replace_all = false;
        egui::TopBottomPanel::top("find").show(ctx, |ui| {
            ui.add_enabled_ui(has_doc, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Find:");
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut search_query)
                            .desired_width(240.0)
                            .hint_text(if search_hex { "6A ?? 40" } else { "text" }),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        action_find = true;
                    }
                    ui.selectable_value(&mut search_hex, true, "Hex");
                    ui.selectable_value(&mut search_hex, false, "Text");
                    if !search_hex {
                        ui.checkbox(&mut search_ci, "Aa")
                            .on_hover_text("case-insensitive");
                    }
                    if ui.button("Find All").clicked() {
                        action_find = true;
                    }
                    if search_hits_len > 0 {
                        if ui.button("<").clicked() {
                            action_nav = -1;
                        }
                        if ui.button(">").clicked() {
                            action_nav = 1;
                        }
                        ui.label(format!("{}/{}", search_idx + 1, search_hits_len));
                    } else if !search_query.trim().is_empty() {
                        ui.label(egui::RichText::new("no matches").weak());
                    }

                    ui.separator();
                    ui.label("Repl:");
                    ui.add(
                        egui::TextEdit::singleline(&mut replace_query)
                            .desired_width(150.0)
                            .hint_text(if search_hex { "90 90" } else { "text" })
                            .id_salt("replace_field"),
                    );
                    if ui
                        .add_enabled(search_hits_len > 0, egui::Button::new("Replace"))
                        .on_hover_text("replace the current match (equal length)")
                        .clicked()
                    {
                        action_replace_next = true;
                    }
                    if ui
                        .add_enabled(search_hits_len > 0, egui::Button::new("All"))
                        .on_hover_text("replace every match (equal length)")
                        .clicked()
                    {
                        action_replace_all = true;
                    }

                    ui.separator();
                    ui.label("Goto:");
                    let gresp = ui.add(
                        egui::TextEdit::singleline(&mut goto_query)
                            .desired_width(90.0)
                            .hint_text("0x1F")
                            .id_salt("goto_field"),
                    );
                    if goto_focus {
                        gresp.request_focus();
                    }
                    let go_enter =
                        gresp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let go_clicked = ui.button("Go").clicked();
                    if go_enter || go_clicked {
                        action_goto = true;
                    }
                });
            });
        });

        // ---- status bar ----
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&self.status).weak());
            });
        });

        // ---- right side panel: inspector / hashes / strings ----
        let mut jump_to: Option<(usize, usize)> = None;
        let mut action_hash: Option<bool> = None;
        let mut mark_dirty = false;
        let mut remove_bookmark: Option<usize> = None;
        let mut action_upx = false;
        let mut action_pe_report = false;
        let mut export_file_icon = false;
        // triage-panel actions
        let mut action_triage = false;
        let mut carve_embedded: Option<(usize, Option<usize>)> = None;
        let mut copy_iocs: Option<bool> = None; // Some(defang) -> copy all IOCs
        let mut ioc_defang = self.docs.get(a).map(|d| d.ioc_defang).unwrap_or(true);
        let mut vt_enabled = self.vt.enabled;
        let mut vt_open = false;
        let mut vt_icon_check: Option<String> = None; // icon dhash → count on VT
        let mut vt_icon_open: Option<String> = None; // icon dhash → browser search
        egui::SidePanel::right("strings")
            .resizable(true)
            .default_width(340.0)
            .max_width(460.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .id_salt("side_scroll")
                    .show(ui, |ui| {
                ui.add_space(4.0);

                // PE structure navigator (only if this file parses as a PE)
                if let Some(pe) = self.docs.get(a).and_then(|d| d.pe.as_ref()) {
                    egui::CollapsingHeader::new(format!(
                        "PE · {} · {} sections",
                        pe.machine_str(),
                        pe.sections.len()
                    ))
                    .default_open(true)
                    .show(ui, |ui| {
                        // Embedded application icon (from the PE's resources).
                        if let Some(d) = self.docs.get(a) {
                            if let Some(tex) = &d.icon_tex {
                                // VT records a perceptual icon hash; if enrichment
                                // is on and the file is known, we can pivot on it.
                                let icon_dhash = if self.vt.enabled {
                                    self.vt.get(&d.file_sha256).and_then(|v| v.icon_dhash.clone())
                                } else {
                                    None
                                };
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::Image::new(egui::load::SizedTexture::new(
                                            tex.id(),
                                            tex.size_vec2(),
                                        ))
                                        .max_size(vec2(48.0, 48.0)),
                                    );
                                    ui.vertical(|ui| {
                                        ui.monospace(format!(
                                            "icon {}×{}",
                                            d.icon_dims.0, d.icon_dims.1
                                        ));
                                        if ui.small_button("Export icon PNG…").clicked() {
                                            export_file_icon = true;
                                        }
                                        // How many VT files share this icon?
                                        if let Some(dh) = &icon_dhash {
                                            if let Some(m) = self.vt.icon(dh) {
                                                if let Some(e) = &m.error {
                                                    ui.label(egui::RichText::new(e).color(self.palette.warn).size(11.0));
                                                } else if m.count <= 1 {
                                                    ui.label(egui::RichText::new("icon: unique on VT").color(self.palette.ok).size(11.0));
                                                } else {
                                                    let r = ui.add(egui::Label::new(
                                                        egui::RichText::new(format!("icon: {} files share it", m.count))
                                                            .color(self.palette.warn).size(11.0),
                                                    ).sense(Sense::click()));
                                                    if r.on_hover_text("open the VT icon search in your browser").clicked() {
                                                        vt_icon_open = Some(dh.clone());
                                                    }
                                                }
                                            } else if self.vt.icon_pending(dh) {
                                                ui.horizontal(|ui| {
                                                    ui.spinner();
                                                    ui.label(egui::RichText::new("checking icon…").weak().size(11.0));
                                                });
                                            } else if ui
                                                .small_button("Icon on VT")
                                                .on_hover_text("count how many files on VirusTotal share this icon (Intelligence search)")
                                                .clicked()
                                            {
                                                vt_icon_check = Some(dh.clone());
                                            }
                                        }
                                    });
                                });
                                ui.separator();
                            }
                        }
                        ui.monospace(format!("{} · {}", pe.language(), pe.compiler_str()));
                        ui.monospace(format!("compiled: {}", pe.timestamp_str()));
                        if pe.is_packed() {
                            let txt = match &pe.packer {
                                Some(p) => format!("PACKED: {p}"),
                                None => "likely packed (high entropy)".to_string(),
                            };
                            ui.colored_label(Color32::from_rgb(230, 120, 90), txt);
                            if pe.packer.as_deref() == Some("UPX")
                                && ui
                                    .button("Unpack (upx -d)")
                                    .on_hover_text("decompress with the upx CLI into a new tab")
                                    .clicked()
                            {
                                action_upx = true;
                            }
                        }
                        if ui
                            .button(if flash_pe { "Copied!" } else { "Copy PE report" })
                            .on_hover_text("copy a paste-ready summary (hashes, sections, imports…) to the clipboard")
                            .clicked()
                        {
                            action_pe_report = true;
                        }
                        // suspicious imports, grouped by capability
                        let flags: Vec<ApiFlag> =
                            self.docs.get(a).map(|d| d.api_flags.clone()).unwrap_or_default();
                        if !flags.is_empty() {
                            egui::CollapsingHeader::new(format!("Flagged APIs ({})", flags.len()))
                                .id_salt("flagged_apis")
                                .default_open(true)
                                .show(ui, |ui| {
                                    let mut cats: Vec<&str> =
                                        flags.iter().map(|f| f.category).collect();
                                    cats.sort_unstable();
                                    cats.dedup();
                                    for cat in cats {
                                        ui.label(
                                            egui::RichText::new(cat)
                                                .color(self.palette.warn)
                                                .size(11.0),
                                        );
                                        for f in flags.iter().filter(|f| f.category == cat) {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "  {} — {}",
                                                    f.api, f.note
                                                ))
                                                .monospace()
                                                .size(11.0),
                                            )
                                            .on_hover_text(&f.dll);
                                        }
                                    }
                                });
                        }
                        ui.separator();
                        ui.horizontal_wrapped(|ui| {
                            if ui.small_button("MZ @ 0").clicked() {
                                jump_to = Some((0, 2));
                            }
                            if ui.small_button(format!("PE @ 0x{:X}", pe.nt_offset)).clicked() {
                                jump_to = Some((pe.nt_offset, 4));
                            }
                            if let Some(ep) = pe.entry_offset() {
                                if ui.small_button(format!("Entry @ 0x{ep:X}")).clicked() {
                                    jump_to = Some((ep, 1));
                                }
                            }
                        });
                        egui::Grid::new("pe_sections")
                            .num_columns(4)
                            .striped(true)
                            .show(ui, |ui| {
                                for s in &pe.sections {
                                    let hover = format!(
                                        "{} · VA 0x{:X} · raw 0x{:X} · size 0x{:X} · entropy {:.2}",
                                        s.perms(),
                                        s.virtual_addr,
                                        s.raw_ptr,
                                        s.raw_size,
                                        s.entropy
                                    );
                                    if ui.button(s.name.as_str()).on_hover_text(hover).clicked() {
                                        jump_to = Some((s.raw_ptr as usize, 1));
                                    }
                                    ui.monospace(format!("0x{:X}", s.raw_ptr));
                                    ui.monospace(s.perms());
                                    let etxt = format!("H{:.1}", s.entropy);
                                    if s.entropy > 7.0 {
                                        ui.colored_label(Color32::from_rgb(220, 140, 90), etxt)
                                            .on_hover_text("high entropy — likely packed/encrypted");
                                    } else {
                                        ui.monospace(etxt);
                                    }
                                    ui.end_row();
                                }
                            });

                        // imports: DLL -> functions
                        if !pe.imports.is_empty() {
                            ui.separator();
                            let total: usize = pe.imports.iter().map(|i| i.funcs.len()).sum();
                            ui.label(format!(
                                "Imports: {} DLLs, {} functions",
                                pe.imports.len(),
                                total
                            ));
                            egui::ScrollArea::vertical()
                                .id_salt("pe_imports")
                                .max_height(220.0)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    for (i, imp) in pe.imports.iter().enumerate() {
                                        let name = if imp.dll.is_empty() {
                                            "<no name>"
                                        } else {
                                            imp.dll.as_str()
                                        };
                                        egui::CollapsingHeader::new(format!(
                                            "{}  ({})",
                                            name,
                                            imp.funcs.len()
                                        ))
                                        .id_salt(("imp", i))
                                        .show(ui, |ui| {
                                            for f in &imp.funcs {
                                                ui.monospace(f);
                                            }
                                        });
                                    }
                                });
                        }

                        // exports (this DLL's own functions) — click to jump
                        if !pe.exports.is_empty() {
                            ui.separator();
                            ui.label(format!("Exports: {}", pe.exports.len()));
                            egui::ScrollArea::vertical()
                                .id_salt("pe_exports")
                                .max_height(200.0)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    for ex in &pe.exports {
                                        let off = pe.rva_to_offset(ex.rva);
                                        let btn = ui.add_enabled(
                                            off.is_some(),
                                            egui::Button::new(format!("{}  (#{})", ex.name, ex.ordinal))
                                                .small(),
                                        );
                                        if btn.clicked() {
                                            if let Some(o) = off {
                                                jump_to = Some((o, 1));
                                            }
                                        }
                                    }
                                });
                        }
                    });
                    ui.separator();
                }

                // hashes (on demand)
                egui::CollapsingHeader::new("Hashes")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if ui.add_enabled(has_doc, egui::Button::new("Hash selection")).clicked() {
                                action_hash = Some(false);
                            }
                            if ui.add_enabled(has_doc, egui::Button::new("Hash file")).clicked() {
                                action_hash = Some(true);
                            }
                            let tri_label = if flash_triage { "Copied!" } else { "Triage report" };
                            let tri_fill = if flash_triage { self.palette.ok } else { self.palette.accent };
                            if ui
                                .add_enabled(
                                    has_doc,
                                    egui::Button::new(
                                        egui::RichText::new(tri_label).color(self.palette.accent_ink),
                                    )
                                    .fill(tri_fill),
                                )
                                .on_hover_text("copy a full Markdown triage report to the clipboard")
                                .clicked()
                            {
                                action_triage = true;
                            }
                        });
                        let imph = self.docs.get(a).map(|d| d.imphash.clone()).unwrap_or_default();
                        if !imph.is_empty() {
                            egui::Grid::new("imphash_grid").num_columns(3).show(ui, |ui| {
                                hash_row(ui, "imphash", &imph);
                            });
                        }
                        if let Some((label, h)) = self.docs.get(a).and_then(|d| d.hashes.as_ref()) {
                            ui.label(egui::RichText::new(label).weak());
                            egui::Grid::new("hash_grid").num_columns(3).show(ui, |ui| {
                                hash_row(ui, "CRC16", &format!("{:04X}", h.crc16));
                                hash_row(ui, "CRC32", &format!("{:08X}", h.crc32));
                                hash_row(ui, "Adler32", &format!("{:08X}", h.adler32));
                                hash_row(ui, "MD5", &h.md5);
                                hash_row(ui, "SHA-1", &h.sha1);
                                hash_row(ui, "SHA-256", &h.sha256);
                            });
                        }
                    });
                ui.separator();

                // AI assistant (codex)
                egui::CollapsingHeader::new("AI assistant")
                    .default_open(false)
                    .show(ui, |ui| {
                        if !self.ai_available {
                            ui.colored_label(
                                Color32::from_rgb(210, 160, 90),
                                "codex CLI not found — install it and run `codex login`.",
                            );
                        }
                        ui.add_enabled_ui(self.ai_available && !self.ai.running, |ui| {
                            let sel_some = sel.is_some();
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .add_enabled(sel_some, egui::Button::new("Explain sel"))
                                    .on_hover_text("what are the selected bytes?")
                                    .clicked()
                                {
                                    ai_action = Some(AiAction::Explain);
                                }
                                if ui
                                    .add_enabled(sel_some, egui::Button::new("Decode sel"))
                                    .on_hover_text("identify the cipher, decode -> new tab (writes files)")
                                    .clicked()
                                {
                                    ai_action = Some(AiAction::Decode);
                                }
                                if ui
                                    .add_enabled(sel_some, egui::Button::new("Explain asm"))
                                    .on_hover_text("explain the selected disassembly")
                                    .clicked()
                                {
                                    ai_action = Some(AiAction::Disasm);
                                }
                            });
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .add_enabled(has_doc, egui::Button::new("Gen YARA"))
                                    .on_hover_text("AI-write a YARA rule -> YARA panel")
                                    .clicked()
                                {
                                    ai_action = Some(AiAction::Yara);
                                }
                                if ui
                                    .add_enabled(has_doc, egui::Button::new("Triage"))
                                    .on_hover_text("family/capabilities/ATT&CK/IOCs")
                                    .clicked()
                                {
                                    ai_action = Some(AiAction::Triage);
                                }
                                if ui
                                    .add_enabled(has_doc, egui::Button::new("Gen .bt"))
                                    .on_hover_text("AI-write a .bt template -> Templates panel")
                                    .clicked()
                                {
                                    ai_action = Some(AiAction::Bt);
                                }
                            });
                            ui.checkbox(&mut ai_allow_write, "allow write (files)")
                                .on_hover_text("needed for Decode; off = read-only sandbox");
                            ui.add(
                                egui::TextEdit::multiline(&mut ai_prompt)
                                    .desired_rows(2)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("ask anything… (codex can read the file & run tools)"),
                            );
                            if ui
                                .add_enabled(
                                    !ai_prompt.trim().is_empty(),
                                    egui::Button::new(
                                        egui::RichText::new("Ask").color(self.palette.accent_ink),
                                    )
                                    .fill(self.palette.accent),
                                )
                                .clicked()
                            {
                                ai_action = Some(AiAction::Ask);
                            }
                        });
                        if self.ai.running {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(format!("codex: {}…", self.ai.label));
                            });
                        }
                        if !self.ai.output.is_empty() {
                            ui.separator();
                            egui::ScrollArea::vertical()
                                .id_salt("ai_out")
                                .max_height(260.0)
                                .show(ui, |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&self.ai.output).monospace(),
                                        )
                                        .wrap(),
                                    );
                                });
                            if ui.small_button("Copy answer").clicked() {
                                ui.ctx().copy_text(self.ai.output.clone());
                            }
                        }
                    });
                ui.separator();

                // VirusTotal — opt-in hash reputation (by-hash only, never uploads)
                let vt_sha = self.docs.get(a).map(|d| d.file_sha256.clone()).unwrap_or_default();
                let vt_verdict = self.vt.get(&vt_sha).cloned();
                let vt_pending = self.vt.is_pending(&vt_sha);
                let vt_header = match &vt_verdict {
                    Some(v) if v.error.is_none() && !v.not_found && v.total > 0 => {
                        format!("VirusTotal · {}/{}", v.malicious + v.suspicious, v.total)
                    }
                    _ => "VirusTotal".to_string(),
                };
                egui::CollapsingHeader::new(vt_header)
                    .id_salt("vt_panel")
                    .default_open(vt_verdict.is_some())
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut vt_enabled, "Enrichment").on_hover_text(
                                "look up the file's SHA-256 on VirusTotal (by hash only — never uploads the sample)",
                            );
                            if ui
                                .add_enabled(!vt_sha.is_empty(), egui::Button::new("Open in VT"))
                                .on_hover_text("open this file's VirusTotal page in your browser")
                                .clicked()
                            {
                                vt_open = true;
                            }
                        });
                        if !self.vt.has_key() {
                            ui.label(
                                egui::RichText::new("No API key — put your VT key in ~/.hexed_vt_key")
                                    .color(self.palette.warn).size(11.0),
                            );
                        } else if !vt_enabled {
                            ui.label(egui::RichText::new("Enrichment off — no lookups are sent.").weak().size(11.0));
                        } else if let Some(v) = &vt_verdict {
                            if let Some(e) = &v.error {
                                ui.label(egui::RichText::new(e).color(self.palette.warn));
                            } else if v.not_found {
                                ui.label(egui::RichText::new("Not seen on VirusTotal").color(self.palette.dim));
                            } else {
                                let detected = v.malicious + v.suspicious;
                                let col = if v.malicious > 0 {
                                    self.palette.crit
                                } else if detected > 0 {
                                    self.palette.warn
                                } else {
                                    self.palette.ok
                                };
                                ui.label(
                                    egui::RichText::new(format!("{detected} / {} engines detected", v.total))
                                        .color(col).strong(),
                                );
                                if let Some(l) = &v.label {
                                    ui.label(egui::RichText::new(l).color(self.palette.dim).monospace().size(11.0));
                                }
                                if let Some(f) = &v.first_seen {
                                    ui.label(egui::RichText::new(format!("first seen {f}")).weak().size(11.0));
                                }
                            }
                        } else if vt_pending {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(egui::RichText::new("looking up…").weak());
                            });
                        }
                    });
                ui.separator();

                // IOCs — extracted network / host indicators
                let ioc_count = self.docs.get(a).map(|d| d.iocs.len()).unwrap_or(0);
                egui::CollapsingHeader::new(format!("IOCs ({ioc_count})"))
                    .id_salt("iocs_panel")
                    .default_open(ioc_count > 0)
                    .show(ui, |ui| {
                        if ioc_count == 0 {
                            ui.weak("No indicators found.");
                        } else {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut ioc_defang, "defang")
                                    .on_hover_text("render safe (hxxp://, 1[.]2[.]3[.]4)");
                                let ioc_label = if flash_iocs { "Copied!" } else { "Copy all" };
                                if ui.button(ioc_label).clicked() {
                                    copy_iocs = Some(ioc_defang);
                                }
                            });
                            if let Some(d) = self.docs.get(a) {
                                for kind in IOC_KINDS {
                                    let group: Vec<&Ioc> =
                                        d.iocs.iter().filter(|i| i.kind == *kind).collect();
                                    if group.is_empty() {
                                        continue;
                                    }
                                    ui.add_space(2.0);
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{} ({})",
                                            kind.label(),
                                            group.len()
                                        ))
                                        .color(self.palette.dim)
                                        .size(11.0),
                                    );
                                    for ioc in group.iter().take(300) {
                                        let shown = if ioc_defang {
                                            defang(&ioc.value)
                                        } else {
                                            ioc.value.clone()
                                        };
                                        let resp = ui.add(
                                            egui::Label::new(egui::RichText::new(&shown).monospace())
                                                .sense(Sense::click())
                                                .truncate(),
                                        );
                                        if resp
                                            .on_hover_text(format!("0x{:X} — click to jump", ioc.offset))
                                            .clicked()
                                        {
                                            jump_to = Some((ioc.offset, ioc.byte_len));
                                        }
                                    }
                                }
                            }
                        }
                    });
                ui.separator();

                // Embedded files found by magic-signature scan
                let emb_count = self.docs.get(a).map(|d| d.embedded.len()).unwrap_or(0);
                egui::CollapsingHeader::new(format!("Embedded files ({emb_count})"))
                    .id_salt("embedded_panel")
                    .default_open(emb_count > 1)
                    .show(ui, |ui| {
                        if emb_count == 0 {
                            ui.weak("No embedded signatures found.");
                        } else if let Some(d) = self.docs.get(a) {
                            for e in d.embedded.iter().take(300) {
                                ui.horizontal(|ui| {
                                    let size_txt = e
                                        .size
                                        .map(|s| format!(" · {s} B"))
                                        .unwrap_or_default();
                                    let label = format!("{:08X}  {}{}", e.offset, e.kind, size_txt);
                                    let resp = ui.add(
                                        egui::Label::new(egui::RichText::new(label).monospace())
                                            .sense(Sense::click())
                                            .truncate(),
                                    );
                                    if resp.on_hover_text("click to jump").clicked() {
                                        jump_to = Some((e.offset, 1));
                                    }
                                    if ui
                                        .small_button("extract")
                                        .on_hover_text("carve this file into a new tab")
                                        .clicked()
                                    {
                                        carve_embedded = Some((e.offset, e.size));
                                    }
                                });
                            }
                        }
                    });
                ui.separator();

                // Crypto-constant / packer signatures
                let sig_count = self.docs.get(a).map(|d| d.sig_hits.len()).unwrap_or(0);
                egui::CollapsingHeader::new(format!("Signatures ({sig_count})"))
                    .id_salt("signatures_panel")
                    .default_open(sig_count > 0)
                    .show(ui, |ui| {
                        if sig_count == 0 {
                            ui.weak("No known crypto constants or packer markers.");
                        } else if let Some(d) = self.docs.get(a) {
                            for h in d.sig_hits.iter().take(300) {
                                let resp = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("{:08X}  {}", h.offset, h.name))
                                            .monospace(),
                                    )
                                    .sense(Sense::click())
                                    .truncate(),
                                );
                                if resp.on_hover_text(h.note).clicked() {
                                    jump_to = Some((h.offset, 1));
                                }
                            }
                        }
                    });
                ui.separator();

                // YARA — auto-scan library matches, then the rule editor
                let lib_hits = self.docs.get(a).map(|d| d.yara_lib_matches.len()).unwrap_or(0);
                let yara_header = if lib_hits > 0 {
                    format!("YARA · {lib_hits} matched")
                } else {
                    "YARA".to_string()
                };
                egui::CollapsingHeader::new(yara_header)
                    .id_salt("yara_panel")
                    .default_open(lib_hits > 0)
                    .show(ui, |ui| {
                        // ---- rule library: auto-scan results for the active file ----
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "Library: {} rule{} · {lib_hits} matched",
                                    self.yara_rules.len(),
                                    if self.yara_rules.len() == 1 { "" } else { "s" }
                                ))
                                .color(self.palette.dim)
                                .size(11.0),
                            );
                            if ui.small_button("Add…").on_hover_text("add a .yar file to the auto-scan library").clicked() {
                                action_yara_add_file = true;
                            }
                            if ui.small_button("Reload").on_hover_text("reload the library and re-scan open tabs").clicked() {
                                action_yara_reload = true;
                            }
                            if ui.small_button("Folder").on_hover_text("open the rule library folder").clicked() {
                                action_yara_open_dir = true;
                            }
                        });
                        if self.yara_rules.is_empty() {
                            ui.label(
                                egui::RichText::new("No rules yet — write one below and \"Save to library\" to auto-scan every file you open.")
                                    .weak().size(11.0),
                            );
                        }
                        if let Some(d) = self.docs.get(a) {
                            for (file, m) in &d.yara_lib_matches {
                                let n = m.locations.len();
                                ui.label(
                                    egui::RichText::new(format!("{}  ({file})  {n} hit{}", m.rule, if n == 1 { "" } else { "s" }))
                                        .color(self.palette.ok),
                                );
                                ui.horizontal_wrapped(|ui| {
                                    for &(off, len) in m.locations.iter().take(40) {
                                        if ui
                                            .small_button(format!("0x{off:X}"))
                                            .on_hover_text("select the matched bytes in the hex view")
                                            .clicked()
                                        {
                                            jump_to = Some((off, len.max(1)));
                                        }
                                    }
                                });
                            }
                            for (file, err) in &d.yara_lib_errors {
                                ui.label(
                                    egui::RichText::new(format!("{file}: {err}"))
                                        .color(self.palette.warn).size(11.0),
                                )
                                .on_hover_text("this library rule failed to compile");
                            }
                        }
                        ui.separator();
                        ui.add(
                            egui::TextEdit::multiline(&mut yara_source)
                                .code_editor()
                                .desired_rows(5)
                                .desired_width(f32::INFINITY),
                        );
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add_enabled(has_doc, egui::Button::new("Scan buffer"))
                                .on_hover_text("scan the active tab's bytes with this rule")
                                .clicked()
                            {
                                action_yara_scan = true;
                            }
                            if ui
                                .add_enabled(self.docs.len() > 1, egui::Button::new("Scan all tabs"))
                                .on_hover_text("run this rule against every open file")
                                .clicked()
                            {
                                action_yara_scan_all = true;
                            }
                            if ui
                                .button("Export…")
                                .on_hover_text("save this rule to a .yar file")
                                .clicked()
                            {
                                action_yara_export = true;
                            }
                            ui.menu_button("Templates ▾", |ui| {
                                if ui.button("New (scaffold)").clicked() {
                                    action_yara_new = true;
                                    ui.close_menu();
                                }
                                if ui
                                    .button("Save to library…")
                                    .on_hover_text("save this rule to the library so it auto-scans every file you open")
                                    .clicked()
                                {
                                    action_yara_save_template = true;
                                    ui.close_menu();
                                }
                                if ui.button("Import from file…").clicked() {
                                    action_yara_import = true;
                                    ui.close_menu();
                                }
                                if !self.yara_templates.is_empty() {
                                    ui.separator();
                                    ui.label(egui::RichText::new("saved templates").weak().small());
                                    for (name, path) in &self.yara_templates {
                                        if ui.button(name).clicked() {
                                            yara_load_template = Some(path.clone());
                                            ui.close_menu();
                                        }
                                    }
                                }
                            });
                        });
                        // Per-tab results; clicking an offset switches to that tab.
                        if let Some(groups) = &self.yara_result {
                            let multi = groups.len() > 1;
                            for (di, fname, res) in groups {
                                if multi {
                                    ui.label(egui::RichText::new(fname).strong().small());
                                }
                                match res {
                                    Ok(matches) if matches.is_empty() => {
                                        ui.label(egui::RichText::new("  no matches").weak());
                                    }
                                    Ok(matches) => {
                                        for m in matches {
                                            let n = m.locations.len();
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "✓ {}  ({n} hit{})",
                                                    m.rule,
                                                    if n == 1 { "" } else { "s" }
                                                ))
                                                .color(self.palette.ok),
                                            );
                                            ui.horizontal_wrapped(|ui| {
                                                for &(off, len) in m.locations.iter().take(30) {
                                                    if ui
                                                        .small_button(format!("0x{off:X}"))
                                                        .clicked()
                                                    {
                                                        cross_jump = Some((*di, off, len));
                                                    }
                                                }
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        ui.colored_label(Color32::from_rgb(230, 120, 90), e);
                                    }
                                }
                            }
                        }
                    });
                ui.separator();

                // strings
                egui::CollapsingHeader::new("Strings")
                    .default_open(true)
                    .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut strings_ascii, "ASCII").changed() {
                        mark_dirty = true;
                    }
                    if ui.checkbox(&mut strings_utf16, "UTF-16").changed() {
                        mark_dirty = true;
                    }
                    ui.label("min");
                    if ui
                        .add(egui::DragValue::new(&mut strings_min_len).range(2..=64))
                        .changed()
                    {
                        mark_dirty = true;
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("filter:");
                    ui.add(
                        egui::TextEdit::singleline(&mut strings_filter)
                            .desired_width(170.0)
                            .hint_text("substring"),
                    );
                    if !strings_filter.is_empty() && ui.small_button("×").clicked() {
                        strings_filter.clear();
                    }
                });
                let total = self.docs.get(a).map(|d| d.strings.len()).unwrap_or(0);
                let filt = strings_filter.to_ascii_lowercase();
                let mut shown = 0usize;
                let mut truncated = false;
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("strings_scroll")
                    .max_height(340.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if let Some(d) = self.docs.get(a) {
                            for s in &d.strings {
                                if !filt.is_empty() && !s.text.to_ascii_lowercase().contains(&filt) {
                                    continue;
                                }
                                if shown >= 3000 {
                                    truncated = true;
                                    break;
                                }
                                shown += 1;
                                let tag = match s.kind {
                                    StringKind::Ascii => "A",
                                    StringKind::Utf16Le => "W",
                                };
                                let line = format!("{:08X} {} {}", s.offset, tag, s.text);
                                let resp = ui.add(
                                    egui::Label::new(egui::RichText::new(line).monospace())
                                        .sense(Sense::click())
                                        .truncate(),
                                );
                                if resp.clicked() {
                                    jump_to = Some((s.offset, s.len));
                                }
                            }
                        }
                    });
                let count_txt = if filt.is_empty() {
                    if truncated {
                        format!("{total} strings (showing first {shown})")
                    } else {
                        format!("{total} strings")
                    }
                } else {
                    format!("{shown} shown / {total}{}", if truncated { " (capped)" } else { "" })
                };
                ui.label(egui::RichText::new(count_txt).weak());
                });
                ui.separator();

                // Byte-frequency histogram (over the selection, else whole file)
                egui::CollapsingHeader::new("Byte histogram")
                    .default_open(false)
                    .show(ui, |ui| {
                        if let Some(d) = self.docs.get(a) {
                            let (hist, scope) = match d.selection_range() {
                                Some((s, e)) if e > s => {
                                    let cap = (e - s).min(8 * 1024 * 1024);
                                    (
                                        byte_histogram(d.buffer.slice(s, s + cap)),
                                        format!("selection · {} bytes", e - s),
                                    )
                                }
                                _ => (
                                    d.histogram.clone(),
                                    format!("whole file · {} bytes", d.buffer.len()),
                                ),
                            };
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} · {} distinct values",
                                    scope,
                                    hist.distinct()
                                ))
                                .weak(),
                            );
                            draw_histogram(ui, &hist, &self.palette);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new("top:").weak());
                                for (v, _c) in hist.top(8) {
                                    let pct = hist.fraction(v) * 100.0;
                                    ui.label(
                                        egui::RichText::new(format!("{v:02X}={pct:.1}%"))
                                            .monospace()
                                            .color(byte_color(v, &self.palette)),
                                    );
                                }
                            });
                        }
                    });
                ui.separator();

                // x86/x64 disassembly of the selection (or a window from cursor)
                egui::CollapsingHeader::new("Disassembly (x86)")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Mode:");
                            ui.selectable_value(&mut disasm_bits, 0u32, "Auto");
                            ui.selectable_value(&mut disasm_bits, 16u32, "16");
                            ui.selectable_value(&mut disasm_bits, 32u32, "32");
                            ui.selectable_value(&mut disasm_bits, 64u32, "64");
                        });
                        if let Some(d) = self.docs.get(a) {
                            let data = d.buffer.data();
                            let (start, end) = match d.selection_range() {
                                Some((s, e)) if e > s => (s, e.min(s + 4096)),
                                _ => {
                                    let c = d.sel_cursor.unwrap_or(0);
                                    (c, (c + 256).min(data.len()))
                                }
                            };
                            let bits = if disasm_bits != 0 {
                                disasm_bits
                            } else if d.pe.as_ref().is_some_and(|p| p.is_64) {
                                64
                            } else {
                                32
                            };
                            if start < data.len() && start < end {
                                let slice = &data[start..end.min(data.len())];
                                let insns = disassemble(slice, bits, start as u64, 512);
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}-bit · {} bytes @ 0x{:X} · {} insns",
                                        bits,
                                        slice.len(),
                                        start,
                                        insns.len()
                                    ))
                                    .weak(),
                                );
                                egui::ScrollArea::vertical()
                                    .id_salt("disasm_scroll")
                                    .max_height(280.0)
                                    .show(ui, |ui| {
                                        for insn in &insns {
                                            let mnem = if insn.invalid {
                                                "(bad)".to_string()
                                            } else {
                                                insn.text.clone()
                                            };
                                            let row = format!(
                                                "{:08X}  {:<21}  {}",
                                                insn.address,
                                                insn.bytes_hex(),
                                                mnem
                                            );
                                            let color = if insn.invalid {
                                                Color32::from_rgb(200, 120, 120)
                                            } else {
                                                ui.visuals().text_color()
                                            };
                                            if ui
                                                .add(
                                                    egui::Label::new(
                                                        egui::RichText::new(row)
                                                            .monospace()
                                                            .color(color),
                                                    )
                                                    .sense(Sense::click())
                                                    .wrap_mode(egui::TextWrapMode::Extend),
                                                )
                                                .clicked()
                                            {
                                                jump_to = Some((start + insn.offset, insn.len.max(1)));
                                            }
                                        }
                                    });
                            } else {
                                ui.weak("Select code (or place the cursor) to disassemble.");
                            }
                        }
                    });
                ui.separator();

                // .bt binary-template engine
                egui::CollapsingHeader::new("Templates (.bt)")
                    .default_open(false)
                    .show(ui, |ui| {
                        if let Some(i) =
                            self.docs.get(a).and_then(|d| detect_builtin_index(d.buffer.data()))
                        {
                            let name = BUILTIN_TEMPLATES[i].0;
                            if ui
                                .add(egui::Button::new(
                                    egui::RichText::new(format!("Auto: {name} — load & run"))
                                        .strong(),
                                ))
                                .on_hover_text("this file's magic bytes match a built-in template")
                                .clicked()
                            {
                                bt_load_builtin = Some(i);
                                action_bt_run = true;
                            }
                        }
                        ui.checkbox(&mut auto_run_template, "auto-run on open")
                            .on_hover_text("run the matching template automatically when a file is opened");
                        ui.horizontal_wrapped(|ui| {
                            ui.label("Load:");
                            for (i, (name, _)) in BUILTIN_TEMPLATES.iter().enumerate() {
                                if ui.small_button(*name).clicked() {
                                    bt_load_builtin = Some(i);
                                }
                            }
                            if ui
                                .small_button("File…")
                                .on_hover_text("load a .bt template file")
                                .clicked()
                            {
                                action_bt_load = true;
                            }
                        });
                        egui::ScrollArea::vertical()
                            .id_salt("bt_src")
                            .max_height(150.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut bt_source)
                                        .code_editor()
                                        .desired_rows(6)
                                        .desired_width(f32::INFINITY),
                                );
                            });
                        if ui
                            .add_enabled(
                                has_doc,
                                egui::Button::new(
                                    egui::RichText::new("Run template")
                                        .color(self.palette.accent_ink),
                                )
                                .fill(self.palette.accent),
                            )
                            .on_hover_text("execute the template against this file")
                            .clicked()
                        {
                            action_bt_run = true;
                        }
                        if let Some(d) = self.docs.get(a) {
                            match &d.bt_result {
                                Some(Ok(t)) => {
                                    ui.separator();
                                    if !t.log.is_empty() {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(t.log.trim_end()).monospace().weak(),
                                            )
                                            .wrap(),
                                        );
                                    }
                                    if t.root.is_empty() {
                                        ui.weak("(template produced no fields)");
                                    } else {
                                        for node in &t.root {
                                            show_bt_node(ui, node, &mut jump_to);
                                        }
                                    }
                                    ui.weak(format!("mapped {} bytes", t.end_pos));
                                }
                                Some(Err(e)) => {
                                    ui.colored_label(Color32::from_rgb(230, 120, 90), e);
                                }
                                None => {
                                    ui.weak("Pick a template and Run to map the file.");
                                }
                            }
                        }
                    });
                ui.separator();

                // Binary compare / diff against another open tab
                egui::CollapsingHeader::new("Compare / diff")
                    .default_open(false)
                    .show(ui, |ui| {
                        if self.docs.len() < 2 {
                            ui.weak("Open a second file (tab) to compare against.");
                        } else {
                            ui.label("Diff this file against:");
                            for (i, d) in self.docs.iter().enumerate() {
                                if i == a {
                                    continue;
                                }
                                if ui
                                    .button(format!("vs  {}", d.file_name))
                                    .on_hover_text("aligned byte-for-byte comparison")
                                    .clicked()
                                {
                                    action_compare = Some(i);
                                }
                            }
                            if let Some(d) = self.docs.get(a) {
                                if let Some(sum) = &d.diff_summary {
                                    ui.separator();
                                    ui.label(egui::RichText::new(sum).monospace());
                                    if !d.diff_ranges.is_empty() {
                                        ui.horizontal(|ui| {
                                            if ui.button("First").clicked() {
                                                action_diff_first = true;
                                            }
                                            if ui.button("Next").clicked() {
                                                action_diff_next = true;
                                            }
                                            ui.weak(format!(
                                                "{}/{}",
                                                (d.diff_idx + 1).min(d.diff_ranges.len()),
                                                d.diff_ranges.len()
                                            ));
                                        });
                                    }
                                    if ui.button("Clear diff").clicked() {
                                        action_diff_clear = true;
                                    }
                                }
                            }
                        }
                    });
                ui.separator();

                // bookmarks
                egui::CollapsingHeader::new("Bookmarks")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut bookmark_name)
                                    .desired_width(140.0)
                                    .hint_text("name (optional)"),
                            );
                            if ui
                                .add_enabled(cur.is_some(), egui::Button::new("+ @ cursor"))
                                .on_hover_text("bookmark the caret (⌘B)")
                                .clicked()
                            {
                                action_add_bookmark = true;
                            }
                        });
                        if let Some(d) = self.docs.get(a) {
                            for (i, (off, name)) in d.bookmarks.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    if ui.small_button("×").clicked() {
                                        remove_bookmark = Some(i);
                                    }
                                    let resp = ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(format!("{off:08X}  {name}"))
                                                .monospace(),
                                        )
                                        .sense(Sense::click())
                                        .truncate(),
                                    );
                                    if resp.clicked() {
                                        jump_to = Some((*off, 1));
                                    }
                                });
                            }
                        }
                    });
                ui.separator();

                // data inspector (follows the caret)
                egui::CollapsingHeader::new("Inspector")
                    .default_open(true)
                    .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut inspect_endian, Endian::Little, "LE");
                    ui.selectable_value(&mut inspect_endian, Endian::Big, "BE");
                });
                match cur {
                    Some(c) if has_doc => {
                        ui.monospace(format!("@ 0x{c:X}  ({c})"));
                        let interps = self
                            .docs
                            .get(a)
                            .map(|d| inspect(d.buffer.data(), c, inspect_endian))
                            .unwrap_or_default();
                        egui::Grid::new("inspector_grid")
                            .num_columns(2)
                            .striped(true)
                            .show(ui, |ui| {
                                for it in interps {
                                    ui.monospace(it.label);
                                    let swatch = matches!(it.label, "RGB" | "RGBA")
                                        .then(|| parse_color_hex(&it.value))
                                        .flatten();
                                    match swatch {
                                        Some(color) => {
                                            ui.horizontal(|ui| {
                                                ui.add(egui::Label::new(
                                                    egui::RichText::new(&it.value).monospace(),
                                                ));
                                                let (rect, _) = ui.allocate_exact_size(
                                                    vec2(14.0, 14.0),
                                                    Sense::hover(),
                                                );
                                                ui.painter().rect_filled(rect, 2.0, color);
                                                ui.painter().rect_stroke(
                                                    rect,
                                                    2.0,
                                                    egui::Stroke::new(1.0, Color32::from_gray(90)),
                                                    egui::StrokeKind::Inside,
                                                );
                                            });
                                        }
                                        None => {
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(&it.value).monospace(),
                                                )
                                                .truncate(),
                                            );
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                        // one-line disassembly of the instruction at the cursor
                        if let Some(d) = self.docs.get(a) {
                            let data = d.buffer.data();
                            if c < data.len() {
                                let bits =
                                    if d.pe.as_ref().is_some_and(|p| p.is_64) { 64 } else { 32 };
                                let end = (c + 16).min(data.len());
                                let insns = disassemble(&data[c..end], bits, c as u64, 1);
                                if let Some(ins) = insns.first() {
                                    let text = if ins.invalid {
                                        "(bad)".to_string()
                                    } else {
                                        ins.text.clone()
                                    };
                                    ui.horizontal(|ui| {
                                        ui.monospace(
                                            egui::RichText::new(format!("asm{bits}")).weak(),
                                        );
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(text)
                                                    .monospace()
                                                    .color(Color32::from_rgb(180, 200, 150)),
                                            )
                                            .truncate(),
                                        );
                                    });
                                }
                            }
                        }
                        // number-base converter for the value at the cursor
                        egui::CollapsingHeader::new("Bases / convert")
                            .default_open(false)
                            .show(ui, |ui| {
                                let w = base_width.clamp(1, 8);
                                ui.horizontal(|ui| {
                                    ui.label("width:");
                                    for bw in [1usize, 2, 4, 8] {
                                        ui.selectable_value(&mut base_width, bw, format!("{bw}"));
                                    }
                                });
                                // Read the unsigned value at the cursor.
                                let val: u64 = self
                                    .docs
                                    .get(a)
                                    .map(|d| {
                                        let data = d.buffer.data();
                                        let end = (c + w).min(data.len());
                                        let sl = &data[c.min(data.len())..end];
                                        if inspect_endian == Endian::Little {
                                            sl.iter().enumerate().fold(0u64, |v, (i, &b)| {
                                                v | ((b as u64) << (8 * i))
                                            })
                                        } else {
                                            sl.iter().fold(0u64, |v, &b| (v << 8) | b as u64)
                                        }
                                    })
                                    .unwrap_or(0);
                                egui::Grid::new("base_grid").num_columns(3).show(ui, |ui| {
                                    hash_row(ui, "dec", &val.to_string());
                                    hash_row(ui, "hex", &format!("{val:X}"));
                                    hash_row(ui, "oct", &format!("{val:o}"));
                                    hash_row(ui, "bin", &format!("{val:b}"));
                                });
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut base_edit)
                                            .desired_width(130.0)
                                            .hint_text("0x1F / 0b.. / 31"),
                                    );
                                    if ui
                                        .button("Write")
                                        .on_hover_text("overwrite these bytes with the value")
                                        .clicked()
                                    {
                                        if let Some(nv) = parse_multibase(&base_edit) {
                                            let bytes = if inspect_endian == Endian::Little {
                                                nv.to_le_bytes()[..w].to_vec()
                                            } else {
                                                nv.to_be_bytes()[8 - w..].to_vec()
                                            };
                                            action_base_write = Some((c, bytes));
                                        }
                                    }
                                });
                            });
                    }
                    _ => {
                        ui.label("Click a byte to inspect it.");
                    }
                }
                    });
                ui.separator();

                // edit / resize (insert / delete bytes)
                egui::CollapsingHeader::new("Edit / resize")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.add(
                                egui::DragValue::new(&mut insert_count)
                                    .range(1..=1_048_576)
                                    .prefix("n="),
                            );
                            if ui
                                .add_enabled(cur.is_some(), egui::Button::new("Insert 00"))
                                .on_hover_text("insert n zero bytes at the caret (undoable)")
                                .clicked()
                            {
                                if let Some(c) = cur {
                                    action_insert = Some((c, insert_count));
                                }
                            }
                            if ui
                                .add_enabled(sel.is_some(), egui::Button::new("Delete sel"))
                                .on_hover_text("remove the selected bytes (undoable)")
                                .clicked()
                            {
                                if let Some((s, e)) = sel {
                                    action_delete = Some((s, e - s));
                                }
                            }
                        });
                    });
                });
            });

        // ---- bottom XOR decode / transform / copy panel ----
        let mut action_apply_xor: Option<(usize, Vec<u8>)> = None;
        let mut action_brute = false;
        let mut set_key: Option<String> = None;
        let mut record_xor_key: Option<String> = None;
        let mut action_block_op: Option<BlockOp> = None;
        let mut copy_kind: Option<CopyKind> = None;
        let mut action_dump = false;
        let mut action_yara_from_sel = false;
        egui::TopBottomPanel::bottom("xor")
            .resizable(true)
            .default_height(250.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let (tick, _) = ui.allocate_exact_size(vec2(3.0, 14.0), Sense::hover());
                    ui.painter().rect_filled(tick, 1.5, self.palette.accent);
                    ui.add_space(3.0);
                    ui.label(
                        egui::RichText::new("Decode — XOR")
                            .color(self.palette.text)
                            .size(14.0),
                    );
                });
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.label("key:");
                    let te = ui.add_enabled(
                        has_doc,
                        egui::TextEdit::singleline(&mut xor_key)
                            .desired_width(220.0)
                            .hint_text("6A 40   or   ascii"),
                    );
                    // Recent-keys dropdown: shown while the key field is focused.
                    // Recent-keys dropdown. Rendered via a memory-backed popup so
                    // it stays alive when a click moves focus off the field —
                    // otherwise the click that picks a key would land on nothing.
                    let popup_id = ui.make_persistent_id("xor_key_history");
                    if te.gained_focus() {
                        ui.memory_mut(|m| m.open_popup(popup_id));
                    }
                    egui::popup_below_widget(
                        ui,
                        popup_id,
                        &te,
                        egui::PopupCloseBehavior::CloseOnClickOutside,
                        |ui| {
                            ui.set_min_width(220.0);
                            if self.xor_key_history.is_empty() {
                                ui.label(
                                    egui::RichText::new(
                                        "no recent keys yet — type a key + Enter to remember it",
                                    )
                                    .weak()
                                    .small(),
                                );
                            } else {
                                ui.label(
                                    egui::RichText::new("recent keys (click to use)")
                                        .weak()
                                        .small(),
                                );
                                for k in &self.xor_key_history {
                                    if ui
                                        .add(
                                            egui::Button::new(egui::RichText::new(k).monospace())
                                                .frame(false),
                                        )
                                        .clicked()
                                    {
                                        xor_key = k.clone();
                                        ui.memory_mut(|m| m.close_popup());
                                    }
                                }
                            }
                        },
                    );
                    // Pressing Enter with a valid key remembers it (no destructive
                    // Apply required) — makes the history easy to build up.
                    if te.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                        && parse_key(&xor_key).is_some()
                    {
                        record_xor_key = Some(xor_key.clone());
                    }
                    match parse_key(&xor_key) {
                        Some(k) => {
                            let hexk: Vec<String> = k.iter().map(|b| format!("{:02X}", b)).collect();
                            ui.label(
                                egui::RichText::new(format!(
                                    "= [{}]  ({} byte key)",
                                    hexk.join(" "),
                                    k.len()
                                ))
                                .monospace()
                                .weak(),
                            );
                        }
                        None => {
                            ui.label(egui::RichText::new("(enter a key)").weak());
                        }
                    }
                });
                ui.separator();

                match sel {
                    None => {
                        ui.label("Drag-select bytes in the hex view to decode them.");
                    }
                    Some((s, e)) => {
                        if let Some(d) = self.docs.get(a) {
                            let buf = &d.buffer;
                            let total = e - s;
                            let plen = total.min(4096);
                            let src = buf.slice(s, s + plen);
                            let key = parse_key(&xor_key);

                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        key.is_some(),
                                        egui::Button::new(
                                            egui::RichText::new("Apply to buffer")
                                                .color(self.palette.accent_ink),
                                        )
                                        .fill(self.palette.accent),
                                    )
                                    .clicked()
                                {
                                    if let Some(k) = &key {
                                        let full = xor_preview(buf.slice(s, e), k);
                                        action_apply_xor = Some((s, full));
                                        record_xor_key = Some(xor_key.clone());
                                    }
                                }
                                if ui.button("Brute-force single-byte").clicked() {
                                    action_brute = true;
                                }
                                if total > plen {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "preview first {plen} of {total} bytes"
                                        ))
                                        .weak(),
                                    );
                                }
                            });

                            if let Some(k) = &key {
                                let decoded = xor_preview(src, k);
                                let mut ascii = String::with_capacity(plen + plen / 64 + 1);
                                for (i, &b) in decoded.iter().enumerate() {
                                    if i > 0 && i % 64 == 0 {
                                        ascii.push('\n');
                                    }
                                    ascii.push(if (0x20..=0x7e).contains(&b) { b as char } else { '.' });
                                }
                                egui::ScrollArea::vertical()
                                    .id_salt("decoded_ascii")
                                    .max_height(110.0)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.add(egui::Label::new(egui::RichText::new(ascii).monospace()));
                                    });

                                let dmin = strings_min_len.max(3);
                                let dstrings = find_strings(&decoded, dmin, true, true);
                                ui.separator();
                                ui.label(format!("{} strings in decoded:", dstrings.len()));
                                egui::ScrollArea::vertical()
                                    .id_salt("decoded_strings")
                                    .max_height(70.0)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        for ds in dstrings.iter().take(200) {
                                            ui.monospace(format!("+{:04X}  {}", ds.offset, ds.text));
                                        }
                                    });
                            }
                        }

                        ui.separator();
                        ui.label("Transform selection (in place, undoable):");
                        ui.horizontal_wrapped(|ui| {
                            let mut op_btn = |ui: &mut egui::Ui, name: &str, op: BlockOp| {
                                if ui.button(name).clicked() {
                                    action_block_op = Some(op);
                                }
                            };
                            op_btn(ui, "NOT", BlockOp::Not);
                            op_btn(ui, "NEG", BlockOp::Neg);
                            op_btn(ui, "+1", BlockOp::Add(1));
                            op_btn(ui, "-1", BlockOp::Sub(1));
                            op_btn(ui, "ROL1", BlockOp::Rol(1));
                            op_btn(ui, "ROR1", BlockOp::Ror(1));
                            op_btn(ui, "Reverse", BlockOp::Reverse);
                            op_btn(ui, "Bswap16", BlockOp::ByteSwap16);
                            op_btn(ui, "Bswap32", BlockOp::ByteSwap32);
                        });

                        ui.separator();
                        ui.horizontal_wrapped(|ui| {
                            ui.label("Copy selection as:");
                            if ui.button("Hex").clicked() {
                                copy_kind = Some(CopyKind::Hex);
                            }
                            if ui.button("Text").clicked() {
                                copy_kind = Some(CopyKind::Text);
                            }
                            if ui.button("YARA").clicked() {
                                copy_kind = Some(CopyKind::Yara);
                            }
                            if ui.button("C array").clicked() {
                                copy_kind = Some(CopyKind::CArray);
                            }
                            if ui.button("base64").clicked() {
                                copy_kind = Some(CopyKind::Base64);
                            }
                            ui.separator();
                            if ui
                                .button("Save…")
                                .on_hover_text("dump the selected bytes to a file (carve a PE, resource, decoded blob…)")
                                .clicked()
                            {
                                action_dump = true;
                            }
                            if ui
                                .button("YARA rule")
                                .on_hover_text("build a YARA rule from the selection into the YARA panel")
                                .clicked()
                            {
                                action_yara_from_sel = true;
                            }
                        });

                        if let Some(d) = self.docs.get(a) {
                            if !d.brute_results.is_empty() {
                                ui.separator();
                                ui.label("Top single-byte keys (text score) — click to use:");
                                ui.horizontal_wrapped(|ui| {
                                    for r in d.brute_results.iter().take(24) {
                                        if ui
                                            .button(format!("{:02X}·{:.0}%", r.key, r.score * 100.0))
                                            .clicked()
                                        {
                                            set_key = Some(format!("{:02X}", r.key));
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            });

        // ---- write back editable snapshots ----
        if let Some(d) = self.docs.get_mut(a) {
            d.xor_key = xor_key;
            d.search_query = search_query;
            d.search_hex = search_hex;
            d.search_ci = search_ci;
            d.ioc_defang = ioc_defang;
        }
        // ---- VirusTotal enrichment toggle + open-in-browser ----
        if vt_enabled != self.vt.enabled {
            self.vt.enabled = vt_enabled;
            save_vt_enabled(vt_enabled);
            if vt_enabled {
                let sha = self
                    .docs
                    .get(a)
                    .map(|d| d.file_sha256.clone())
                    .unwrap_or_default();
                self.vt.request(&sha);
            }
        }
        if vt_open {
            let sha = self
                .docs
                .get(a)
                .map(|d| d.file_sha256.clone())
                .unwrap_or_default();
            if sha.len() == 64 {
                let url = format!("https://www.virustotal.com/gui/file/{sha}");
                let _ = std::process::Command::new("open").arg(url).spawn();
            }
        }
        if let Some(dh) = vt_icon_check {
            self.vt.request_icon(&dh);
        }
        if let Some(dh) = vt_icon_open {
            let url = format!("https://www.virustotal.com/gui/search/main_icon_dhash:{dh}");
            let _ = std::process::Command::new("open").arg(url).spawn();
        }
        self.strings_ascii = strings_ascii;
        self.strings_utf16 = strings_utf16;
        self.strings_min_len = strings_min_len;
        self.inspect_endian = inspect_endian;
        self.base_width = base_width;
        self.base_edit = base_edit;
        self.goto_query = goto_query;
        self.replace_query = replace_query.clone();
        self.bookmark_name = bookmark_name;
        self.strings_filter = strings_filter;
        self.yara_source = yara_source;
        self.disasm_bits = disasm_bits;
        self.bytes_per_row = bytes_per_row;
        if view_mode != self.view {
            if self.view == ViewMode::Text {
                self.commit_text(self.active); // leaving text view: flush edits
            }
            save_view(view_mode);
        }
        self.view = view_mode;
        self.insert_count = insert_count;
        self.auto_run_template = auto_run_template;
        self.ai.prompt = ai_prompt;
        self.ai.allow_write = ai_allow_write;
        // ---- AI assistant: dispatch a codex run ----
        if let Some(act) = ai_action {
            let mut context = self.ai_context();
            let mut write = self.ai.allow_write;
            let mut pending_open = None;
            let (label, instr) = match act {
                AiAction::Explain => ("explain", AI_EXPLAIN.to_string()),
                AiAction::Ask => ("ask", self.ai.prompt.clone()),
                AiAction::Decode => {
                    write = true; // decode must be able to write its output
                    let out = std::env::temp_dir()
                        .join(format!("hexed_decoded_{}.bin", std::process::id()));
                    let instr = format!(
                        "You are a malware analyst. The selected bytes in the context appear \
                         encoded/obfuscated. Identify the algorithm (XOR/RC4/base64/LZNT1/etc.), \
                         recover the key or parameters, decode the bytes, and WRITE THE DECODED \
                         BYTES (raw) to exactly this path: {}. Write nothing else to that path. \
                         Then briefly state the algorithm and key you used.",
                        out.display()
                    );
                    pending_open = Some(out);
                    ("decode", instr)
                }
                AiAction::Yara => ("yara", AI_YARA.to_string()),
                AiAction::Triage => {
                    if let Some(rep) = self.docs.get(a).and_then(|d| {
                        d.pe.as_ref()
                            .map(|pe| build_pe_report(&d.file_name, d.buffer.data(), pe))
                    }) {
                        context.push_str("\n\n=== PE report ===\n");
                        context.push_str(&rep);
                    }
                    ("triage", AI_TRIAGE.to_string())
                }
                AiAction::Disasm => {
                    if let Some(d) = self.docs.get(a) {
                        if let Some((s, e)) = d.selection_range() {
                            let bits = if d.pe.as_ref().is_some_and(|p| p.is_64) {
                                64
                            } else {
                                32
                            };
                            let end = (s + (e - s).min(1024)).min(d.buffer.len());
                            let insns = disassemble(d.buffer.slice(s, end), bits, s as u64, 300);
                            context.push_str("\n\n=== disassembly ===\n");
                            for i in &insns {
                                context.push_str(&format!(
                                    "{:08X}  {:<20}  {}\n",
                                    i.address,
                                    i.bytes_hex(),
                                    if i.invalid { "(bad)" } else { i.text.as_str() }
                                ));
                            }
                        }
                    }
                    ("explain asm", AI_DISASM.to_string())
                }
                AiAction::Bt => ("bt template", AI_BT.to_string()),
            };
            self.ai_last_action = Some(act);
            self.ai_pending_open = pending_open;
            self.ai.run(label, instr, context, write);
        }
        if mark_dirty {
            if let Some(d) = self.docs.get_mut(a) {
                d.strings_dirty = true;
            }
        }

        // ---- .bt template: load a builtin/file, then run it ----
        if let Some(i) = bt_load_builtin {
            bt_source = BUILTIN_TEMPLATES[i].1.to_string();
            self.status = format!("Loaded {} template", BUILTIN_TEMPLATES[i].0);
        }
        if action_bt_load {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Binary Template", &["bt"])
                .pick_file()
            {
                match std::fs::read_to_string(&path) {
                    Ok(s) => {
                        bt_source = s;
                        self.status = format!("Loaded template {}", abbrev_home(&path));
                    }
                    Err(e) => self.status = format!("Template load failed: {e}"),
                }
            }
        }
        self.bt_source = bt_source;
        if action_bt_run {
            let src = self.bt_source.clone();
            let mut st = None;
            if let Some(d) = self.docs.get_mut(a) {
                let res = hexed_bt::run(&src, d.buffer.data());
                d.bt_spans.clear();
                match &res {
                    Ok(t) => {
                        collect_bt_spans(&t.root, &mut d.bt_spans);
                        st = Some(format!(
                            "Template mapped {} bytes ({} fields)",
                            t.end_pos,
                            t.root.len()
                        ));
                    }
                    Err(e) => st = Some(format!("Template error: {e}")),
                }
                d.bt_result = Some(res);
            }
            if let Some(s) = st {
                self.status = s;
            }
        }

        // ---- binary compare / diff ----
        if let Some(other) = action_compare {
            if other != a && other < self.docs.len() && a < self.docs.len() {
                // Compute the diff from two shared borrows, then store on active.
                let res = {
                    let da = self.docs[a].buffer.data();
                    let db = self.docs[other].buffer.data();
                    diff_aligned(da, db)
                };
                let other_name = self.docs[other].file_name.clone();
                let summary = if res.identical() {
                    format!("identical to {other_name} ({} bytes)", res.len_a)
                } else {
                    let tail = if res.tail_extra > 0 {
                        format!(", +{} tail", res.tail_extra)
                    } else {
                        String::new()
                    };
                    format!(
                        "vs {}: {} diff / {} bytes ({:.1}% same){}",
                        other_name,
                        res.differing,
                        res.compared,
                        res.similarity() * 100.0,
                        tail
                    )
                };
                if let Some(d) = self.docs.get_mut(a) {
                    d.diff_ranges = res.runs.iter().map(|r| (r.start, r.end())).collect();
                    d.diff_idx = 0;
                    d.diff_summary = Some(summary.clone());
                }
                self.status = summary;
            }
        }
        if action_diff_clear {
            if let Some(d) = self.docs.get_mut(a) {
                d.diff_ranges.clear();
                d.diff_summary = None;
                d.diff_idx = 0;
            }
        }
        if action_diff_first || action_diff_next {
            if let Some(d) = self.docs.get_mut(a) {
                if !d.diff_ranges.is_empty() {
                    d.diff_idx = if action_diff_first {
                        0
                    } else {
                        (d.diff_idx + 1) % d.diff_ranges.len()
                    };
                    let (s, e) = d.diff_ranges[d.diff_idx];
                    d.goto(s, e - s);
                }
            }
        }

        // ---- insert / delete bytes (resize + undoable) ----
        if let Some((off, n)) = action_insert {
            self.commit_text(a); // flush any pending text-view edits first
            let mut st = None;
            if let Some(d) = self.docs.get_mut(a) {
                let off = off.min(d.buffer.len());
                d.buffer.insert(off, &vec![0u8; n]);
                for (b, _) in d.bookmarks.iter_mut() {
                    if *b >= off {
                        *b += n;
                    }
                }
                invalidate_derived(d);
                d.goto(off, n); // select the inserted region
                st = Some(format!("Inserted {n} byte(s) at 0x{off:X}"));
            }
            if let Some(s) = st {
                self.status = s;
            }
        }
        if let Some((off, len)) = action_delete {
            self.commit_text(a); // flush any pending text-view edits first
            let mut st = None;
            if let Some(d) = self.docs.get_mut(a) {
                let len = len.min(d.buffer.len().saturating_sub(off));
                d.buffer.delete(off, len);
                // Drop bookmarks inside the hole; shift those after it down.
                d.bookmarks.retain(|(b, _)| !(*b >= off && *b < off + len));
                for (b, _) in d.bookmarks.iter_mut() {
                    if *b >= off + len {
                        *b -= len;
                    }
                }
                invalidate_derived(d);
                let nl = d.buffer.len();
                if nl == 0 {
                    d.sel_anchor = None;
                    d.sel_cursor = None;
                } else {
                    let o = off.min(nl - 1);
                    d.sel_anchor = Some(o);
                    d.sel_cursor = Some(o);
                    d.scroll_to = Some(o);
                    d.scroll_ttl = 4;
                }
                st = Some(format!("Deleted {len} byte(s) at 0x{off:X}"));
            }
            if let Some(s) = st {
                self.status = s;
            }
        }

        // ---- jump from strings list (before drawing the grid) ----
        if let Some((off, ln)) = jump_to {
            if let Some(d) = self.docs.get_mut(a) {
                d.goto(off, ln);
            }
        }

        // ---- cross-tab jump from a YARA hit (switches active tab) ----
        if let Some((di, off, len)) = cross_jump {
            if di < self.docs.len() {
                self.active = di;
                if let Some(d) = self.docs.get_mut(di) {
                    d.goto(off, len);
                }
            }
        }

        // ---- find & replace (overwrite-only ⇒ equal length required) ----
        if action_replace_next || action_replace_all {
            self.commit_text(a); // flush any pending text-view edits first
            let rep = if search_hex {
                parse_hex_bytes(&replace_query).ok_or_else(|| {
                    "Replacement must be concrete hex bytes (e.g. 90 90).".to_string()
                })
            } else {
                Ok(replace_query.as_bytes().to_vec())
            };
            let mut st = None;
            let mut did_replace = false;
            match rep {
                Err(e) => st = Some(e),
                Ok(rep) => {
                    if let Some(d) = self.docs.get_mut(a) {
                        if d.search_hits.is_empty() {
                            st = Some("Run Find first, then Replace.".to_string());
                        } else if rep.is_empty() {
                            st = Some("Enter replacement bytes.".to_string());
                        } else if rep.len() != d.search_hit_len {
                            st = Some(format!(
                                "Replacement is {} bytes but matches are {} — this editor is overwrite-only, so use an equal-length replacement.",
                                rep.len(),
                                d.search_hit_len
                            ));
                        } else if action_replace_all {
                            let mut positions = d.search_hits.clone();
                            positions.sort_unstable();
                            for &off in &positions {
                                d.buffer.overwrite(off, &rep);
                            }
                            st = Some(format!("Replaced {} occurrence(s).", positions.len()));
                            did_replace = true;
                        } else {
                            let idx = d.search_idx.min(d.search_hits.len() - 1);
                            let off = d.search_hits[idx];
                            d.buffer.overwrite(off, &rep);
                            st = Some(format!("Replaced 1 at 0x{off:X}."));
                            did_replace = true;
                        }
                    }
                }
            }
            if let Some(s) = st {
                self.status = s;
            }
            // Refresh hits against the edited buffer without clobbering the
            // replace status (the search block below would overwrite it).
            if did_replace {
                if let Some(d) = self.docs.get_mut(a) {
                    d.strings_dirty = true;
                    let q = d.search_query.trim().to_string();
                    d.search_idx = 0;
                    if d.search_hex {
                        if let Some(pat) = parse_hex_pattern(&q) {
                            d.search_hits = find_pattern(d.buffer.data(), &pat);
                        }
                    } else if !q.is_empty() {
                        let ci = d.search_ci;
                        d.search_hits = find_text(d.buffer.data(), &q, ci);
                    }
                }
            }
        }

        // ---- process search ----
        if action_find {
            let mut result_status = None;
            if let Some(d) = self.docs.get_mut(a) {
                d.search_hits.clear();
                d.search_idx = 0;
                let q = d.search_query.trim().to_string();
                if q.is_empty() {
                    // nothing
                } else if d.search_hex {
                    match parse_hex_pattern(&q) {
                        Some(pat) => {
                            d.search_hit_len = pat.len();
                            d.search_hits = find_pattern(d.buffer.data(), &pat);
                        }
                        None => result_status = Some("Invalid hex pattern.".to_string()),
                    }
                } else {
                    d.search_hit_len = q.len();
                    let ci = d.search_ci;
                    d.search_hits = find_text(d.buffer.data(), &q, ci);
                }
                if !d.search_hits.is_empty() {
                    result_status = Some(format!("{} matches", d.search_hits.len()));
                } else if !q.is_empty() && result_status.is_none() {
                    result_status = Some("No matches.".to_string());
                }
            }
            if let Some(s) = result_status {
                self.status = s;
            }
        }
        if action_nav != 0 {
            if let Some(d) = self.docs.get_mut(a) {
                if !d.search_hits.is_empty() {
                    let n = d.search_hits.len() as i32;
                    d.search_idx = (((d.search_idx as i32 + action_nav) % n + n) % n) as usize;
                }
            }
        }
        if action_find || action_nav != 0 {
            if let Some(d) = self.docs.get_mut(a) {
                if !d.search_hits.is_empty() {
                    let off = d.search_hits[d.search_idx];
                    let len = d.search_hit_len.max(1);
                    d.goto(off, len);
                }
            }
        }

        // ---- goto address (Ctrl+G / Go) ----
        if action_goto {
            match parse_offset(&self.goto_query) {
                Some(off) => {
                    let mut jumped = None;
                    if let Some(d) = self.docs.get_mut(a) {
                        let o = off.min(d.buffer.len().saturating_sub(1));
                        d.goto(o, 1);
                        jumped = Some(o);
                    }
                    if let Some(o) = jumped {
                        self.status = format!("Jumped to 0x{o:X}");
                    }
                }
                None => self.status = "Bad address (try 0x1F or 31).".to_string(),
            }
        }

        // ---- entropy minimap strip ----
        let mut strip_jump: Option<usize> = None;
        egui::SidePanel::left("entropy_strip")
            .exact_width(16.0)
            .resizable(false)
            .show(ctx, |ui| {
                strip_jump = self.draw_entropy_strip(ui);
            });

        // ---- central pane: hex grid or text view ----
        let (hex_action, carve) = egui::CentralPanel::default()
            .show(ctx, |ui| {
                if self.view == ViewMode::Text {
                    self.draw_text(ui)
                } else {
                    self.draw_hex(ui)
                }
            })
            .inner;
        if let Some(off) = strip_jump {
            if let Some(d) = self.docs.get_mut(a) {
                d.goto(off.min(d.buffer.len().saturating_sub(1)), 1);
            }
        }
        if let Some(d) = self.docs.get_mut(a) {
            if hex_action.is_some() {
                // a click/drag cancels any in-flight programmatic scroll
                d.scroll_ttl = 0;
                d.scroll_to = None;
            } else if d.scroll_ttl > 0 {
                d.scroll_ttl -= 1;
                if d.scroll_ttl == 0 {
                    d.scroll_to = None;
                } else {
                    ctx.request_repaint(); // keep frames coming until the scroll settles
                }
            }
            match hex_action {
                Some(SelUpdate::Set(i)) => {
                    d.sel_anchor = Some(i);
                    d.sel_cursor = Some(i);
                }
                Some(SelUpdate::Extend(i)) => {
                    if d.sel_anchor.is_none() {
                        d.sel_anchor = Some(i);
                    }
                    d.sel_cursor = Some(i);
                }
                None => {}
            }
        }

        // ---- theme switch ----
        if let Some(t) = action_set_theme {
            self.theme = t;
            self.palette = theme::palette(t);
            theme::apply(ctx, t);
            save_theme(t);
            self.status = format!("Theme: {}", t.name());
        }

        // ---- About window (logo + export icon) ----
        if action_about {
            self.show_about = true;
        }
        if self.show_about && self.logo_tex.is_none() {
            if let Ok(img) = image::load_from_memory(LOGO_PNG) {
                let rgba = img.to_rgba8();
                let (w, h) = rgba.dimensions();
                let ci = egui::ColorImage::from_rgba_unmultiplied(
                    [w as usize, h as usize],
                    rgba.as_raw(),
                );
                self.logo_tex = Some(ctx.load_texture("logo", ci, egui::TextureOptions::LINEAR));
            }
        }
        let mut about_open = self.show_about;
        let mut export_icon = false;
        if about_open {
            egui::Window::new("About Hexed")
                .open(&mut about_open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        if let Some(tex) = &self.logo_tex {
                            ui.add(
                                egui::Image::new(egui::load::SizedTexture::new(
                                    tex.id(),
                                    tex.size_vec2(),
                                ))
                                .max_size(vec2(160.0, 160.0)),
                            );
                        }
                        ui.heading("Hexed");
                        ui.label("hex editor & malware-triage tool");
                        ui.add_space(8.0);
                        if ui.button("Export icon as PNG…").clicked() {
                            export_icon = true;
                        }
                    });
                });
        }
        self.show_about = about_open;
        if export_icon {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("PNG image", &["png"])
                .set_file_name("hexed_icon.png")
                .save_file()
            {
                self.status = match std::fs::write(&path, LOGO_PNG) {
                    Ok(()) => format!("Exported icon to {}", abbrev_home(&path)),
                    Err(e) => format!("Icon export failed: {e}"),
                };
            }
        }

        // ---- carve selection into a new in-memory tab ----
        if let Some((start, bytes)) = carve {
            let n = bytes.len();
            let src = self
                .docs
                .get(a)
                .map(|d| d.file_name.clone())
                .unwrap_or_default();
            let name = format!("{src}@0x{start:X} ({n}B)");
            self.docs
                .push(Document::new(Buffer::from_bytes(bytes), name));
            self.active = self.docs.len() - 1;
            self.maybe_autorun_template(); // auto-parse if the blob is a known format
            self.status = format!("Carved {n} bytes from 0x{start:X} into a new tab");
        }

        // ---- extract an embedded file into a new tab ----
        if let Some((off, size)) = carve_embedded {
            let carved = self.docs.get(a).and_then(|d| {
                let total = d.buffer.len();
                let end = match size {
                    Some(s) => (off + s).min(total),
                    // no size hint: carve to the next embedded signature, else EOF
                    None => d
                        .embedded
                        .iter()
                        .map(|e| e.offset)
                        .filter(|&o| o > off)
                        .min()
                        .unwrap_or(total)
                        .min(total),
                };
                (end > off).then(|| (d.buffer.slice(off, end).to_vec(), d.file_name.clone()))
            });
            if let Some((bytes, src)) = carved {
                let n = bytes.len();
                let name = format!("{src}@0x{off:X} ({n}B)");
                self.docs
                    .push(Document::new(Buffer::from_bytes(bytes), name));
                self.active = self.docs.len() - 1;
                self.maybe_autorun_template();
                self.status = format!("Extracted {n} bytes from 0x{off:X} into a new tab");
            }
        }

        // ---- copy all IOCs to the clipboard ----
        if let Some(defanged) = copy_iocs {
            if let Some(d) = self.docs.get(a) {
                let mut s = String::new();
                for kind in IOC_KINDS {
                    let group: Vec<&Ioc> = d.iocs.iter().filter(|i| i.kind == *kind).collect();
                    if group.is_empty() {
                        continue;
                    }
                    s.push_str(&format!("# {}\n", kind.label()));
                    for ioc in group {
                        let v = if defanged {
                            defang(&ioc.value)
                        } else {
                            ioc.value.clone()
                        };
                        s.push_str(&v);
                        s.push('\n');
                    }
                    s.push('\n');
                }
                if !s.is_empty() {
                    ctx.copy_text(s);
                    self.status = "IOCs copied to clipboard".to_string();
                    self.copy_flash_id = "iocs";
                    self.copy_flash_until = now + 1.2;
                }
            }
        }

        // ---- build + copy a full triage report ----
        if action_triage {
            // Include the VirusTotal verdict only if enrichment is opted in.
            let sha = self
                .docs
                .get(a)
                .map(|d| d.file_sha256.clone())
                .unwrap_or_default();
            let vt = if self.vt.enabled {
                self.vt.get(&sha).cloned()
            } else {
                None
            };
            if let Some(r) = self
                .docs
                .get(a)
                .map(|d| build_triage_report(d, vt.as_ref()))
            {
                ctx.copy_text(r);
                self.status = "Triage report copied to clipboard".to_string();
                self.copy_flash_id = "triage";
                self.copy_flash_until = now + 1.2;
            }
        }

        // ---- apply collected actions (mutations, no borrow conflicts) ----
        if let Some(k) = set_key {
            if let Some(d) = self.docs.get_mut(a) {
                d.xor_key = k;
            }
        }
        if action_open {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                self.open_path(path);
            }
        }
        if let Some(path) = action_open_recent {
            self.open_path(path);
        }
        if action_save {
            self.commit_text(a); // flush any pending text-view edits first
            let mut st = None;
            if let Some(d) = self.docs.get_mut(a) {
                st = Some(match d.buffer.save() {
                    Ok(()) => "Saved.".to_string(),
                    Err(e) => format!("Save failed: {e}"),
                });
            }
            if let Some(s) = st {
                self.status = s;
            }
        }
        if let Some((off, bytes)) = action_apply_xor {
            let n = bytes.len();
            if let Some(d) = self.docs.get_mut(a) {
                d.buffer.overwrite(off, &bytes);
                d.strings_dirty = true;
            }
            self.status = format!("XOR applied to {n} bytes @ 0x{off:X}");
        }
        if let Some((off, bytes)) = action_base_write {
            let n = bytes.len();
            if let Some(d) = self.docs.get_mut(a) {
                d.buffer.overwrite(off, &bytes);
                d.strings_dirty = true;
            }
            self.status = format!("Wrote {n} byte(s) @ 0x{off:X}");
        }
        if let Some(k) = record_xor_key {
            push_xor_key(&mut self.xor_key_history, &k);
        }
        if action_undo {
            let mut ok = false;
            if let Some(d) = self.docs.get_mut(a) {
                if d.buffer.undo() {
                    d.strings_dirty = true;
                    ok = true;
                }
            }
            if ok {
                self.status = "Undo.".to_string();
            }
        }
        if action_redo {
            let mut ok = false;
            if let Some(d) = self.docs.get_mut(a) {
                if d.buffer.redo() {
                    d.strings_dirty = true;
                    ok = true;
                }
            }
            if ok {
                self.status = "Redo.".to_string();
            }
        }
        if action_brute {
            let mut st = None;
            if let Some((s, e)) = sel {
                if let Some(d) = self.docs.get_mut(a) {
                    let n = (e - s).min(65536);
                    d.brute_results = brute_force_single_byte(d.buffer.slice(s, s + n));
                    st = Some(format!("Brute-forced {} bytes (256 keys)", n.min(e - s)));
                }
            }
            if let Some(s) = st {
                self.status = s;
            }
        }
        if let Some(file) = action_hash {
            let mut st = None;
            let mut new_hashes = None;
            if let Some(d) = self.docs.get(a) {
                let (label, data): (String, &[u8]) = if file {
                    (
                        format!("whole file ({} bytes)", d.buffer.len()),
                        d.buffer.data(),
                    )
                } else if let Some((s, e)) = sel {
                    (
                        format!("selection 0x{s:X}–0x{e:X} ({} bytes)", e - s),
                        d.buffer.slice(s, e),
                    )
                } else {
                    (String::new(), &[][..])
                };
                if data.is_empty() {
                    st = Some("Nothing to hash (empty selection?).".to_string());
                } else {
                    st = Some(format!("Hashed {label}"));
                    new_hashes = Some((label, hash_all(data)));
                }
            }
            if let Some(h) = new_hashes {
                if let Some(d) = self.docs.get_mut(a) {
                    d.hashes = Some(h);
                }
            }
            if let Some(s) = st {
                self.status = s;
            }
        }
        if let Some(op) = action_block_op {
            let mut st = None;
            if let Some((s, e)) = sel {
                let bytes = self.docs.get(a).map(|d| d.buffer.slice(s, e).to_vec());
                if let Some(mut bytes) = bytes {
                    if !bytes.is_empty() {
                        apply_block_op(op, &mut bytes);
                        if let Some(d) = self.docs.get_mut(a) {
                            d.buffer.overwrite(s, &bytes);
                            d.strings_dirty = true;
                        }
                        st = Some(format!("Applied {op:?} to {} bytes @ 0x{s:X}", e - s));
                    }
                }
            }
            if let Some(s) = st {
                self.status = s;
            }
        }
        if action_save_as {
            self.commit_text(a); // flush any pending text-view edits first
            if let Some(path) = rfd::FileDialog::new().save_file() {
                let mut st = None;
                if let Some(d) = self.docs.get_mut(a) {
                    match d.buffer.save_as(&path) {
                        Ok(()) => {
                            d.file_name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            st = Some(format!("Saved as {}", d.file_name));
                        }
                        Err(e) => st = Some(format!("Save As failed: {e}")),
                    }
                }
                if let Some(s) = st {
                    self.status = s;
                }
            }
        }
        if let Some(kind) = copy_kind {
            let mut text = None;
            if let Some((s, e)) = sel {
                if let Some(d) = self.docs.get(a) {
                    let dd = d.buffer.slice(s, e);
                    text = Some(match kind {
                        CopyKind::Hex => to_hex_string(dd),
                        CopyKind::Text => to_text(dd),
                        CopyKind::Yara => to_yara_hex(dd),
                        CopyKind::CArray => to_c_array(dd, "data"),
                        CopyKind::Base64 => to_base64(dd),
                    });
                }
            }
            if let Some(t) = text {
                ctx.copy_text(t);
                self.status = format!("Copied selection as {kind:?}");
            }
        }
        if action_dump {
            if let Some((s, e)) = sel {
                let bytes = self
                    .docs
                    .get(a)
                    .map(|d| d.buffer.slice(s, e).to_vec())
                    .unwrap_or_default();
                if !bytes.is_empty() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name("selection.bin")
                        .save_file()
                    {
                        self.status = match std::fs::write(&path, &bytes) {
                            Ok(()) => format!(
                                "Saved {} bytes to {}",
                                bytes.len(),
                                path.file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_default()
                            ),
                            Err(err) => format!("Save failed: {err}"),
                        };
                    }
                }
            }
        }
        if action_add_bookmark {
            if let Some(c) = cur {
                let name = if self.bookmark_name.trim().is_empty() {
                    format!("bm {c:X}")
                } else {
                    self.bookmark_name.trim().to_string()
                };
                if let Some(d) = self.docs.get_mut(a) {
                    d.bookmarks.push((c, name));
                    d.bookmarks.sort_by_key(|(o, _)| *o);
                }
                self.sync_bookmarks(a);
                self.bookmark_name.clear();
                self.status = format!("Bookmarked 0x{c:X}");
            }
        }
        if let Some(i) = remove_bookmark {
            if let Some(d) = self.docs.get_mut(a) {
                if i < d.bookmarks.len() {
                    d.bookmarks.remove(i);
                }
            }
            self.sync_bookmarks(a);
        }
        if action_upx {
            let bytes = self.docs.get(a).map(|d| d.buffer.data().to_vec());
            if let Some(bytes) = bytes {
                let dir = std::env::temp_dir();
                let tmp_in = dir.join(format!("hexed_upx_in_{}", std::process::id()));
                let tmp_out = dir.join(format!("hexed_upx_out_{}", std::process::id()));
                let _ = std::fs::remove_file(&tmp_out);
                self.status = match std::fs::write(&tmp_in, &bytes) {
                    Err(e) => format!("temp write failed: {e}"),
                    Ok(()) => match upx_command()
                        .arg("-d")
                        .arg("-o")
                        .arg(&tmp_out)
                        .arg(&tmp_in)
                        .output()
                    {
                        Err(e) => {
                            format!("upx not found ({e}) — install it (e.g. `brew install upx`)")
                        }
                        Ok(out) if out.status.success() && tmp_out.exists() => {
                            self.open_path(tmp_out.clone());
                            if let Some(d) = self.docs.last_mut() {
                                d.file_name = "unpacked".to_string();
                            }
                            "UPX unpacked into a new tab".to_string()
                        }
                        Ok(out) => {
                            let err = String::from_utf8_lossy(&out.stderr);
                            format!(
                                "upx -d failed: {}",
                                err.lines().last().unwrap_or("(not packed?)").trim()
                            )
                        }
                    },
                };
                let _ = std::fs::remove_file(&tmp_in);
            }
        }
        if action_pe_report {
            let report = self.docs.get(a).and_then(|d| {
                d.pe.as_ref()
                    .map(|pe| build_pe_report(&d.file_name, d.buffer.data(), pe))
            });
            if let Some(r) = report {
                ctx.copy_text(r);
                self.status = "PE report copied to clipboard".to_string();
                self.copy_flash_id = "pe_report";
                self.copy_flash_until = now + 1.2;
            }
        }
        if export_file_icon {
            let png = self.docs.get(a).and_then(|d| d.icon_png.clone());
            if let Some(png) = png {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("PNG image", &["png"])
                    .set_file_name("file_icon.png")
                    .save_file()
                {
                    self.status = match std::fs::write(&path, &png) {
                        Ok(()) => format!("Exported file icon to {}", abbrev_home(&path)),
                        Err(e) => format!("Icon export failed: {e}"),
                    };
                }
            }
        }
        if action_yara_scan || action_yara_scan_all {
            let indices: Vec<usize> = if action_yara_scan_all {
                (0..self.docs.len()).collect()
            } else {
                vec![a]
            };
            let mut groups = Vec::new();
            let mut total_hits = 0usize;
            for i in indices {
                if let Some(d) = self.docs.get(i) {
                    let res = yara_scan(&self.yara_source, d.buffer.data());
                    if let Ok(m) = &res {
                        total_hits += m.len();
                    }
                    groups.push((i, d.file_name.clone(), res));
                }
            }
            if !groups.is_empty() {
                let scanned = groups.len();
                self.yara_result = Some(groups);
                self.status = format!("YARA: {total_hits} match(es) across {scanned} file(s)");
            }
        }
        if action_yara_export {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("YARA rule", &["yar", "yara"])
                .set_file_name("rule.yar")
                .save_file()
            {
                self.status = match std::fs::write(&path, self.yara_source.as_bytes()) {
                    Ok(()) => format!("Exported rule to {}", abbrev_home(&path)),
                    Err(e) => format!("Export failed: {e}"),
                };
            }
        }
        if action_yara_import {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("YARA rule", &["yar", "yara"])
                .pick_file()
            {
                self.status = match std::fs::read_to_string(&path) {
                    Ok(s) => {
                        self.yara_source = s;
                        format!("Imported rule from {}", abbrev_home(&path))
                    }
                    Err(e) => format!("Import failed: {e}"),
                };
            }
        }
        if action_yara_new {
            self.yara_source = yara_template();
            self.status = "Inserted a new YARA template".to_string();
        }
        if action_yara_save_template {
            if let Some(dir) = yara_template_dir() {
                let _ = std::fs::create_dir_all(&dir);
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("YARA rule", &["yar", "yara"])
                    .set_directory(&dir)
                    .set_file_name("my_rule.yar")
                    .save_file()
                {
                    self.status = match std::fs::write(&path, self.yara_source.as_bytes()) {
                        Ok(()) => {
                            self.reload_yara_library();
                            format!(
                                "Saved to library: {} — auto-scans on open",
                                abbrev_home(&path)
                            )
                        }
                        Err(e) => format!("Save failed: {e}"),
                    };
                }
            }
        }
        // ---- YARA library management ----
        if action_yara_reload {
            self.reload_yara_library();
            self.status = format!("Reloaded YARA library ({} rules)", self.yara_rules.len());
        }
        if action_yara_add_file {
            if let (Some(dir), Some(src)) = (
                yara_template_dir(),
                rfd::FileDialog::new()
                    .add_filter("YARA rule", &["yar", "yara"])
                    .pick_file(),
            ) {
                let _ = std::fs::create_dir_all(&dir);
                let name = src
                    .file_name()
                    .map(std::path::PathBuf::from)
                    .unwrap_or_default();
                let dest = dir.join(name);
                self.status = match std::fs::copy(&src, &dest) {
                    Ok(_) => {
                        self.reload_yara_library();
                        format!("Added {} to the library", abbrev_home(&dest))
                    }
                    Err(e) => format!("Add failed: {e}"),
                };
            }
        }
        if action_yara_open_dir {
            if let Some(dir) = yara_template_dir() {
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::process::Command::new("open").arg(&dir).spawn();
            }
        }
        if let Some(path) = yara_load_template {
            self.status = match std::fs::read_to_string(&path) {
                Ok(s) => {
                    self.yara_source = s;
                    format!("Loaded template {}", abbrev_home(&path))
                }
                Err(e) => format!("Load failed: {e}"),
            };
        }
        if action_yara_from_sel {
            let rule = sel.and_then(|(s, e)| {
                let cap = e.min(s + 256);
                self.docs.get(a).map(|d| {
                    // Anchor the condition to the file's magic (PE/ELF/PNG/…).
                    let magic = yara_file_magic(d.buffer.data());
                    let today = today_ymd();
                    to_yara_rule(
                        d.buffer.slice(s, cap),
                        "hexed_sel",
                        Some("Chi-en (Ashley) Shen"),
                        Some(&today),
                        magic,
                    )
                })
            });
            if let Some(r) = rule {
                self.yara_source = r;
                self.status =
                    "YARA rule generated from selection — open the YARA panel to scan".to_string();
            }
        }
        if action_close {
            close_idx = close_idx.or(Some(a));
        }

        // ---- tab switch / close (last, so indices stay valid above) ----
        if let Some(i) = switch_to {
            if i < self.docs.len() {
                self.active = i;
            }
        }
        if let Some(i) = close_idx {
            self.close_doc(i);
        }
    }
}

impl HexedApp {
    /// Draw the whole-file entropy minimap; returns a click-to-jump offset.
    fn draw_entropy_strip(&self, ui: &mut egui::Ui) -> Option<usize> {
        let doc = self.docs.get(self.active)?;
        let (rect, resp) = ui.allocate_exact_size(
            vec2(ui.available_width(), ui.available_height()),
            Sense::click(),
        );
        let profile = &doc.entropy_profile;
        let len = doc.buffer.len();
        if profile.is_empty() || len == 0 {
            return None;
        }
        let painter = ui.painter_at(rect);
        let h = rect.height();
        let n = profile.len();
        for (i, &e) in profile.iter().enumerate() {
            let y0 = rect.top() + (i as f32 / n as f32) * h;
            let y1 = rect.top() + ((i + 1) as f32 / n as f32) * h;
            painter.rect_filled(
                Rect::from_min_max(pos2(rect.left(), y0), pos2(rect.right(), y1)),
                0.0,
                entropy_color(e),
            );
        }
        let clicked = resp.clicked();
        let click_pos = resp.interact_pointer_pos();
        resp.on_hover_text("entropy minimap — click to jump (blue=low, red=high/packed)");
        if clicked {
            if let Some(p) = click_pos {
                let frac = ((p.y - rect.top()) / h).clamp(0.0, 1.0);
                return Some((frac * len as f32) as usize);
            }
        }
        None
    }

    /// Draw the launch splash: the logo fades + scales in over an accent glow,
    /// a progress bar sweeps, then the whole thing dissolves. `t` is seconds
    /// since launch. Themed to the active palette's accent.
    fn draw_splash(&mut self, ctx: &egui::Context, t: f32) {
        const DUR: f32 = 1.6;
        if self.logo_tex.is_none() {
            if let Ok(img) = image::load_from_memory(LOGO_PNG) {
                let rgba = img.to_rgba8();
                let (w, h) = rgba.dimensions();
                let ci = egui::ColorImage::from_rgba_unmultiplied(
                    [w as usize, h as usize],
                    rgba.as_raw(),
                );
                self.logo_tex = Some(ctx.load_texture("logo", ci, egui::TextureOptions::LINEAR));
            }
        }
        let p = self.palette;
        let screen = ctx.screen_rect();
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("hexed_splash"),
        ));
        let ease = |x: f32| {
            let x = x.clamp(0.0, 1.0);
            x * x * (3.0 - 2.0 * x)
        };
        // Whole-overlay fade: in over [0,0.12], out over [DUR-0.45, DUR].
        let overall = if t < 0.12 {
            t / 0.12
        } else if t > DUR - 0.45 {
            ((DUR - t) / 0.45).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let a = |c: Color32, mul: f32| {
            Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), (mul * overall * 255.0) as u8)
        };

        painter.rect_filled(screen, 0.0, a(p.bg, 1.0));
        let glow = screen.center() - vec2(0.0, 26.0);
        for k in 0..7 {
            let rad = 54.0 + k as f32 * 36.0;
            let alpha = (0.11 - k as f32 * 0.014).max(0.0);
            painter.circle_filled(glow, rad, a(p.accent, alpha));
        }
        if let Some(tex) = &self.logo_tex {
            let li = ease(t / 0.5);
            let sz = 118.0 * (0.9 + 0.1 * li);
            let rect = Rect::from_center_size(glow, vec2(sz, sz));
            let tint = Color32::from_rgba_unmultiplied(255, 255, 255, (li * overall * 255.0) as u8);
            painter.image(
                tex.id(),
                rect,
                Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                tint,
            );
        }
        let wi = ((t - 0.15) / 0.45).clamp(0.0, 1.0);
        let cx = screen.center().x;
        let wy = glow.y + 96.0;
        painter.text(
            pos2(cx, wy),
            Align2::CENTER_CENTER,
            "hexed",
            FontId::proportional(30.0),
            a(p.text, wi),
        );
        painter.text(
            pos2(cx, wy + 26.0),
            Align2::CENTER_CENTER,
            "HEX · TRIAGE · AI",
            FontId::proportional(10.5),
            a(p.dim, wi),
        );
        let bw = 184.0;
        let bx = cx - bw / 2.0;
        let by = wy + 50.0;
        painter.rect_filled(
            Rect::from_min_size(pos2(bx, by), vec2(bw, 3.0)),
            1.5,
            a(p.text, 0.12),
        );
        let pf = ease(((t - 0.1) / 1.05).clamp(0.0, 1.0));
        painter.rect_filled(
            Rect::from_min_size(pos2(bx, by), vec2(bw * pf, 3.0)),
            1.5,
            a(p.accent, 1.0),
        );
    }

    /// Route a finished AI run's output based on which action launched it.
    fn on_ai_done(&mut self) {
        let action = self.ai_last_action.take();
        let pending = self.ai_pending_open.take();
        if !self.ai.last_ok {
            return; // error text already shown in the AI panel
        }
        match action {
            Some(AiAction::Decode) => {
                if let Some(p) = pending {
                    if p.exists() {
                        self.open_path(p);
                    } else {
                        self.status = "AI finished, but no decoded file was written.".to_string();
                    }
                }
            }
            Some(AiAction::Yara) => {
                let rule = strip_fences(&self.ai.output);
                if !rule.trim().is_empty() {
                    self.yara_source = rule;
                    self.status = "AI generated a YARA rule (in the YARA panel)".to_string();
                }
            }
            Some(AiAction::Bt) => {
                let src = strip_fences(&self.ai.output);
                if !src.trim().is_empty() {
                    self.bt_source = src.clone();
                    let a = self.active;
                    if let Some(d) = self.docs.get_mut(a) {
                        let res = hexed_bt::run(&src, d.buffer.data());
                        d.bt_spans.clear();
                        if let Ok(t) = &res {
                            collect_bt_spans(&t.root, &mut d.bt_spans);
                        }
                        d.bt_result = Some(res);
                    }
                    self.status = "AI generated a .bt template and ran it".to_string();
                }
            }
            _ => {} // Explain / Ask / Triage / Disasm: shown in the AI output pane
        }
    }

    /// Assemble the context block sent to Codex: enough for it to reason about
    /// the file, plus the on-disk path so it can read/scan the file itself.
    fn ai_context(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let Some(d) = self.docs.get(self.active) else {
            return s;
        };
        let data = d.buffer.data();
        let _ = writeln!(s, "File: {}", d.file_name);
        match d.buffer.path() {
            Some(p) => {
                let _ = writeln!(
                    s,
                    "Path on disk (you may read/scan this directly): {}",
                    p.display()
                );
            }
            None => {
                let _ = writeln!(s, "Path on disk: (in-memory tab, not saved)");
            }
        }
        let _ = writeln!(s, "Size: {} bytes", data.len());
        if let Some(name) = detect_builtin_name(data) {
            let _ = writeln!(s, "Detected type: {name}");
        }
        if let Some(pe) = &d.pe {
            let _ = writeln!(
                s,
                "PE: {} {}, {} sections, entry RVA 0x{:X}, language {}",
                pe.machine_str(),
                if pe.is_64 { "PE32+" } else { "PE32" },
                pe.sections.len(),
                pe.entry_rva,
                pe.language()
            );
        }
        if let Some((st, en)) = d.selection_range() {
            let cap = (en - st).min(4096);
            let sl = d.buffer.slice(st, st + cap);
            let _ = writeln!(
                s,
                "\nCurrent selection: 0x{st:X}..0x{en:X} ({} bytes)",
                en - st
            );
            let _ = writeln!(s, "Selected bytes (hex): {}", to_hex_string(sl));
            let _ = writeln!(s, "Selected bytes (ascii): {}", to_text(sl));
        }
        if !d.strings.is_empty() {
            let _ = writeln!(s, "\nSample extracted strings:");
            for fs in d.strings.iter().take(40) {
                let _ = writeln!(s, "  0x{:X}: {}", fs.offset, fs.text);
            }
        }
        s
    }

    /// Text view: the file decoded as UTF-8-lossy text in a **wrapping, editable**
    /// multiline editor. Edits are committed back to the byte buffer as one
    /// undoable change when the field loses focus (or on save). Binary
    /// (non-UTF-8) or large files are read-only to avoid corruption / lag.
    fn draw_text(&mut self, ui: &mut egui::Ui) -> (Option<SelUpdate>, Option<(usize, Vec<u8>)>) {
        const EDIT_LIMIT: usize = 1024 * 1024;
        let active = self.active;
        let (len, editable) = match self.docs.get(active) {
            None => {
                ui.centered_and_justified(|ui| {
                    ui.label("Open a file (Ctrl+O) or drop one onto the window.");
                });
                return (None, None);
            }
            Some(d) => (d.buffer.len(), std::str::from_utf8(d.buffer.data()).is_ok()),
        };
        if len == 0 {
            ui.label("(empty file)");
            return (None, None);
        }
        if len > EDIT_LIMIT {
            ui.label(
                egui::RichText::new(format!(
                    "File is {:.1} MB — too large for the text view; use the Hex view.",
                    len as f64 / (1024.0 * 1024.0)
                ))
                .weak(),
            );
            return (None, None);
        }
        // Rebuild the text buffer from bytes when the buffer changed under us
        // (any edit/undo/redo/op bumps generation), unless we hold uncommitted
        // text edits of our own.
        if let Some(d) = self.docs.get_mut(active) {
            if !d.text_dirty && d.buffer.generation() != d.text_gen {
                d.text_buf = String::from_utf8_lossy(d.buffer.data()).into_owned();
                d.text_gen = d.buffer.generation();
            }
        }
        if !editable {
            ui.label(
                egui::RichText::new("binary data — read-only here; edit the bytes in the Hex view")
                    .color(self.palette.warn)
                    .size(11.0),
            );
            ui.add_space(2.0);
        }

        // Syntax colours must be pulled from the palette BEFORE we mutably borrow
        // self.docs below (the layouter captures them by value).
        let colors = highlight::SyntaxColors::from(&self.palette);
        let mut changed = false;
        let mut lost_focus = false;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if let Some(d) = self.docs.get_mut(active) {
                    // Auto-detect the language (extension, else content sniff) and
                    // colour via a layouter — but only for real, not-too-large
                    // UTF-8 text; binaries / huge files render plain.
                    let lang = if editable && d.text_buf.len() <= HL_LIMIT {
                        highlight::detect(&d.file_name, &d.text_buf)
                    } else {
                        highlight::Lang::Plain
                    };
                    let mut layouter = move |ui: &egui::Ui, text: &str, wrap: f32| {
                        let font_bits = egui::TextStyle::Monospace
                            .resolve(ui.style())
                            .size
                            .to_bits();
                        let mut job = ui.ctx().memory_mut(|m| {
                            m.caches
                                .cache::<HighlightCache>()
                                .get((colors, text, lang, font_bits))
                        });
                        job.wrap.max_width = wrap;
                        ui.fonts(|f| f.layout_job(job))
                    };
                    let out = egui::TextEdit::multiline(&mut d.text_buf)
                        .id(egui::Id::new(TEXT_EDIT_ID))
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(30)
                        .interactive(editable)
                        .layouter(&mut layouter)
                        .show(ui);
                    changed = out.response.changed();
                    lost_focus = out.response.lost_focus();

                    // Reveal a pending Find / Goto / click-to-jump target: scroll to
                    // it and (when editable, so egui paints the highlight) select it.
                    // The byte offset maps 1:1 to a text_buf byte offset because the
                    // editable text view requires valid UTF-8; clamp to a char
                    // boundary so slicing can't panic, then count chars for the
                    // char-based cursor. egui does NOT auto-scroll a programmatic
                    // cursor, and focusing the field makes egui scroll the widget to
                    // the top — so we re-assert our own scroll for `text_reveal_ttl`
                    // frames to win that race and land on the match.
                    if let Some((off, len)) = d.text_reveal {
                        if d.text_reveal_ttl > 0 {
                            // Only map the byte offset in the editable view. There
                            // text_buf is the file verbatim (valid UTF-8), so byte
                            // offsets line up 1:1. The read-only view decodes with
                            // from_utf8_lossy, which inserts multi-byte U+FFFD for
                            // each bad byte, so `off` wouldn't map — reveal would
                            // scroll to the wrong place. Binaries: use the hex view.
                            if editable {
                                let s = char_boundary_floor(&d.text_buf, off);
                                let e = char_boundary_floor(&d.text_buf, off.saturating_add(len));
                                let cstart = d.text_buf[..s].chars().count();
                                let cend = d.text_buf[..e].chars().count();
                                let mut st = out.state;
                                st.cursor.set_char_range(Some(egui::text::CCursorRange::two(
                                    egui::text::CCursor::new(cstart),
                                    egui::text::CCursor::new(cend),
                                )));
                                st.store(ui.ctx(), egui::Id::new(TEXT_EDIT_ID));
                                ui.memory_mut(|m| m.request_focus(egui::Id::new(TEXT_EDIT_ID)));
                                let caret = out
                                    .galley
                                    .pos_from_ccursor(egui::text::CCursor::new(cstart))
                                    .translate(out.galley_pos.to_vec2());
                                ui.scroll_to_rect(caret.expand(24.0), Some(egui::Align::Center));
                            }
                            d.text_reveal_ttl -= 1;
                            if d.text_reveal_ttl == 0 {
                                d.text_reveal = None;
                            }
                            ui.ctx().request_repaint();
                        }
                    }
                }
            });

        if editable {
            if changed {
                if let Some(d) = self.docs.get_mut(active) {
                    d.text_dirty = true;
                }
            }
            if lost_focus {
                self.commit_text(active);
            }
        }
        (None, None)
    }

    /// Flush pending text-view edits into the byte buffer as one undoable change.
    fn commit_text(&mut self, active: usize) {
        if let Some(d) = self.docs.get_mut(active) {
            if d.text_dirty {
                let bytes = d.text_buf.clone().into_bytes();
                d.buffer.replace_all(bytes);
                d.text_dirty = false;
                invalidate_derived(d);
                // A text edit rewrites the whole buffer and can change its length,
                // so byte-offset bookmarks past the new end are now invalid — drop
                // them rather than let them jump past EOF.
                let len = d.buffer.len();
                d.bookmarks.retain(|(b, _)| *b < len);
                // text_buf already equals the just-written buffer, so record its
                // generation to avoid a redundant rebuild next frame.
                d.text_gen = d.buffer.generation();
            }
        }
    }

    fn draw_hex(&mut self, ui: &mut egui::Ui) -> (Option<SelUpdate>, Option<(usize, Vec<u8>)>) {
        let active = self.active;
        let Some(doc) = self.docs.get(active) else {
            ui.centered_and_justified(|ui| {
                ui.label("Open a file (Ctrl+O) or drop one onto the window.");
            });
            return (None, None);
        };
        let data = doc.buffer.data();
        let len = data.len();
        if len == 0 {
            ui.label("(empty file)");
            return (None, None);
        }
        // Edit-caret state snapshotted for this frame (byte-editing, 010-style).
        let caret0 = doc.sel_cursor.map(|c| c.min(len - 1));
        let low0 = doc.hex_low_nibble;
        let ascii0 = doc.edit_ascii;
        let font = FontId::monospace(14.0);
        let char_w = ui.fonts(|f| f.glyph_width(&font, '0')).max(7.0);
        let row_h = ui.fonts(|f| f.row_height(&font)).max(15.0);

        // Bytes-per-row: fixed (8/16/32) or "Fit" (0) → derive from width.
        // Layout width is char_w*(13 + 4*bpr); solve for the largest bpr.
        let bpr = if self.bytes_per_row == 0 {
            let avail = (ui.available_width() - 18.0).max(char_w * 20.0);
            ((((avail / char_w) - 13.0) / 4.0).floor() as i64).clamp(4, 256) as usize
        } else {
            self.bytes_per_row.max(1)
        };
        let num_rows = len.div_ceil(bpr);

        let x_hex = 10.0 * char_w;
        let byte_w = 3.0 * char_w;
        let hex_w = bpr as f32 * byte_w;
        let x_ascii = x_hex + hex_w + 2.0 * char_w;
        let total_w = x_ascii + bpr as f32 * char_w + char_w;

        let sel = doc.selection_range();
        let sel_color = self.palette.sel;

        let mut result: Option<SelUpdate> = None;
        // Bytes to carve into a new tab (start offset, bytes), set from the menu.
        let mut carve: Option<(usize, Vec<u8>)> = None;
        // Byte edits typed this frame, and the resulting caret/nibble/pane state.
        let mut edits: Vec<(usize, u8)> = Vec::new();
        let mut new_caret: Option<usize> = None;
        let mut new_low: Option<bool> = None;
        let mut new_ascii: Option<bool> = None;
        let mut scroll_follow: Option<usize> = None;

        let content_h = num_rows as f32 * row_h;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Reserve the full virtual content height (this sets the scroll
                // range) and take one response over it for hit-testing. Use a
                // stable id so keyboard focus (for byte-editing) is identifiable.
                let (rect, _) = ui.allocate_exact_size(vec2(total_w, content_h), Sense::hover());
                let response =
                    ui.interact(rect, egui::Id::new(HEX_GRID_ID), Sense::click_and_drag());
                let ox = rect.left();
                let content_top = rect.top();

                // Programmatic jump — scroll the target row into view via
                // scroll_to_rect (a real scroll target egui honors reliably with
                // virtualized content, unlike vertical_scroll_offset).
                if let Some(off) = doc.scroll_to {
                    let ty = content_top + (off / bpr) as f32 * row_h;
                    ui.scroll_to_rect(
                        Rect::from_min_size(pos2(ox, ty), vec2(total_w, row_h)),
                        Some(egui::Align::Center),
                    );
                }

                // Paint only the rows within the visible clip rect.
                let clip = ui.clip_rect();
                let first = (((clip.top() - content_top) / row_h).floor().max(0.0)) as usize;
                let last = ((((clip.bottom() - content_top) / row_h).ceil()).max(0.0) as usize)
                    .min(num_rows);
                let painter = ui.painter_at(clip);

                // Template field highlights intersecting the visible window.
                let vis_start = first * bpr;
                let vis_end = (last * bpr).min(len);
                let vis_spans: Vec<(usize, usize, Color32)> = doc
                    .bt_spans
                    .iter()
                    .filter(|(s, e, _)| *e > vis_start && *s < vis_end)
                    .copied()
                    .collect();
                let tmpl_bg = |idx: usize| -> Option<Color32> {
                    // Last match wins so a nested field overrides its parent.
                    let mut found = None;
                    for (s, e, c) in &vis_spans {
                        if idx >= *s && idx < *e {
                            found = Some(*c);
                        }
                    }
                    found.map(|c| Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 70))
                };

                // Diff overlay: differing byte runs intersecting the window.
                let vis_diffs: Vec<(usize, usize)> = doc
                    .diff_ranges
                    .iter()
                    .filter(|(s, e)| *e > vis_start && *s < vis_end)
                    .copied()
                    .collect();
                let diff_bg =
                    |idx: usize| -> bool { vis_diffs.iter().any(|(s, e)| idx >= *s && idx < *e) };

                for row in first..last {
                    let y = content_top + row as f32 * row_h;
                    let row_off = row * bpr;
                    painter.text(
                        pos2(ox, y),
                        Align2::LEFT_TOP,
                        format!("{row_off:08X}"),
                        font.clone(),
                        self.palette.faint,
                    );
                    for col in 0..bpr {
                        let idx = row_off + col;
                        if idx >= len {
                            break;
                        }
                        let b = data[idx];
                        let selected = sel.is_some_and(|(s, e)| idx >= s && idx < e);
                        let col_color = byte_color(b, &self.palette);

                        let tbg = tmpl_bg(idx);
                        let dbg = diff_bg(idx);
                        let dc = self.palette.crit;
                        let diff_tint =
                            Color32::from_rgba_unmultiplied(dc.r(), dc.g(), dc.b(), 105);

                        let hx = ox + x_hex + col as f32 * byte_w;
                        let hex_rect = Rect::from_min_size(pos2(hx - 1.0, y), vec2(byte_w, row_h));
                        if let Some(bg) = tbg {
                            painter.rect_filled(hex_rect, 1.0, bg);
                        }
                        if dbg {
                            painter.rect_filled(hex_rect, 1.0, diff_tint);
                        }
                        if selected {
                            painter.rect_filled(hex_rect, 1.0, sel_color);
                        }
                        painter.text(
                            pos2(hx, y),
                            Align2::LEFT_TOP,
                            format!("{b:02X}"),
                            font.clone(),
                            col_color,
                        );

                        let ax = ox + x_ascii + col as f32 * char_w;
                        let ascii_rect = Rect::from_min_size(pos2(ax, y), vec2(char_w, row_h));
                        if let Some(bg) = tbg {
                            painter.rect_filled(ascii_rect, 1.0, bg);
                        }
                        if dbg {
                            painter.rect_filled(ascii_rect, 1.0, diff_tint);
                        }
                        if selected {
                            painter.rect_filled(ascii_rect, 1.0, sel_color);
                        }
                        let ch = if (0x20..=0x7e).contains(&b) {
                            b as char
                        } else {
                            '.'
                        };
                        painter.text(
                            pos2(ax, y),
                            Align2::LEFT_TOP,
                            ch.to_string(),
                            font.clone(),
                            col_color,
                        );
                    }
                }

                // Selection: left-drag = range, single left-click = one byte.
                // React only to drag/click events so a click can't flash a range.
                if let Some(p) = response.interact_pointer_pos() {
                    let row = (((p.y - content_top) / row_h).floor().max(0.0)) as usize;
                    let rel_x = p.x - ox;
                    let col = if rel_x >= x_ascii {
                        (((rel_x - x_ascii) / char_w) as usize).min(bpr - 1)
                    } else if rel_x >= x_hex {
                        (((rel_x - x_hex) / byte_w) as usize).min(bpr - 1)
                    } else {
                        0
                    };
                    let idx = (row * bpr + col).min(len - 1);
                    if response.drag_started_by(egui::PointerButton::Primary) || response.clicked()
                    {
                        result = Some(SelUpdate::Set(idx));
                        // Place the edit caret here: pick the clicked pane, reset
                        // to the high nibble, and take keyboard focus for typing.
                        new_ascii = Some(rel_x >= x_ascii);
                        new_low = Some(false);
                        response.request_focus();
                    } else if response.dragged_by(egui::PointerButton::Primary) {
                        result = Some(SelUpdate::Extend(idx));
                    }
                }

                // ---- keyboard byte-editing (010-style) when the grid is focused ----
                // Require a placed caret (a click sets sel_cursor): a fresh doc has
                // sel_cursor=None, so a stray keystroke can't overwrite its byte 0
                // just because the grid inherited focus from a previous document.
                if response.has_focus() && caret0.is_some() {
                    let mut cur = caret0.unwrap_or(0);
                    let mut low = low0;
                    let mut moved = false;
                    let events = ui.input(|i| i.events.clone());
                    for ev in &events {
                        match ev {
                            egui::Event::Text(t) => {
                                for ch in t.chars() {
                                    if ascii0 {
                                        if (' '..='~').contains(&ch) {
                                            edits.push((cur, ch as u8));
                                            if cur + 1 < len {
                                                cur += 1;
                                            }
                                            moved = true;
                                        }
                                    } else if let Some(hd) = ch.to_digit(16) {
                                        let base = latest_byte(&edits, cur, data);
                                        if !low {
                                            edits.push((cur, (base & 0x0F) | ((hd as u8) << 4)));
                                            low = true;
                                        } else {
                                            edits.push((cur, (base & 0xF0) | hd as u8));
                                            low = false;
                                            if cur + 1 < len {
                                                cur += 1;
                                            }
                                        }
                                        moved = true;
                                    }
                                }
                            }
                            egui::Event::Key {
                                key, pressed: true, ..
                            } => {
                                let step = match key {
                                    egui::Key::ArrowRight => 1i64,
                                    egui::Key::ArrowLeft => -1,
                                    egui::Key::ArrowDown => bpr as i64,
                                    egui::Key::ArrowUp => -(bpr as i64),
                                    _ => 0,
                                };
                                if step != 0 {
                                    cur = (cur as i64 + step).clamp(0, len as i64 - 1) as usize;
                                    low = false;
                                    moved = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    if moved {
                        new_caret = Some(cur);
                        new_low = Some(low);
                        let cr = cur / bpr;
                        if cr < first || cr >= last {
                            scroll_follow = Some(cur); // caret left the viewport
                        }
                    }
                }

                // ---- caret marker (outline the byte being edited) ----
                if response.has_focus() {
                    if let Some(ci) = new_caret.or(caret0) {
                        let row = ci / bpr;
                        let col = ci % bpr;
                        let y = content_top + row as f32 * row_h;
                        let active_pane_ascii = new_ascii.unwrap_or(ascii0);
                        let hx = ox + x_hex + col as f32 * byte_w;
                        let ax = ox + x_ascii + col as f32 * char_w;
                        let hex_rect = Rect::from_min_size(pos2(hx - 1.0, y), vec2(byte_w, row_h));
                        let asc_rect =
                            Rect::from_min_size(pos2(ax - 1.0, y), vec2(char_w + 1.0, row_h));
                        let strong = egui::Stroke::new(1.5, self.palette.accent);
                        let faint = egui::Stroke::new(1.0, self.palette.faint);
                        painter.rect_stroke(
                            hex_rect,
                            1.0,
                            if active_pane_ascii { faint } else { strong },
                            egui::StrokeKind::Inside,
                        );
                        painter.rect_stroke(
                            asc_rect,
                            1.0,
                            if active_pane_ascii { strong } else { faint },
                            egui::StrokeKind::Inside,
                        );
                    }
                }

                // right-click: 010-style "Copy As" menu on the current selection.
                response.context_menu(|ui| match sel {
                    Some((s, e)) => {
                        let d = &data[s.min(len)..e.min(len)];
                        if ui.button("Copy as Hex").clicked() {
                            ui.ctx().copy_text(to_hex_string(d));
                            ui.close_menu();
                        }
                        if ui.button("Copy as Text").clicked() {
                            ui.ctx().copy_text(to_text(d));
                            ui.close_menu();
                        }
                        if ui.button("Copy as YARA hex").clicked() {
                            ui.ctx().copy_text(to_yara_hex(d));
                            ui.close_menu();
                        }
                        if ui.button("Copy as base64").clicked() {
                            ui.ctx().copy_text(to_base64(d));
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .button("Open selection in new tab")
                            .on_hover_text(format!(
                                "carve these {} bytes into a new in-memory tab",
                                d.len()
                            ))
                            .clicked()
                        {
                            carve = Some((s, d.to_vec()));
                            ui.close_menu();
                        }
                        if ui
                            .button("Save selection to file…")
                            .on_hover_text(format!("write these {} bytes to a file", d.len()))
                            .clicked()
                        {
                            let default = format!("selection_0x{s:X}_{}b.bin", d.len());
                            if let Some(path) =
                                rfd::FileDialog::new().set_file_name(default).save_file()
                            {
                                let _ = std::fs::write(path, d);
                            }
                            ui.close_menu();
                        }
                    }
                    None => {
                        ui.label("Select bytes first");
                    }
                });
            });

        // Apply the frame's byte edits + caret/nibble/pane changes to the doc.
        if let Some(d) = self.docs.get_mut(active) {
            if !edits.is_empty() {
                for (off, b) in &edits {
                    d.buffer.overwrite(*off, &[*b]);
                }
                // Defer the expensive re-analysis: reset the debounce so it fires
                // once, shortly after typing stops, instead of every keystroke.
                // (The text view refreshes immediately via buffer.generation().)
                d.derived_ttl = EDIT_RESCAN_DELAY;
            }
            if let Some(c) = new_caret {
                d.sel_anchor = Some(c);
                d.sel_cursor = Some(c);
            }
            if let Some(l) = new_low {
                d.hex_low_nibble = l;
            }
            if let Some(a2) = new_ascii {
                d.edit_ascii = a2;
            }
            if let Some(off) = scroll_follow {
                d.scroll_to = Some(off);
                d.scroll_ttl = 4;
            }
        }

        (result, carve)
    }
}

/// Stable egui id for the hex grid's interaction/focus target, so the keyboard
/// handler can tell "editing bytes in the grid" from "typing in a text field".
const HEX_GRID_ID: &str = "hexed_hex_grid";

/// Stable egui id for the editable Text-view field. A `TextEdit`'s auto id is
/// structural (identical across documents, since `draw_text` is one code path),
/// so its keyboard focus would otherwise persist onto a document the user never
/// clicked into after a keyboard-driven active-doc change (⌘W / ⌘O). Pinning the
/// id lets `update()` surrender that focus on every switch, just like the grid.
const TEXT_EDIT_ID: &str = "hexed_text_edit";

/// Frames of no-typing after a byte edit before the heavy re-analysis (strings,
/// PE, IOC, YARA, hashes, …) runs. ~0.25 s at 60 fps — long enough to coalesce a
/// burst of keystrokes into a single rescan, short enough to feel responsive.
const EDIT_RESCAN_DELAY: u32 = 15;

/// The latest value of the byte at `off` given edits queued this frame (so the
/// second hex nibble sees the first). Falls back to the buffer's current byte.
fn latest_byte(edits: &[(usize, u8)], off: usize, data: &[u8]) -> u8 {
    edits
        .iter()
        .rev()
        .find(|(o, _)| *o == off)
        .map(|(_, b)| *b)
        .unwrap_or(data[off])
}

/// Render one `.bt` results-tree node. Leaves are clickable (jump to their
/// bytes); struct/array nodes are collapsible with a jump button in the header.
fn show_bt_node(ui: &mut egui::Ui, node: &hexed_bt::Node, jump_to: &mut Option<(usize, usize)>) {
    let sz = node.size.max(1);
    if node.children.is_empty() {
        let text = format!("{}: {} = {}", node.name, node.type_name, node.display);
        let resp = ui
            .selectable_label(false, egui::RichText::new(text).monospace())
            .on_hover_text(format!("offset 0x{:X} · {} bytes", node.offset, node.size));
        if resp.clicked() {
            *jump_to = Some((node.offset, sz));
        }
    } else {
        let header = format!("{}: {}", node.name, node.type_name);
        egui::CollapsingHeader::new(egui::RichText::new(header).monospace())
            .id_salt((node.offset, node.size, node.name.as_str()))
            .show(ui, |ui| {
                if ui
                    .small_button(format!("goto 0x{:X}", node.offset))
                    .on_hover_text(format!("{} bytes", node.size))
                    .clicked()
                {
                    *jump_to = Some((node.offset, sz));
                }
                for child in &node.children {
                    show_bt_node(ui, child, jump_to);
                }
            });
    }
}

/// Flatten a template's colored nodes into byte spans for the hex grid. Emits
/// parents before children (pre-order) so a nested field's color wins.
fn collect_bt_spans(nodes: &[hexed_bt::Node], out: &mut Vec<(usize, usize, Color32)>) {
    for n in nodes {
        if let Some(rgb) = n.color {
            let c = Color32::from_rgb(
                ((rgb >> 16) & 0xFF) as u8,
                ((rgb >> 8) & 0xFF) as u8,
                (rgb & 0xFF) as u8,
            );
            out.push((n.offset, n.offset + n.size, c));
        }
        collect_bt_spans(&n.children, out);
    }
}

/// Build a paste-ready plaintext triage summary of a PE.
fn build_pe_report(file_name: &str, data: &[u8], pe: &PeInfo) -> String {
    use std::fmt::Write;
    let h = hash_all(data);
    let mut s = String::new();
    let _ = writeln!(s, "# {file_name}  ({} bytes)", data.len());
    let _ = writeln!(s, "MD5:    {}", h.md5);
    let _ = writeln!(s, "SHA1:   {}", h.sha1);
    let _ = writeln!(s, "SHA256: {}", h.sha256);
    let _ = writeln!(s, "CRC32:  {:08X}", h.crc32);
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "PE: {} ({})   language: {}   compiler: {}",
        pe.machine_str(),
        if pe.is_64 { "PE32+" } else { "PE32" },
        pe.language(),
        pe.compiler_str()
    );
    let _ = writeln!(s, "compiled: {}", pe.timestamp_str());
    let _ = writeln!(s, "image base: 0x{:X}", pe.image_base);
    let entry = pe
        .entry_offset()
        .map(|o| format!(" (file 0x{o:X})"))
        .unwrap_or_default();
    let _ = writeln!(s, "entry: RVA 0x{:X}{}", pe.entry_rva, entry);
    if pe.is_packed() {
        let _ = writeln!(
            s,
            "PACKED: {}",
            pe.packer
                .clone()
                .unwrap_or_else(|| "likely (high entropy)".to_string())
        );
    }
    let _ = writeln!(s, "\nSections ({}):", pe.sections.len());
    for sec in &pe.sections {
        let _ = writeln!(
            s,
            "  {:<8} raw 0x{:<7X} vsize 0x{:<7X} {:<3} entropy {:.2}",
            sec.name,
            sec.raw_ptr,
            sec.virtual_size,
            sec.perms(),
            sec.entropy
        );
    }
    let total: usize = pe.imports.iter().map(|i| i.funcs.len()).sum();
    let _ = writeln!(
        s,
        "\nImports ({} DLLs, {} functions):",
        pe.imports.len(),
        total
    );
    for imp in &pe.imports {
        let _ = writeln!(s, "  {}:", imp.dll);
        for f in &imp.funcs {
            let _ = writeln!(s, "    {f}");
        }
    }
    if !pe.exports.is_empty() {
        let _ = writeln!(s, "\nExports ({}):", pe.exports.len());
        for ex in &pe.exports {
            let _ = writeln!(s, "  #{:<5} {}", ex.ordinal, ex.name);
        }
    }
    s
}

/// Aggregate everything the triage panels know into one Markdown report:
/// hashes (+imphash), entropy, PE summary with per-section MD5, flagged APIs,
/// IOCs (defanged), embedded files, and crypto signatures.
fn build_triage_report(d: &Document, vt: Option<&vt::VtVerdict>) -> String {
    use std::fmt::Write;
    let data = d.buffer.data();
    let h = hash_all(data);
    let mut s = String::new();
    let _ = writeln!(s, "# Triage — {}", d.file_name);
    let _ = writeln!(s, "_generated {}_\n", today_ymd());
    let _ = writeln!(s, "- size: {} bytes", data.len());
    let _ = writeln!(s, "- MD5: `{}`", h.md5);
    let _ = writeln!(s, "- SHA1: `{}`", h.sha1);
    let _ = writeln!(s, "- SHA256: `{}`", h.sha256);
    let _ = writeln!(s, "- CRC32: `{:08X}`", h.crc32);
    if !d.imphash.is_empty() {
        let _ = writeln!(s, "- imphash: `{}`", d.imphash);
    }
    let overall = shannon_entropy(data);
    let hi = if overall > 7.2 {
        "  HIGH (packed/encrypted)"
    } else {
        ""
    };
    let _ = writeln!(s, "- entropy: {overall:.2} bits/byte{hi}");
    // VirusTotal reputation — only when enrichment is opted in and a result exists.
    if let Some(v) = vt {
        if v.error.is_none() {
            if v.not_found {
                let _ = writeln!(s, "- VirusTotal: not seen");
            } else {
                let det = v.malicious + v.suspicious;
                let label = v
                    .label
                    .as_deref()
                    .map(|l| format!(" · {l}"))
                    .unwrap_or_default();
                let seen = v
                    .first_seen
                    .as_deref()
                    .map(|f| format!(" · first seen {f}"))
                    .unwrap_or_default();
                let _ = writeln!(s, "- VirusTotal: {det}/{} detected{label}{seen}", v.total);
            }
        }
    }

    if let Some(pe) = &d.pe {
        let _ = writeln!(s, "\n## PE");
        let _ = writeln!(
            s,
            "- arch: {} ({})",
            pe.machine_str(),
            if pe.is_64 { "PE32+" } else { "PE32" }
        );
        let _ = writeln!(
            s,
            "- language: {}   compiler: {}",
            pe.language(),
            pe.compiler_str()
        );
        let _ = writeln!(s, "- compiled: {}", pe.timestamp_str());
        if pe.is_packed() {
            let _ = writeln!(
                s,
                "- **packed**: {}",
                pe.packer
                    .clone()
                    .unwrap_or_else(|| "likely (high entropy)".into())
            );
        }
        let _ = writeln!(s, "- sections ({}):", pe.sections.len());
        for sec in &pe.sections {
            let start = (sec.raw_ptr as usize).min(data.len());
            let end = start.saturating_add(sec.raw_size as usize).min(data.len());
            let md5 = md5_hex(&data[start..end]);
            let _ = writeln!(
                s,
                "  - `{:<8}` {:<3} entropy {:.2}  md5 {md5}",
                sec.name,
                sec.perms(),
                sec.entropy
            );
        }
    }

    if !d.api_flags.is_empty() {
        let _ = writeln!(s, "\n## Flagged APIs ({})", d.api_flags.len());
        let mut cats: Vec<&str> = d.api_flags.iter().map(|f| f.category).collect();
        cats.sort_unstable();
        cats.dedup();
        for cat in cats {
            let apis: Vec<&str> = d
                .api_flags
                .iter()
                .filter(|f| f.category == cat)
                .map(|f| f.api.as_str())
                .collect();
            let _ = writeln!(s, "- **{cat}**: {}", apis.join(", "));
        }
    }

    if !d.iocs.is_empty() {
        let _ = writeln!(s, "\n## IOCs ({}) — defanged", d.iocs.len());
        for kind in IOC_KINDS {
            let group: Vec<&Ioc> = d.iocs.iter().filter(|i| i.kind == *kind).collect();
            if group.is_empty() {
                continue;
            }
            let _ = writeln!(s, "\n### {} ({})", kind.label(), group.len());
            for ioc in group {
                let _ = writeln!(s, "- `{}`  (0x{:X})", defang(&ioc.value), ioc.offset);
            }
        }
    }

    if !d.embedded.is_empty() {
        let _ = writeln!(s, "\n## Embedded files ({})", d.embedded.len());
        for e in &d.embedded {
            let sz = e.size.map(|s| format!(" ({s} B)")).unwrap_or_default();
            let _ = writeln!(s, "- 0x{:X}  {}{}", e.offset, e.kind, sz);
        }
    }

    if !d.sig_hits.is_empty() {
        let _ = writeln!(s, "\n## Signatures ({})", d.sig_hits.len());
        for hh in &d.sig_hits {
            let _ = writeln!(s, "- 0x{:X}  {} — {}", hh.offset, hh.name, hh.note);
        }
    }

    let _ = writeln!(s, "\n## Strings\n- {} printable strings", d.strings.len());
    s
}

/// Heat scale for the entropy strip: blue (low) → green → red (high/packed).
fn entropy_color(e: f32) -> Color32 {
    let t = (e / 8.0).clamp(0.0, 1.0);
    let (r, g, b) = if t < 0.5 {
        let u = t * 2.0;
        (0.0, u, 1.0 - u)
    } else {
        let u = (t - 0.5) * 2.0;
        (u, 1.0 - u, 0.0)
    };
    Color32::from_rgb((r * 230.0) as u8, (g * 200.0) as u8, (b * 230.0) as u8)
}

/// Render a 256-bin byte histogram as a compact bar chart (log-scaled so a
/// dominant value like 0x00 padding doesn't flatten everything else).
fn draw_histogram(ui: &mut egui::Ui, hist: &Histogram, pal: &Palette) {
    let height = 84.0;
    let (rect, _resp) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, pal.bg);
    let max = hist.max_count().max(1) as f32;
    let ln_max = (1.0 + max).ln();
    let bar_w = rect.width() / 256.0;
    for i in 0..256usize {
        let c = hist.counts[i] as f32;
        if c <= 0.0 {
            continue;
        }
        let frac = (1.0 + c).ln() / ln_max;
        let bh = frac * (height - 3.0);
        let x = rect.left() + i as f32 * bar_w;
        let bar = Rect::from_min_max(
            pos2(x, rect.bottom() - bh),
            pos2(x + bar_w.max(1.0), rect.bottom()),
        );
        painter.rect_filled(bar, 0.0, byte_color(i as u8, pal));
    }
}

fn byte_color(b: u8, p: &Palette) -> Color32 {
    match b {
        0x00 => p.b_zero,
        0x09 | 0x0a | 0x0d => p.b_ctrl,
        0x20..=0x7e => p.b_print,
        0xff => p.b_high,
        _ => p.b_other,
    }
}

/// Locate the `upx` binary. Checks common install paths first so a
/// Finder-launched `.app` (which has a minimal PATH) still finds Homebrew's upx,
/// then falls back to the PATH.
fn upx_command() -> std::process::Command {
    for p in [
        "/opt/homebrew/bin/upx",
        "/usr/local/bin/upx",
        "/usr/bin/upx",
    ] {
        if std::path::Path::new(p).exists() {
            return std::process::Command::new(p);
        }
    }
    std::process::Command::new("upx")
}

/// Parse a `#RRGGBB` or `#RRGGBBAA` color string into a Color32.
fn parse_color_hex(s: &str) -> Option<Color32> {
    let h = s.strip_prefix('#')?;
    let byte = |i: usize| u8::from_str_radix(h.get(i..i + 2)?, 16).ok();
    match h.len() {
        6 => Some(Color32::from_rgb(byte(0)?, byte(2)?, byte(4)?)),
        8 => Some(Color32::from_rgba_unmultiplied(
            byte(0)?,
            byte(2)?,
            byte(4)?,
            byte(6)?,
        )),
        _ => None,
    }
}

/// Parse a hex replacement into concrete bytes: `"90 90"` or `"9090"`.
/// Rejects wildcards and odd-length input (a replacement must be exact bytes).
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) || cleaned.contains('?') {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

/// Parse an integer in any base: `0x1F` (hex), `0b1010` (bin), `0o17` (oct),
/// else decimal.
fn parse_multibase(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        u64::from_str_radix(b, 2).ok()
    } else if let Some(o) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        u64::from_str_radix(o, 8).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

/// Parse a Goto address: `0x1F` / `1F` (hex) or `31` (decimal).
fn parse_offset(s: &str) -> Option<usize> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        usize::from_str_radix(h, 16).ok()
    } else if let Ok(d) = t.parse::<usize>() {
        Some(d)
    } else {
        usize::from_str_radix(t, 16).ok()
    }
}

/// A name + read-only selectable monospace value + a one-click copy button,
/// as one 3-column grid row.
fn hash_row(ui: &mut egui::Ui, name: &str, value: &str) {
    ui.monospace(name);
    let mut v = value.to_string();
    ui.add(
        egui::TextEdit::singleline(&mut v)
            .font(egui::TextStyle::Monospace)
            .desired_width(240.0),
    );
    if ui
        .small_button("copy")
        .on_hover_text(format!("copy {name}"))
        .clicked()
    {
        ui.ctx().copy_text(value.to_string());
    }
    ui.end_row();
}
