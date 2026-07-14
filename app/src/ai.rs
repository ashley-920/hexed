//! Bridge to the `codex` CLI (`codex exec`) for AI-assisted analysis.
//!
//! Runs Codex non-interactively in a background thread so the UI never blocks,
//! piping analysis context on stdin and reading the agent's final answer back
//! via `--output-last-message`. `CODEX_HOME` is set from `$CODEX_WORK_HOME` to
//! mirror the user's `codex-work` shell function. Because the prompt includes
//! the file's on-disk path, Codex can read it and run its own tooling — the
//! sandbox mode gates whether it may also write.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::OnceLock;

/// Cap on piped context so a huge selection can't stall the stdin write.
const MAX_CONTEXT: usize = 48 * 1024;

/// Locate the `codex` binary. A Finder-launched `.app` has a minimal PATH, so
/// check the usual install locations before falling back to PATH.
fn codex_bin() -> std::path::PathBuf {
    for p in ["/opt/homebrew/bin/codex", "/usr/local/bin/codex", "/usr/bin/codex"] {
        if std::path::Path::new(p).exists() {
            return std::path::PathBuf::from(p);
        }
    }
    std::path::PathBuf::from("codex")
}

/// Resolve `$CODEX_WORK_HOME` (the separate CODEX_HOME the `codex-work` function
/// uses). Read from the env if present, else ask a login+interactive shell —
/// necessary because a `.app` doesn't inherit the shell environment. Cached.
fn codex_home() -> Option<std::ffi::OsString> {
    static HOME: OnceLock<Option<std::ffi::OsString>> = OnceLock::new();
    HOME.get_or_init(|| {
        if let Some(h) = std::env::var_os("CODEX_WORK_HOME") {
            return Some(h);
        }
        let out = Command::new("zsh")
            .arg("-ic")
            .arg("printf %s \"$CODEX_WORK_HOME\"")
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let s = s.trim();
        (!s.is_empty()).then(|| std::ffi::OsString::from(s))
    })
    .clone()
}

enum AiEvent {
    Done(String),
    Failed(String),
}

/// Result of draining the worker channel in the UI loop.
pub enum Poll {
    /// No run in flight.
    Idle,
    /// A run is still executing (caller should request a repaint).
    Running,
    /// A run just finished this frame (caller should route the output).
    JustDone,
}

#[derive(Default)]
pub struct Ai {
    /// Free-form user prompt (bound to the panel's text box).
    pub prompt: String,
    /// Last result or error, for display.
    pub output: String,
    /// A short label of what's running / last ran (e.g. "explain selection").
    pub label: String,
    pub running: bool,
    /// Whether the most recent run succeeded (for output routing).
    pub last_ok: bool,
    /// Sandbox: false = read-only, true = workspace-write (decode-and-write).
    pub allow_write: bool,
    rx: Option<Receiver<AiEvent>>,
}

impl Ai {
    /// Whether the `codex` CLI is present. Deliberately a passive filesystem
    /// check — never spawns a process at startup (spawning a child at launch can
    /// trigger macOS "wants to access…" prompts). A subprocess only runs when
    /// the user explicitly invokes an AI action.
    pub fn available() -> bool {
        let bin = codex_bin();
        bin.is_absolute() && bin.exists()
    }

    /// Drain the worker channel, reporting whether a run is idle/running/just
    /// finished so the caller can route the output on completion.
    pub fn poll(&mut self) -> Poll {
        let Some(rx) = &self.rx else {
            return Poll::Idle;
        };
        match rx.try_recv() {
            Ok(AiEvent::Done(s)) => {
                self.output = s;
                self.last_ok = true;
                self.running = false;
                self.rx = None;
                Poll::JustDone
            }
            Ok(AiEvent::Failed(e)) => {
                self.output = format!("Error: {e}");
                self.last_ok = false;
                self.running = false;
                self.rx = None;
                Poll::JustDone
            }
            Err(TryRecvError::Empty) => Poll::Running,
            Err(TryRecvError::Disconnected) => {
                self.running = false;
                self.rx = None;
                Poll::JustDone
            }
        }
    }

    /// Launch a `codex exec` run with `instructions` and piped `context`.
    /// `write` selects the sandbox (workspace-write vs read-only). No-op if a
    /// run is already in flight.
    pub fn run(&mut self, label: impl Into<String>, instructions: String, context: String, write: bool) {
        if self.running {
            return;
        }
        self.running = true;
        self.label = label.into();
        self.output.clear();
        let (tx, rx) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(run_codex(&instructions, &context, write));
        });
    }
}

fn run_codex(instructions: &str, context: &str, allow_write: bool) -> AiEvent {
    let out_file = std::env::temp_dir().join(format!("hexed_ai_{}.txt", std::process::id()));
    let mut cmd = Command::new(codex_bin());
    cmd.arg("exec")
        .arg("--skip-git-repo-check")
        .arg("-s")
        .arg(if allow_write { "workspace-write" } else { "read-only" })
        .arg("--output-last-message")
        .arg(&out_file);
    // Mirror the `codex-work` shell function's separate CODEX_HOME.
    if let Some(home) = codex_home() {
        cmd.env("CODEX_HOME", home);
    }
    cmd.arg(instructions)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return AiEvent::Failed(format!(
                "could not launch codex ({e}). Install it and run `codex login`."
            ))
        }
    };

    if let Some(mut si) = child.stdin.take() {
        let mut ctx = context.as_bytes();
        if ctx.len() > MAX_CONTEXT {
            ctx = &ctx[..MAX_CONTEXT];
        }
        let _ = si.write_all(ctx);
        // `si` drops here, closing stdin so the agent sees EOF.
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return AiEvent::Failed(format!("codex run failed: {e}")),
    };

    let answer = std::fs::read_to_string(&out_file)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| String::from_utf8_lossy(&output.stdout).into_owned());
    let _ = std::fs::remove_file(&out_file);

    if answer.trim().is_empty() {
        let err = String::from_utf8_lossy(&output.stderr);
        AiEvent::Failed(if err.trim().is_empty() {
            "codex returned no output".to_string()
        } else {
            err.trim().to_string()
        })
    } else {
        AiEvent::Done(answer)
    }
}
