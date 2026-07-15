//! macOS "Open With" support.
//!
//! When a file is opened via Finder's *Open With → Hexed*, double-clicked with
//! Hexed as its handler, or dropped on the app icon, macOS delivers a
//! `kAEOpenDocuments` ('odoc') Apple Event — **not** command-line arguments.
//! eframe/winit own the `NSApplication` delegate and don't surface this event,
//! so we register our own handler with `NSAppleEventManager` (additive — it
//! doesn't disturb winit's delegate) and stash the resulting paths in a queue
//! the UI drains each frame. Requires `CFBundleDocumentTypes` in the bundle's
//! Info.plist so Launch Services offers Hexed and sends the event.

#[cfg(target_os = "macos")]
mod imp {
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    use eframe::egui;
    use objc2::rc::Retained;
    use objc2::runtime::NSObject;
    use objc2::{declare_class, msg_send, msg_send_id, mutability, sel, ClassType, DeclaredClass};
    use objc2_foundation::{
        NSAppleEventDescriptor, NSAppleEventManager, NSNotificationCenter, NSString, NSURL,
    };

    /// Files delivered by 'odoc' events, waiting to be opened by the UI.
    static PENDING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    /// egui context, so the Apple Event handler can wake the UI to drain.
    static CTX: OnceLock<egui::Context> = OnceLock::new();

    /// Build a four-char-code (OSType) from a 4-byte tag.
    const fn fourcc(t: &[u8; 4]) -> u32 {
        ((t[0] as u32) << 24) | ((t[1] as u32) << 16) | ((t[2] as u32) << 8) | (t[3] as u32)
    }

    declare_class!(
        struct AeHandler;

        unsafe impl ClassType for AeHandler {
            type Super = NSObject;
            type Mutability = mutability::InteriorMutable;
            const NAME: &'static str = "HexedAppleEventHandler";
        }

        impl DeclaredClass for AeHandler {}

        unsafe impl AeHandler {
            #[method(handleAppleEvent:withReplyEvent:)]
            fn handle_apple_event(
                &self,
                event: &NSAppleEventDescriptor,
                _reply: &NSAppleEventDescriptor,
            ) {
                unsafe { collect_paths(event) };
            }

            // Invoked from NSApplicationWillFinishLaunchingNotification — the
            // Apple-recommended point to (re)install AE handlers so ours overrides
            // AppKit's default in time for a cold-launch "Open With" document.
            #[method(installOdocHandler:)]
            fn install_odoc_handler(&self, _notification: &NSObject) {
                unsafe { register_odoc(self) };
            }
        }
    );

    /// Point the shared Apple Event manager's 'odoc' handler at `handler`.
    unsafe fn register_odoc(handler: &AeHandler) {
        const K_CORE_EVENT_CLASS: u32 = fourcc(b"aevt");
        const K_AE_OPEN_DOCUMENTS: u32 = fourcc(b"odoc");
        let mgr = NSAppleEventManager::sharedAppleEventManager();
        let selector = sel!(handleAppleEvent:withReplyEvent:);
        let _: () = msg_send![
            &mgr,
            setEventHandler: handler,
            andSelector: selector,
            forEventClass: K_CORE_EVENT_CLASS,
            andEventID: K_AE_OPEN_DOCUMENTS,
        ];
    }

    /// Extract file paths from an 'odoc' Apple Event's direct object and queue
    /// them, then nudge the UI to repaint so it drains the queue promptly.
    unsafe fn collect_paths(event: &NSAppleEventDescriptor) {
        const KEY_DIRECT_OBJECT: u32 = fourcc(b"----");
        // `paramDescriptorForKeyword:` isn't in the generated bindings — call raw.
        let direct: Option<Retained<NSAppleEventDescriptor>> =
            msg_send_id![event, paramDescriptorForKeyword: KEY_DIRECT_OBJECT];
        let Some(direct) = direct else { return };

        let mut paths = Vec::new();
        let n = direct.numberOfItems();
        if n >= 1 {
            // A list descriptor: one file per (1-based) item.
            for i in 1..=n {
                if let Some(item) = direct.descriptorAtIndex(i) {
                    if let Some(p) = url_path(&item) {
                        paths.push(p);
                    }
                }
            }
        } else if let Some(p) = url_path(&direct) {
            // A single, non-list file descriptor.
            paths.push(p);
        }

        if !paths.is_empty() {
            if let Ok(mut q) = PENDING.lock() {
                q.extend(paths);
            }
            if let Some(ctx) = CTX.get() {
                ctx.request_repaint();
            }
        }
    }

    /// Coerce a descriptor to a file URL and read its filesystem path.
    unsafe fn url_path(desc: &NSAppleEventDescriptor) -> Option<PathBuf> {
        let url: Retained<NSURL> = desc.fileURLValue()?;
        let path: Retained<NSString> = url.path()?;
        Some(PathBuf::from(path.to_string()))
    }

    /// Register the 'odoc' handler. Call once, early on the main thread — ideally
    /// the FIRST thing in `main()`, before `eframe::run_native`, so the
    /// willFinishLaunching observer is in place for a cold-launch document.
    /// [`set_context`] wires the repaint nudge once egui exists.
    pub fn install() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        if INSTALLED.set(()).is_err() {
            return; // already installed
        }
        unsafe {
            let handler: Retained<AeHandler> = msg_send_id![AeHandler::class(), new];
            // Install now for the already-running / late-launch case...
            register_odoc(&handler);
            // ...and again at applicationWillFinishLaunching, which fires during a
            // cold launch AFTER AppKit installs its own default 'odoc' handler but
            // BEFORE the launch document is delivered — so ours wins and the file
            // actually opens instead of erroring "cannot open files in the X
            // format". (Installing only in the eframe setup closure races the
            // launch event and loses it about half the time.)
            let center = NSNotificationCenter::defaultCenter();
            let name = NSString::from_str("NSApplicationWillFinishLaunchingNotification");
            let _: () = msg_send![
                &center,
                addObserver: &*handler,
                selector: sel!(installOdocHandler:),
                name: &*name,
                object: Option::<&NSObject>::None,
            ];
            // Both the AE manager and the notification center keep only weak
            // references — leak the handler so it lives for the whole process.
            std::mem::forget(handler);
        }
    }

    /// Wire the egui context so the handler can nudge a repaint when a file
    /// arrives. Optional: the UI also drains the queue every frame regardless.
    pub fn set_context(ctx: &egui::Context) {
        let _ = CTX.set(ctx.clone());
    }

    /// Take any files delivered since the last call (drains the queue).
    pub fn take_pending() -> Vec<PathBuf> {
        PENDING
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }
}

#[cfg(target_os = "macos")]
pub use imp::{install, set_context, take_pending};

#[cfg(not(target_os = "macos"))]
pub fn install() {}

#[cfg(not(target_os = "macos"))]
pub fn set_context(_ctx: &eframe::egui::Context) {}

#[cfg(not(target_os = "macos"))]
pub fn take_pending() -> Vec<std::path::PathBuf> {
    Vec::new()
}
