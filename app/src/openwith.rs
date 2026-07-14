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
    use objc2_foundation::{NSAppleEventDescriptor, NSAppleEventManager, NSString, NSURL};

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
        }
    );

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

    /// Register the 'odoc' handler with the shared Apple Event manager. Safe to
    /// call once, early on the main thread (e.g. the eframe creation closure).
    pub fn install(ctx: &egui::Context) {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        if INSTALLED.set(()).is_err() {
            return; // already installed
        }
        let _ = CTX.set(ctx.clone());

        const K_CORE_EVENT_CLASS: u32 = fourcc(b"aevt");
        const K_AE_OPEN_DOCUMENTS: u32 = fourcc(b"odoc");
        unsafe {
            let handler: Retained<AeHandler> = msg_send_id![AeHandler::class(), new];
            let mgr = NSAppleEventManager::sharedAppleEventManager();
            let selector = sel!(handleAppleEvent:withReplyEvent:);
            let _: () = msg_send![
                &mgr,
                setEventHandler: &*handler,
                andSelector: selector,
                forEventClass: K_CORE_EVENT_CLASS,
                andEventID: K_AE_OPEN_DOCUMENTS,
            ];
            // The manager keeps only a weak reference — leak the handler so it
            // lives for the whole process.
            std::mem::forget(handler);
        }
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
pub use imp::{install, take_pending};

#[cfg(not(target_os = "macos"))]
pub fn install(_ctx: &eframe::egui::Context) {}

#[cfg(not(target_os = "macos"))]
pub fn take_pending() -> Vec<std::path::PathBuf> {
    Vec::new()
}
