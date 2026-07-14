//! Minimal, defensive PE (Portable Executable) structure parser — just enough
//! to navigate to sections and key headers. Not a validator; every field read
//! is bounds-checked because it runs on hostile / truncated files.

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read a bounded NUL-terminated ASCII string at `off`.
fn read_cstr(data: &[u8], off: usize) -> String {
    data.get(off..)
        .map(|rest| {
            rest.iter()
                .take_while(|&&b| b != 0)
                .take(256)
                .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
                .collect()
        })
        .unwrap_or_default()
}

/// Translate an RVA to a file offset using the section table.
fn rva_to_off(sections: &[PeSection], rva: u32) -> Option<usize> {
    for s in sections {
        let span = s.virtual_size.max(s.raw_size);
        let end = s.virtual_addr.saturating_add(span);
        if rva >= s.virtual_addr && rva < end {
            return Some((s.raw_ptr + (rva - s.virtual_addr)) as usize);
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_addr: u32,
    pub raw_size: u32,
    /// File offset of the section's raw data (PointerToRawData).
    pub raw_ptr: u32,
    pub characteristics: u32,
    /// Shannon entropy of the section's raw bytes (0.0..=8.0).
    pub entropy: f64,
}

impl PeSection {
    /// Section memory permissions as an "RWX"-style string.
    pub fn perms(&self) -> String {
        let mut s = String::new();
        if self.characteristics & 0x4000_0000 != 0 {
            s.push('R');
        }
        if self.characteristics & 0x8000_0000 != 0 {
            s.push('W');
        }
        if self.characteristics & 0x2000_0000 != 0 {
            s.push('X');
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct PeImport {
    pub dll: String,
    pub funcs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PeExport {
    pub name: String,
    pub ordinal: u32,
    /// Function RVA (or forwarder-string RVA).
    pub rva: u32,
}

#[derive(Clone, Debug)]
pub struct PeInfo {
    pub is_64: bool,
    pub machine: u16,
    /// File offset of the PE signature (e_lfanew).
    pub nt_offset: usize,
    pub entry_rva: u32,
    pub image_base: u64,
    /// COFF TimeDateStamp (Unix seconds).
    pub timestamp: u32,
    pub linker_major: u8,
    pub linker_minor: u8,
    /// Has a CLR/.NET runtime header (data directory 14).
    pub is_dotnet: bool,
    /// Detected packer from section-name signatures, if any.
    pub packer: Option<String>,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<PeExport>,
}

impl PeInfo {
    /// File offset of the entry point, if its RVA falls inside a section.
    pub fn entry_offset(&self) -> Option<usize> {
        self.rva_to_offset(self.entry_rva)
    }

    /// Translate a relative virtual address to a file offset via the section
    /// table.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        rva_to_off(&self.sections, rva)
    }

    pub fn machine_str(&self) -> &'static str {
        match self.machine {
            0x014C => "x86",
            0x8664 => "x64",
            0xAA64 => "ARM64",
            0x01C0 | 0x01C4 => "ARM",
            _ => "unknown",
        }
    }

    pub fn timestamp_str(&self) -> String {
        if self.timestamp == 0 {
            "(none)".to_string()
        } else {
            format!("{} UTC", crate::inspect::format_unix(self.timestamp as i64))
        }
    }

    /// Best-effort source language / runtime.
    pub fn language(&self) -> &'static str {
        if self.is_dotnet {
            return ".NET (C#/VB)";
        }
        for s in &self.sections {
            if s.name.contains("go.buildinfo") || s.name == ".gosymtab" || s.name == ".gopclntab" {
                return "Go";
            }
        }
        "native (C/C++)"
    }

    /// Rough compiler guess from the linker version.
    pub fn compiler_str(&self) -> String {
        if self.is_dotnet {
            return "MSIL / Roslyn".to_string();
        }
        match self.linker_major {
            0 => "unknown".to_string(),
            2 => format!("GNU ld / MinGW (v{}.{:02})", self.linker_major, self.linker_minor),
            v => format!("MSVC link v{}.{:02}", v, self.linker_minor),
        }
    }

    /// Heuristic: a named packer, or every section is very high entropy.
    pub fn is_packed(&self) -> bool {
        if self.packer.is_some() {
            return true;
        }
        let with_data: Vec<&PeSection> = self.sections.iter().filter(|s| s.raw_size > 0).collect();
        !with_data.is_empty() && with_data.iter().all(|s| s.entropy > 7.2)
    }
}

/// Detect a packer from known section-name signatures.
fn detect_packer(sections: &[PeSection]) -> Option<String> {
    for s in sections {
        let n = s.name.to_ascii_lowercase();
        let p = if n.starts_with("upx") {
            "UPX"
        } else if n.contains("aspack") {
            "ASPack"
        } else if n.contains("petite") {
            "Petite"
        } else if n.contains("fsg") {
            "FSG"
        } else if n.contains("mpress") {
            "MPRESS"
        } else if n.contains("vmp") {
            "VMProtect"
        } else if n.contains("themida") || n.contains("winlice") {
            "Themida"
        } else {
            continue;
        };
        return Some(p.to_string());
    }
    None
}

/// Walk the import directory (data directory #1) into DLL -> function lists.
/// Defensive: every read is bounds-checked and counts are capped, since this
/// runs on malformed / hostile PEs.
fn parse_imports(data: &[u8], sections: &[PeSection], opt: usize, magic: u16) -> Vec<PeImport> {
    let mut imports = Vec::new();
    let is_64 = magic == 0x20B;
    let datadir = if is_64 { opt + 112 } else { opt + 96 };
    let imp_rva = match u32le(data, datadir + 8) {
        Some(v) if v != 0 => v,
        _ => return imports,
    };
    let mut off = match rva_to_off(sections, imp_rva) {
        Some(o) => o,
        None => return imports,
    };

    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes, terminated by an all-zero entry.
    for _ in 0..1024 {
        let oft = u32le(data, off).unwrap_or(0);
        let name_rva = u32le(data, off + 12).unwrap_or(0);
        let ft = u32le(data, off + 16).unwrap_or(0);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let dll = rva_to_off(sections, name_rva)
            .map(|o| read_cstr(data, o))
            .unwrap_or_default();

        // Prefer the Import Lookup Table (OriginalFirstThunk); fall back to IAT.
        let thunk_rva = if oft != 0 { oft } else { ft };
        let mut funcs = Vec::new();
        if let Some(mut t) = rva_to_off(sections, thunk_rva) {
            for _ in 0..8192 {
                let (val, by_ordinal, name_rva) = if is_64 {
                    match u64le(data, t) {
                        Some(v) => (v, v & 0x8000_0000_0000_0000 != 0, (v & 0x7FFF_FFFF) as u32),
                        None => break,
                    }
                } else {
                    match u32le(data, t) {
                        Some(v) => (v as u64, v & 0x8000_0000 != 0, v & 0x7FFF_FFFF),
                        None => break,
                    }
                };
                if val == 0 {
                    break;
                }
                if by_ordinal {
                    funcs.push(format!("#{}", val & 0xFFFF));
                } else if let Some(no) = rva_to_off(sections, name_rva) {
                    // IMAGE_IMPORT_BY_NAME: 2-byte hint, then the ASCII name.
                    funcs.push(read_cstr(data, no + 2));
                }
                t += if is_64 { 8 } else { 4 };
                if funcs.len() >= 5000 {
                    break;
                }
            }
        }
        imports.push(PeImport { dll, funcs });
        off += 20;
    }
    imports
}

/// Walk the export directory (data directory #0) into named exports.
fn parse_exports(data: &[u8], sections: &[PeSection], opt: usize, magic: u16) -> Vec<PeExport> {
    let mut out = Vec::new();
    let is_64 = magic == 0x20B;
    let datadir = if is_64 { opt + 112 } else { opt + 96 };
    let exp_rva = match u32le(data, datadir) {
        Some(v) if v != 0 => v,
        _ => return out,
    };
    let base = match rva_to_off(sections, exp_rva) {
        Some(o) => o,
        None => return out,
    };
    let ordinal_base = u32le(data, base + 16).unwrap_or(0);
    let num_names = u32le(data, base + 24).unwrap_or(0) as usize;
    let addr_funcs = u32le(data, base + 28).unwrap_or(0);
    let addr_names = u32le(data, base + 32).unwrap_or(0);
    let addr_ords = u32le(data, base + 36).unwrap_or(0);

    let (names_off, ords_off, funcs_off) = match (
        rva_to_off(sections, addr_names),
        rva_to_off(sections, addr_ords),
        rva_to_off(sections, addr_funcs),
    ) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return out,
    };

    for i in 0..num_names.min(65536) {
        let name_rva = match u32le(data, names_off + i * 4) {
            Some(v) => v,
            None => break,
        };
        let name = rva_to_off(sections, name_rva)
            .map(|o| read_cstr(data, o))
            .unwrap_or_default();
        let ord = u16le(data, ords_off + i * 2).unwrap_or(0);
        let rva = u32le(data, funcs_off + ord as usize * 4).unwrap_or(0);
        out.push(PeExport {
            name,
            ordinal: ordinal_base + ord as u32,
            rva,
        });
    }
    out
}

/// Parse the PE structure of `data`. Returns `None` if it isn't a PE.
pub fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew = u32le(data, 0x3C)? as usize;
    match data.get(e_lfanew..) {
        Some(rest) if rest.starts_with(b"PE\0\0") => {}
        _ => return None,
    }

    let fh = e_lfanew + 4; // COFF file header
    let machine = u16le(data, fh)?;
    let num_sections = u16le(data, fh + 2)? as usize;
    let size_opt = u16le(data, fh + 16)? as usize;

    let opt = fh + 20; // optional header
    let magic = u16le(data, opt).unwrap_or(0);
    let is_64 = magic == 0x20B || matches!(machine, 0x8664 | 0xAA64);
    let entry_rva = u32le(data, opt + 16).unwrap_or(0);
    let image_base = if magic == 0x20B {
        u64le(data, opt + 24).unwrap_or(0)
    } else {
        u32le(data, opt + 28).unwrap_or(0) as u64
    };

    let sec_table = opt + size_opt;
    let mut sections = Vec::new();
    for i in 0..num_sections.min(96) {
        let s = sec_table + i * 40;
        let name_bytes = data.get(s..s + 8)?;
        let name: String = name_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect();
        let raw_size = u32le(data, s + 16)?;
        let raw_ptr = u32le(data, s + 20)?;
        let start = raw_ptr as usize;
        let end = start.saturating_add(raw_size as usize).min(data.len());
        let entropy = crate::entropy::shannon_entropy(if start < end { &data[start..end] } else { &[] });
        sections.push(PeSection {
            name,
            virtual_size: u32le(data, s + 8)?,
            virtual_addr: u32le(data, s + 12)?,
            raw_size,
            raw_ptr,
            characteristics: u32le(data, s + 36)?,
            entropy,
        });
    }

    let imports = parse_imports(data, &sections, opt, magic);
    let exports = parse_exports(data, &sections, opt, magic);
    let timestamp = u32le(data, fh + 4).unwrap_or(0);
    let linker_major = data.get(opt + 2).copied().unwrap_or(0);
    let linker_minor = data.get(opt + 3).copied().unwrap_or(0);
    let datadir = if is_64 { opt + 112 } else { opt + 96 };
    let is_dotnet = u32le(data, datadir + 14 * 8).unwrap_or(0) != 0;
    let packer = detect_packer(&sections);
    Some(PeInfo {
        is_64,
        machine,
        nt_offset: e_lfanew,
        entry_rva,
        image_base,
        timestamp,
        linker_major,
        linker_minor,
        is_dotnet,
        packer,
        sections,
        imports,
        exports,
    })
}

/// Extract raw icon image resources (RT_ICON, resource type 3) from a PE's
/// `.rsrc` directory. Each returned blob is a raw icon image — a DIB (BMP-style)
/// or, for large icons, an embedded PNG. Bounds-checked for hostile input.
pub fn icon_resources(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some(pe) = parse_pe(data) else {
        return out;
    };
    let opt = pe.nt_offset + 24;
    let datadir = opt + if pe.is_64 { 112 } else { 96 };
    // Data directory entry 2 = resource table (RVA at +16, size at +20).
    let res_rva = match u32le(data, datadir + 16) {
        Some(v) if v != 0 => v,
        _ => return out,
    };
    let Some(base) = pe.rva_to_offset(res_rva) else {
        return out;
    };

    // Level 1: the RT_ICON (id 3) subdirectory; then gather all leaf entries.
    let Some(type_dir) = res_find_id(data, base, base, 3) else {
        return out;
    };
    let mut leaves = Vec::new();
    res_collect_leaves(data, base, type_dir, 0, &mut leaves);
    for de in leaves {
        // IMAGE_RESOURCE_DATA_ENTRY: OffsetToData (RVA, u32), Size (u32).
        if let (Some(rva), Some(sz)) = (u32le(data, de), u32le(data, de + 4)) {
            if let Some(off) = pe.rva_to_offset(rva) {
                let sz = sz as usize;
                let end = off.saturating_add(sz).min(data.len());
                if off < end && sz <= 8 * 1024 * 1024 {
                    out.push(data[off..end].to_vec());
                }
            }
        }
        if out.len() >= 64 {
            break;
        }
    }
    out
}

/// Find the subdirectory file offset for the directory entry with the given ID.
fn res_find_id(data: &[u8], base: usize, dir: usize, want: u32) -> Option<usize> {
    let named = u16le(data, dir + 12)? as usize;
    let ids = u16le(data, dir + 14)? as usize;
    for i in 0..named + ids {
        let e = dir + 16 + i * 8;
        let name = u32le(data, e)?;
        let off = u32le(data, e + 4)?;
        // ID entry (name high bit clear) matching `want`, pointing at a subdir.
        if name & 0x8000_0000 == 0 && name == want && off & 0x8000_0000 != 0 {
            return Some(base + (off & 0x7FFF_FFFF) as usize);
        }
    }
    None
}

/// Recursively gather leaf data-entry file offsets under a resource directory.
fn res_collect_leaves(data: &[u8], base: usize, dir: usize, depth: u32, out: &mut Vec<usize>) {
    if depth > 4 || out.len() >= 64 {
        return;
    }
    let named = u16le(data, dir + 12).unwrap_or(0) as usize;
    let ids = u16le(data, dir + 14).unwrap_or(0) as usize;
    for i in 0..(named + ids).min(4096) {
        let e = dir + 16 + i * 8;
        let Some(off) = u32le(data, e + 4) else {
            continue;
        };
        if off & 0x8000_0000 != 0 {
            let sub = base + (off & 0x7FFF_FFFF) as usize;
            res_collect_leaves(data, base, sub, depth + 1, out);
        } else {
            out.push(base + off as usize);
        }
    }
}

/// Compute the standard **imphash** — the MD5 of the import table rendered as
/// `dll.func` entries (extension stripped, everything lowercased), joined by
/// commas in import order. Empty string if no imports.
///
/// Matches pefile/VirusTotal for name-imported functions. Known limitation:
/// ordinal-only imports are emitted as `ord<N>` rather than resolved to their
/// well-known names (pefile keeps per-DLL ordinal tables for `ws2_32`/`oleaut32`
/// etc.), so imphashes for ordinal-heavy samples may differ from VT.
pub fn imphash(pe: &PeInfo) -> String {
    let mut parts: Vec<String> = Vec::new();
    for imp in &pe.imports {
        // Strip a trailing .dll/.ocx/.sys (exactly what pefile strips) from the
        // module name; other extensions (.drv, .cpl) are kept, as pefile does.
        let dll = imp.dll.to_ascii_lowercase();
        let dll_stem = match dll.rsplit_once('.') {
            Some((stem, ext)) if matches!(ext, "dll" | "ocx" | "sys") => stem,
            _ => dll.as_str(),
        };
        for f in &imp.funcs {
            let func = if let Some(ord) = f.strip_prefix('#') {
                format!("ord{ord}")
            } else {
                f.to_ascii_lowercase()
            };
            // pefile skips unnamed imports rather than emitting a bare "dll.".
            if func.is_empty() {
                continue;
            }
            parts.push(format!("{dll_stem}.{func}"));
        }
    }
    if parts.is_empty() {
        return String::new();
    }
    crate::hashes::md5_hex(parts.join(",").as_bytes())
}

/// A flagged import — an API commonly abused by malware, with a category and a
/// short reason so a triage report reads at a glance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiFlag {
    pub dll: String,
    pub api: String,
    pub category: &'static str,
    pub note: &'static str,
}

/// Curated map of notable Win32 APIs keyed by lowercased base name (no trailing
/// A/W). Kept deliberately high-signal — the kind of imports an analyst circles.
const SUSPICIOUS_APIS: &[(&str, &str, &str)] = &[
    // process injection / execution
    ("virtualalloc", "Injection", "allocate executable memory"),
    ("virtualallocex", "Injection", "allocate memory in another process"),
    ("virtualprotect", "Injection", "change memory protection (e.g. make RWX)"),
    ("virtualprotectex", "Injection", "change memory protection in another process"),
    ("writeprocessmemory", "Injection", "write into another process"),
    ("readprocessmemory", "Injection", "read another process's memory"),
    ("createremotethread", "Injection", "run code in another process"),
    ("createremotethreadex", "Injection", "run code in another process"),
    ("ntcreatethreadex", "Injection", "stealthy remote thread creation"),
    ("queueuserapc", "Injection", "APC injection"),
    ("ntunmapviewofsection", "Injection", "process hollowing"),
    ("ntmapviewofsection", "Injection", "section-mapping injection"),
    ("setthreadcontext", "Injection", "hijack a thread's execution"),
    ("openprocess", "Injection", "obtain a handle to another process"),
    ("createprocess", "Execution", "spawn a process"),
    ("createprocessinternal", "Execution", "spawn a process (internal)"),
    ("shellexecute", "Execution", "launch a file/URL"),
    ("winexec", "Execution", "legacy process launch"),
    ("system", "Execution", "run a shell command"),
    // dynamic resolution
    ("loadlibrary", "Dynamic API", "load a DLL at runtime"),
    ("loadlibraryex", "Dynamic API", "load a DLL at runtime"),
    ("getprocaddress", "Dynamic API", "resolve an API by name (evasion)"),
    ("ldrloaddll", "Dynamic API", "low-level DLL load"),
    ("ldrgetprocedureaddress", "Dynamic API", "low-level API resolve"),
    // persistence
    ("regsetvalue", "Persistence", "write a registry value"),
    ("regsetvalueex", "Persistence", "write a registry value"),
    ("regcreatekey", "Persistence", "create a registry key"),
    ("regcreatekeyex", "Persistence", "create a registry key"),
    ("createservice", "Persistence", "install a service"),
    ("openscmanager", "Persistence", "access the service manager"),
    ("schtasks", "Persistence", "scheduled task"),
    // credential / keylogging / spying
    ("setwindowshookex", "Spying", "install a hook (keylogger)"),
    ("getasynckeystate", "Spying", "poll keystrokes"),
    ("getkeystate", "Spying", "read key state"),
    ("getforegroundwindow", "Spying", "track active window"),
    ("bitblt", "Spying", "screen capture"),
    ("getclipboarddata", "Spying", "read the clipboard"),
    // privilege / token
    ("adjusttokenprivileges", "Privilege", "enable privileges (e.g. SeDebug)"),
    ("lookupprivilegevalue", "Privilege", "look up a privilege LUID"),
    ("openprocesstoken", "Privilege", "open a process token"),
    // anti-analysis
    ("isdebuggerpresent", "Anti-analysis", "debugger check"),
    ("checkremotedebuggerpresent", "Anti-analysis", "debugger check"),
    ("ntqueryinformationprocess", "Anti-analysis", "debugger/enum check"),
    ("outputdebugstring", "Anti-analysis", "debugger trick/timing"),
    ("gettickcount", "Anti-analysis", "timing/sandbox check"),
    ("queryperformancecounter", "Anti-analysis", "timing/sandbox check"),
    ("sleep", "Anti-analysis", "stall to evade sandboxes"),
    ("createtoolhelp32snapshot", "Discovery", "enumerate processes"),
    ("process32first", "Discovery", "enumerate processes"),
    ("process32next", "Discovery", "enumerate processes"),
    // networking / download
    ("urldownloadtofile", "Networking", "download a file"),
    ("internetopen", "Networking", "WinINet HTTP client"),
    ("internetopenurl", "Networking", "open a URL"),
    ("internetconnect", "Networking", "connect to a host"),
    ("httpsendrequest", "Networking", "HTTP request"),
    ("winhttpopen", "Networking", "WinHTTP client"),
    ("wsastartup", "Networking", "init Winsock"),
    ("socket", "Networking", "raw socket"),
    ("connect", "Networking", "outbound connection"),
    ("send", "Networking", "send over a socket"),
    ("recv", "Networking", "receive over a socket"),
    ("gethostbyname", "Networking", "DNS resolve"),
    ("getaddrinfo", "Networking", "DNS resolve"),
    ("bind", "Networking", "listen (possible backdoor)"),
    ("listen", "Networking", "listen (possible backdoor)"),
    // crypto (ransomware)
    ("cryptacquirecontext", "Crypto", "acquire a crypto provider"),
    ("cryptencrypt", "Crypto", "encrypt data (ransomware)"),
    ("cryptdecrypt", "Crypto", "decrypt data"),
    ("cryptgenkey", "Crypto", "generate a key"),
    ("cryptderivekey", "Crypto", "derive a key from a secret"),
    ("bcryptencrypt", "Crypto", "CNG encrypt (ransomware)"),
    ("bcryptgenrandom", "Crypto", "CNG RNG"),
    // filesystem sweeps (ransomware / stealers)
    ("findfirstfile", "Discovery", "enumerate files"),
    ("findnextfile", "Discovery", "enumerate files"),
    ("getlogicaldrives", "Discovery", "enumerate drives"),
];

/// Flag imported APIs commonly abused by malware. Matches case-insensitively,
/// ignoring the trailing `A`/`W`/`Ex` variants.
pub fn suspicious_apis(pe: &PeInfo) -> Vec<ApiFlag> {
    let mut out = Vec::new();
    for imp in &pe.imports {
        for f in &imp.funcs {
            let base = normalize_api(f);
            if let Some(&(_, category, note)) =
                SUSPICIOUS_APIS.iter().find(|(name, _, _)| *name == base)
            {
                out.push(ApiFlag {
                    dll: imp.dll.clone(),
                    api: f.clone(),
                    category,
                    note,
                });
            }
        }
    }
    out
}

/// Normalize an API name: lowercase and drop a trailing `A`/`W` (the ANSI /
/// Unicode suffix), so `CreateProcessW` matches `createprocess`. The `Ex`
/// suffix is kept — `VirtualAllocEx` is a different API from `VirtualAlloc`, so
/// both are listed in the table explicitly.
fn normalize_api(name: &str) -> String {
    let mut s = name.to_ascii_lowercase();
    if (s.ends_with('a') || s.ends_with('w')) && s.len() > 4 {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert!(parse_pe(b"not a pe file at all").is_none());
        assert!(parse_pe(&[]).is_none());
        assert!(parse_pe(b"MZ").is_none()); // MZ but no e_lfanew/PE
    }

    #[test]
    fn parses_minimal_pe() {
        let mut d = vec![0u8; 0x200];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // machine x64
        d[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        d[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes()); // SizeOfOptionalHeader
        d[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // magic PE32+
        d[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes()); // entry rva
        let st = 0x98 + 0xE0; // section table
        d[st..st + 5].copy_from_slice(b".text");
        d[st + 8..st + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual size
        d[st + 12..st + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual addr
        d[st + 16..st + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        d[st + 20..st + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw ptr
        d[st + 36..st + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // code|exec|read

        let pe = parse_pe(&d).expect("should parse");
        assert!(pe.is_64);
        assert_eq!(pe.machine_str(), "x64");
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name, ".text");
        assert_eq!(pe.sections[0].raw_ptr, 0x400);
        assert_eq!(pe.sections[0].virtual_addr, 0x1000);
        assert_eq!(pe.sections[0].perms(), "RX");
        assert_eq!(pe.entry_offset(), Some(0x400));
        assert!(pe.imports.is_empty()); // no data directories set in this fixture
        assert!(pe.exports.is_empty());
    }

    fn pe_with_imports(imports: Vec<PeImport>) -> PeInfo {
        PeInfo {
            is_64: false,
            machine: 0x14C,
            nt_offset: 0,
            entry_rva: 0,
            image_base: 0,
            timestamp: 0,
            linker_major: 0,
            linker_minor: 0,
            is_dotnet: false,
            packer: None,
            sections: Vec::new(),
            imports,
            exports: Vec::new(),
        }
    }

    #[test]
    fn imphash_matches_reference() {
        // pefile's imphash of {KERNEL32.dll: [CreateFileA], USER32.dll: [MessageBoxA]}
        // is md5("kernel32.createfilea,user32.messageboxa").
        let pe = pe_with_imports(vec![
            PeImport { dll: "KERNEL32.dll".into(), funcs: vec!["CreateFileA".into()] },
            PeImport { dll: "USER32.dll".into(), funcs: vec!["MessageBoxA".into()] },
        ]);
        let expected = crate::hashes::md5_hex(b"kernel32.createfilea,user32.messageboxa");
        assert_eq!(imphash(&pe), expected);
    }

    #[test]
    fn imphash_handles_ordinals_and_empty() {
        let pe = pe_with_imports(vec![PeImport {
            dll: "WS2_32.dll".into(),
            funcs: vec!["#115".into()],
        }]);
        assert_eq!(imphash(&pe), crate::hashes::md5_hex(b"ws2_32.ord115"));
        assert_eq!(imphash(&pe_with_imports(vec![])), "");
    }

    #[test]
    fn imphash_keeps_drv_ext_and_skips_empty_func() {
        // pefile strips only dll/ocx/sys — .drv is kept; blank import names skip.
        let pe = pe_with_imports(vec![PeImport {
            dll: "WINSPOOL.DRV".into(),
            funcs: vec!["OpenPrinterW".into(), String::new()],
        }]);
        assert_eq!(imphash(&pe), crate::hashes::md5_hex(b"winspool.drv.openprinterw"));
    }

    #[test]
    fn flags_suspicious_apis() {
        let pe = pe_with_imports(vec![PeImport {
            dll: "KERNEL32.dll".into(),
            funcs: vec![
                "VirtualAllocEx".into(),
                "WriteProcessMemory".into(),
                "CreateRemoteThread".into(),
                "lstrlenA".into(), // benign — must not be flagged
            ],
        }]);
        let flags = suspicious_apis(&pe);
        let apis: Vec<&str> = flags.iter().map(|f| f.api.as_str()).collect();
        assert!(apis.contains(&"VirtualAllocEx"));
        assert!(apis.contains(&"WriteProcessMemory"));
        assert!(apis.contains(&"CreateRemoteThread"));
        assert!(!apis.contains(&"lstrlenA"));
        // VirtualAllocEx keeps its own (cross-process) note, not VirtualAlloc's.
        let va = flags.iter().find(|f| f.api == "VirtualAllocEx").unwrap();
        assert!(va.note.contains("another process"));
    }
}
