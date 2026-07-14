//! Indicator-of-compromise (IOC) extraction for triage.
//!
//! Scans printable strings (ASCII + UTF-16LE) for network and host indicators —
//! URLs, IPs, domains, emails, file paths, registry keys, and crypto-wallet
//! addresses — recording each with its byte offset so the UI can jump to it.
//! Matchers are hand-rolled (no regex dependency) and tuned to keep binary noise
//! low: domains require a real TLD, file extensions like `.dll` are rejected, and
//! version-number quads are excluded from IPv4.

use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IocKind {
    Ipv4,
    Url,
    Domain,
    Email,
    WinPath,
    UnixPath,
    Registry,
    Wallet,
}

impl IocKind {
    pub fn label(self) -> &'static str {
        match self {
            IocKind::Ipv4 => "IPv4",
            IocKind::Url => "URL",
            IocKind::Domain => "Domain",
            IocKind::Email => "Email",
            IocKind::WinPath => "Windows path",
            IocKind::UnixPath => "Unix path",
            IocKind::Registry => "Registry",
            IocKind::Wallet => "Wallet",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    /// Byte offset of the first occurrence within the scanned buffer.
    pub offset: usize,
    /// Span in buffer bytes (2× the char count for UTF-16LE sources), so the UI
    /// can highlight the whole match — not just the char count of `value`.
    pub byte_len: usize,
}

/// Extract IOCs from a buffer. Results are de-duplicated by (kind, value),
/// keeping the earliest offset, and returned sorted by offset.
pub fn extract_iocs(data: &[u8]) -> Vec<Ioc> {
    let strings = crate::strings::find_strings(data, 5, true, true);
    let mut seen: HashSet<(IocKind, String)> = HashSet::new();
    let mut out: Vec<Ioc> = Vec::new();

    for s in &strings {
        let stride = match s.kind {
            crate::strings::StringKind::Ascii => 1,
            crate::strings::StringKind::Utf16Le => 2,
        };
        let base = s.offset;
        let mut push = |kind: IocKind, value: String, idx: usize| {
            if seen.insert((kind, value.clone())) {
                // value chars are all ASCII (1 byte each in `text`), so the
                // buffer span is char-count × stride (2 for UTF-16LE).
                let byte_len = (value.len() * stride).max(1);
                out.push(Ioc {
                    kind,
                    byte_len,
                    offset: base + idx * stride,
                    value,
                });
            }
        };
        scan(s.text.as_bytes(), &mut push);
    }

    out.sort_by_key(|i| i.offset);
    out
}

/// Wrap an indicator in defanged form (`hxxp`, `1.2.3[.]4`, `evil[.]com`) so it
/// is safe to paste into a report or chat without becoming a live link.
pub fn defang(s: &str) -> String {
    let out = s.replace("http://", "hxxp://").replace("https://", "hxxps://");
    // Neutralize every dot so IPs/domains/URLs can't resolve or auto-link.
    out.replace('.', "[.]")
}

fn scan(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    scan_urls(t, push);
    scan_emails(t, push);
    scan_ipv4(t, push);
    scan_domains(t, push);
    scan_win_paths(t, push);
    scan_unix_paths(t, push);
    scan_registry(t, push);
    scan_wallets(t, push);
}

// ---- character classes -----------------------------------------------------

#[inline]
fn is_url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b)
}
#[inline]
fn is_host(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
}
#[inline]
fn is_label(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

// ---- matchers --------------------------------------------------------------

fn scan_urls(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    for scheme in [&b"https://"[..], b"http://", b"ftp://"] {
        let mut i = 0;
        while let Some(p) = find(&t[i..], scheme) {
            let start = i + p;
            let scheme_end = start + scheme.len();
            let mut end = scheme_end;
            while end < t.len() && is_url(t[end]) {
                // stop if a new scheme begins (adjacent URLs share no separator);
                // match full schemes so a path containing "http" isn't truncated
                if end > scheme_end
                    && (t[end..].starts_with(b"http://")
                        || t[end..].starts_with(b"https://")
                        || t[end..].starts_with(b"ftp://"))
                {
                    break;
                }
                end += 1;
            }
            // trim trailing punctuation that's usually sentence noise
            while end > start && matches!(t[end - 1], b'.' | b',' | b')' | b']' | b'"' | b'\'' | b';') {
                end -= 1;
            }
            if end > start + scheme.len() {
                push(IocKind::Url, ascii(&t[start..end]), start);
            }
            i = end.max(start + 1);
        }
    }
}

fn scan_emails(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    for (i, &b) in t.iter().enumerate() {
        if b != b'@' {
            continue;
        }
        // local part to the left
        let mut ls = i;
        while ls > 0 && (t[ls - 1].is_ascii_alphanumeric() || b"._%+-".contains(&t[ls - 1])) {
            ls -= 1;
        }
        // domain to the right
        let mut de = i + 1;
        while de < t.len() && is_host(t[de]) {
            de += 1;
        }
        if ls == i || de == i + 1 {
            continue;
        }
        let dom = &t[i + 1..de];
        if valid_domain(dom) {
            push(IocKind::Email, ascii(&t[ls..de]), ls);
        }
    }
}

fn scan_ipv4(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    let n = t.len();
    let mut i = 0;
    while i < n {
        if !t[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut octets = [0u32; 4];
        let mut count = 0;
        let mut j = i;
        let mut ok = true;
        while count < 4 {
            let (val, len) = read_octet(&t[j..]);
            if len == 0 || val > 255 {
                ok = false;
                break;
            }
            octets[count] = val;
            j += len;
            count += 1;
            if count < 4 {
                if j < n && t[j] == b'.' {
                    j += 1;
                } else {
                    ok = false;
                    break;
                }
            }
        }
        // reject if part of a longer dotted-number run (versions), and reject
        // x.0.0.0 / 0.0.0.0 which are almost always version/netmask artifacts.
        let preceded = start > 0 && t[start - 1] == b'.';
        let followed = j < n && (t[j] == b'.' || t[j].is_ascii_digit());
        let trailing_zero = octets[1] == 0 && octets[2] == 0 && octets[3] == 0;
        if ok && count == 4 && !preceded && !followed && !trailing_zero {
            push(IocKind::Ipv4, ascii(&t[start..j]), start);
            i = j;
        } else {
            while i < n && (t[i].is_ascii_digit() || t[i] == b'.') {
                i += 1;
            }
            i = i.max(start + 1);
        }
    }
}

fn scan_domains(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    let n = t.len();
    let mut i = 0;
    while i < n {
        if !is_label(t[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_host(t[i]) {
            i += 1;
        }
        let host = &t[start..i];
        // must not be inside a URL/email boundary (@ or :// handled by dedup),
        // must be a valid multi-label domain with a real TLD, not an IP.
        if valid_domain(host) && !looks_like_ipv4(host) {
            push(IocKind::Domain, ascii(host).to_ascii_lowercase(), start);
        }
        i = i.max(start + 1);
    }
}

fn scan_win_paths(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    let n = t.len();
    // Drive paths (C:\...), UNC (\\host\share), and %ENV%\... paths.
    let mut i = 0;
    while i < n {
        // Drive: X:\ or X:/ at a word boundary, not followed by a second slash.
        let drive = i + 3 < n
            && t[i].is_ascii_alphabetic()
            && t[i + 1] == b':'
            && (t[i + 2] == b'\\' || t[i + 2] == b'/')
            && t[i + 3] != b'\\'
            && t[i + 3] != b'/'
            && (i == 0 || !t[i - 1].is_ascii_alphanumeric());
        // UNC: exactly two backslashes then a host character (not more slashes).
        let unc = i + 2 < n && t[i] == b'\\' && t[i + 1] == b'\\' && t[i + 2].is_ascii_alphanumeric();
        // Env: %NAME%\ with a real variable name.
        let env = env_path(&t[i..]);
        if drive || unc || env {
            let start = i;
            let mut end = i;
            while end < n
                && t[end] >= 0x20
                && !matches!(t[end], b'"' | b'<' | b'>' | b'|' | b'*' | b'?')
            {
                end += 1;
            }
            if end - start >= 4 {
                push(IocKind::WinPath, ascii(&t[start..end]), start);
            }
            i = end.max(start + 1);
        } else {
            i += 1;
        }
    }
}

/// True if `t` begins with a `%NAME%` env reference followed by a path separator.
fn env_path(t: &[u8]) -> bool {
    if t.first() != Some(&b'%') {
        return false;
    }
    let mut j = 1;
    while j < t.len() && (t[j].is_ascii_alphanumeric() || t[j] == b'_') {
        j += 1;
    }
    j > 1 && j + 1 < t.len() && t[j] == b'%' && (t[j + 1] == b'\\' || t[j + 1] == b'/')
}

const UNIX_ROOTS: &[&[u8]] = &[
    b"usr/", b"etc/", b"tmp/", b"var/", b"bin/", b"opt/", b"lib/", b"home/", b"root/",
    b"sbin/", b"mnt/", b"srv/", b"dev/", b"proc/", b"sys/", b"boot/", b"Users/", b"Library/",
    b"Applications/", b"System/", b"private/", b"Volumes/",
];

fn scan_unix_paths(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    let n = t.len();
    let mut i = 0;
    while i < n {
        if t[i] == b'/' && (i == 0 || !is_url(t[i - 1])) {
            // require a recognized root directory to keep noise down
            let after = &t[i + 1..];
            if UNIX_ROOTS.iter().any(|r| after.starts_with(r)) {
                let start = i;
                let mut end = i;
                while end < n
                    && t[end] > 0x20
                    && t[end] < 0x7f
                    && t[end] != b'"'
                    && t[end] != b'\''
                    && t[end] != b':'
                    && t[end] != b'*'
                    && t[end] != b'?'
                {
                    end += 1;
                }
                if end - start >= 5 {
                    push(IocKind::UnixPath, ascii(&t[start..end]), start);
                }
                i = end.max(start + 1);
                continue;
            }
        }
        i += 1;
    }
}

const REG_PREFIXES: &[&[u8]] = &[
    b"HKEY_LOCAL_MACHINE", b"HKEY_CURRENT_USER", b"HKEY_CLASSES_ROOT", b"HKEY_USERS",
    b"HKEY_CURRENT_CONFIG", b"HKLM\\", b"HKCU\\", b"HKCR\\", b"HKU\\",
];

fn scan_registry(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    let n = t.len();
    let mut i = 0;
    while i < n {
        let hit = REG_PREFIXES.iter().find(|p| t[i..].starts_with(p));
        if let Some(_p) = hit {
            let start = i;
            let mut end = i;
            while end < n && t[end] != 0 && t[end] != b'"' && t[end] != b'\t' && t[end] >= 0x20 {
                end += 1;
            }
            if end - start >= 6 {
                push(IocKind::Registry, ascii(&t[start..end]), start);
            }
            i = end.max(start + 1);
        } else {
            i += 1;
        }
    }
}

fn scan_wallets(t: &[u8], push: &mut impl FnMut(IocKind, String, usize)) {
    let n = t.len();
    // Ethereum: 0x + 40 hex, not part of a longer hex run.
    let mut i = 0;
    while i + 42 <= n {
        if t[i] == b'0' && (t[i + 1] == b'x' || t[i + 1] == b'X') {
            let hexs = &t[i + 2..i + 42];
            let after = i + 42;
            if hexs.iter().all(|b| b.is_ascii_hexdigit())
                && (after >= n || !t[after].is_ascii_hexdigit())
            {
                push(IocKind::Wallet, ascii(&t[i..i + 42]), i);
                i += 42;
                continue;
            }
        }
        i += 1;
    }
    // Bitcoin: base58 starting 1/3 (26-35) or bech32 bc1 (>=14).
    let mut i = 0;
    while i < n {
        let c = t[i];
        let boundary = i == 0 || !t[i - 1].is_ascii_alphanumeric();
        if boundary && (c == b'1' || c == b'3') {
            let mut end = i;
            while end < n && is_base58(t[end]) {
                end += 1;
            }
            let len = end - i;
            if (26..=35).contains(&len) && (end >= n || !t[end].is_ascii_alphanumeric()) {
                push(IocKind::Wallet, ascii(&t[i..end]), i);
            }
            i = end.max(i + 1);
        } else if boundary && t[i..].starts_with(b"bc1") {
            let mut end = i + 3;
            while end < n && (t[end].is_ascii_lowercase() || t[end].is_ascii_digit()) {
                end += 1;
            }
            if end - i >= 14 {
                push(IocKind::Wallet, ascii(&t[i..end]), i);
            }
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
}

// ---- helpers ---------------------------------------------------------------

#[inline]
fn is_base58(b: u8) -> bool {
    // base58: alphanumerics minus 0, O, I, l
    matches!(b, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

fn read_octet(t: &[u8]) -> (u32, usize) {
    let mut v = 0u32;
    let mut len = 0usize;
    while len < 3 && len < t.len() && t[len].is_ascii_digit() {
        v = v * 10 + (t[len] - b'0') as u32;
        len += 1;
    }
    (v, len)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn ascii(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn looks_like_ipv4(host: &[u8]) -> bool {
    host.iter().all(|&b| b.is_ascii_digit() || b == b'.')
}

/// A small curated TLD set — real TLDs plus ones common in malware infra.
const TLDS: &[&[u8]] = &[
    b"com", b"net", b"org", b"info", b"biz", b"xyz", b"top", b"club", b"online", b"site",
    b"shop", b"store", b"live", b"icu", b"vip", b"cc", b"io", b"co", b"me", b"tv", b"ws",
    b"su", b"ru", b"cn", b"br", b"in", b"uk", b"de", b"fr", b"nl", b"eu", b"pl", b"it",
    b"es", b"ua", b"kr", b"jp", b"tw", b"hk", b"tk", b"ml", b"ga", b"cf", b"gq", b"pw",
    b"pro", b"dev", b"app", b"cloud", b"work", b"space", b"fun", b"link", b"gov", b"edu",
    b"mil", b"int", b"asia", b"mobi", b"name", b"tech", b"host", b"press", b"gdn", b"bid",
    b"loan", b"win", b"download", b"stream", b"party", b"review", b"trade", b"date", b"kim",
];

fn valid_domain(host: &[u8]) -> bool {
    // at least one dot, no leading/trailing dot, labels 1..=63, TLD in list
    if host.len() < 4 || host[0] == b'.' || host[host.len() - 1] == b'.' {
        return false;
    }
    let labels: Vec<&[u8]> = host.split(|&b| b == b'.').collect();
    if labels.len() < 2 {
        return false;
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 || !l.iter().all(|&b| is_label(b)) {
            return false;
        }
    }
    let tld = labels[labels.len() - 1].to_ascii_lowercase();
    // TLD must be alphabetic and in the curated set
    tld.iter().all(|b| b.is_ascii_alphabetic()) && TLDS.iter().any(|t| *t == tld.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(data: &[u8], kind: IocKind) -> Vec<String> {
        extract_iocs(data)
            .into_iter()
            .filter(|i| i.kind == kind)
            .map(|i| i.value)
            .collect()
    }

    #[test]
    fn finds_url_and_domain() {
        let data = b"\x00GET http://evil.example.com/beacon?id=1 HTTP\x00";
        let urls = kinds(data, IocKind::Url);
        assert_eq!(urls, vec!["http://evil.example.com/beacon?id=1"]);
        let doms = kinds(data, IocKind::Domain);
        assert!(doms.contains(&"evil.example.com".to_string()));
    }

    #[test]
    fn finds_ipv4_but_not_version() {
        let ips = kinds(b"\x00connect 185.220.101.7 now\x00", IocKind::Ipv4);
        assert_eq!(ips, vec!["185.220.101.7"]);
        // version-like quad embedded in a longer dotted run is rejected
        let none = kinds(b"\x00version 6.2.9200.16384.0\x00", IocKind::Ipv4);
        assert!(none.is_empty(), "got {none:?}");
    }

    #[test]
    fn rejects_dotted_zero_ip() {
        // version/netmask artifacts x.0.0.0 are dropped; localhost is kept.
        assert!(kinds(b"\x00ver 1.0.0.0 x\x00", IocKind::Ipv4).is_empty());
        assert!(kinds(b"\x00net 6.0.0.0 x\x00", IocKind::Ipv4).is_empty());
        assert_eq!(kinds(b"\x00lo 127.0.0.1 x\x00", IocKind::Ipv4), vec!["127.0.0.1"]);
    }

    #[test]
    fn splits_concatenated_urls() {
        let urls = kinds(b"\x00https://a.com/xhttps://b.net/y end\x00", IocKind::Url);
        assert_eq!(urls, vec!["https://a.com/x", "https://b.net/y"]);
    }

    #[test]
    fn url_with_http_in_path_not_truncated() {
        // "http" inside a path must not trigger the adjacent-URL split.
        let urls = kinds(b"\x00get http://cdn.example.com/httpstuff ok\x00", IocKind::Url);
        assert_eq!(urls, vec!["http://cdn.example.com/httpstuff"]);
    }

    #[test]
    fn rejects_backslash_run_and_bad_env() {
        assert!(kinds(b"\x00\\\\\\\\\\\\ junk\x00", IocKind::WinPath).is_empty());
        assert!(kinds(b"\x00%H+broken path\x00", IocKind::WinPath).is_empty());
        // a real UNC and env path are still found
        assert!(!kinds(b"\x00\\\\server\\share\\a.dll\x00", IocKind::WinPath).is_empty());
        assert!(!kinds(b"\x00%APPDATA%\\Roaming\\x.exe\x00", IocKind::WinPath).is_empty());
    }

    #[test]
    fn finds_email() {
        let e = kinds(b"\x00contact bad.actor@mail.ru please\x00", IocKind::Email);
        assert_eq!(e, vec!["bad.actor@mail.ru"]);
    }

    #[test]
    fn rejects_dll_as_domain() {
        let d = kinds(b"\x00LoadLibrary kernel32.dll ok\x00", IocKind::Domain);
        assert!(d.is_empty(), "got {d:?}");
    }

    #[test]
    fn finds_win_and_registry() {
        let p = kinds(b"\x00C:\\Users\\v\\AppData\\Local\\Temp\\a.exe\x00", IocKind::WinPath);
        assert_eq!(p.len(), 1);
        let r = kinds(
            b"\x00HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00",
            IocKind::Registry,
        );
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn finds_unix_path() {
        let p = kinds(b"\x00drop /tmp/.hidden/payload.sh here\x00", IocKind::UnixPath);
        assert_eq!(p, vec!["/tmp/.hidden/payload.sh"]);
    }

    #[test]
    fn finds_wallets() {
        let eth = kinds(
            b"\x00pay 0x52908400098527886E0F7030069857D2E4169EE7 eth\x00",
            IocKind::Wallet,
        );
        assert_eq!(eth.len(), 1);
    }

    #[test]
    fn offset_maps_to_buffer() {
        let data = b"XX185.220.101.7";
        let iocs = extract_iocs(data);
        let ip = iocs.iter().find(|i| i.kind == IocKind::Ipv4).unwrap();
        assert_eq!(ip.offset, 2);
    }

    #[test]
    fn defang_neutralizes() {
        assert_eq!(defang("http://evil.com"), "hxxp://evil[.]com");
        assert_eq!(defang("1.2.3.4"), "1[.]2[.]3[.]4");
    }
}
