//! Quick triage dump for a file: `cargo run -p hexed-core --example triage -- FILE`.
//! Prints counts and samples for the IOC / carve / signature / PE scans so the
//! extractors can be sanity-checked against real binaries.

use hexed_core::{
    extract_iocs, find_embedded, imphash, parse_pe, scan_signatures, suspicious_apis, IocKind,
};

fn main() {
    let path = std::env::args().nth(1).expect("usage: triage FILE");
    let data = std::fs::read(&path).expect("read file");
    println!("== {path} ({} bytes) ==", data.len());

    let iocs = extract_iocs(&data);
    println!("\nIOCs: {}", iocs.len());
    for kind in [
        IocKind::Url,
        IocKind::Domain,
        IocKind::Ipv4,
        IocKind::Email,
        IocKind::WinPath,
        IocKind::UnixPath,
        IocKind::Registry,
        IocKind::Wallet,
    ] {
        let g: Vec<&str> = iocs
            .iter()
            .filter(|i| i.kind == kind)
            .map(|i| i.value.as_str())
            .collect();
        if !g.is_empty() {
            println!("  {} ({}): {}", kind.label(), g.len(), sample(&g, 6));
        }
    }

    let emb = find_embedded(&data);
    println!("\nEmbedded ({}):", emb.len());
    for e in emb.iter().take(12) {
        println!("  0x{:X} {} {:?}", e.offset, e.kind, e.size);
    }

    let sigs = scan_signatures(&data);
    println!("\nSignatures ({}):", sigs.len());
    for s in sigs.iter().take(12) {
        println!("  0x{:X} {}", s.offset, s.name);
    }

    if let Some(pe) = parse_pe(&data) {
        println!("\nimphash: {}", imphash(&pe));
        let flags = suspicious_apis(&pe);
        println!("flagged APIs ({}):", flags.len());
        for f in flags.iter().take(20) {
            println!("  [{}] {} — {}", f.category, f.api, f.note);
        }
    }
}

fn sample(v: &[&str], n: usize) -> String {
    let shown: Vec<&str> = v.iter().take(n).copied().collect();
    let more = if v.len() > n {
        format!(" …+{}", v.len() - n)
    } else {
        String::new()
    };
    format!("{}{}", shown.join(", "), more)
}
