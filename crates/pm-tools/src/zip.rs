//! A small ZIP writer and reader for uncompressed ("stored") archives, so an
//! evidence pack opens with any operating system's built-in tools. No I/O.
//! The reader takes untrusted files: every offset and length is checked,
//! sizes are capped, and only stored entries are accepted.

/// Most entries and bytes a pack may hold.
const MAX_ENTRIES: usize = 20_000;
const MAX_TOTAL: usize = 512 * 1024 * 1024;

fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

fn u16le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn u32le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Builds a stored ZIP from `(name, bytes)` entries, in order.
pub fn write(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        if name.is_empty() || name.starts_with('/') || name.contains('\\') || name.split('/').any(|p| p == "..") {
            return Err(format!("bad entry name {name:?}"));
        }
        let (size, offset) = (
            u32::try_from(data.len()).map_err(|_| format!("{name} is too large"))?,
            u32::try_from(out.len()).map_err(|_| "the archive is too large".to_string())?,
        );
        let crc = crc32(data);
        let n = u16::try_from(name.len()).map_err(|_| format!("name too long: {name}"))?;
        // Local file header: version 1.0, UTF-8 names (bit 11), stored, DOS time 1980-01-01.
        u32le(&mut out, 0x0403_4b50);
        for x in [10u16, 0x0800, 0, 0, 0x21] {
            u16le(&mut out, x);
        }
        for x in [crc, size, size] {
            u32le(&mut out, x);
        }
        u16le(&mut out, n);
        u16le(&mut out, 0);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        // Central directory entry.
        u32le(&mut central, 0x0201_4b50);
        for x in [20u16, 10, 0x0800, 0, 0, 0x21] {
            u16le(&mut central, x);
        }
        for x in [crc, size, size] {
            u32le(&mut central, x);
        }
        for x in [n, 0, 0, 0, 0] {
            u16le(&mut central, x);
        }
        u32le(&mut central, 0);
        u32le(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let count = u16::try_from(entries.len()).map_err(|_| "too many entries".to_string())?;
    let cd_offset = u32::try_from(out.len()).map_err(|_| "the archive is too large".to_string())?;
    let cd_size = u32::try_from(central.len()).map_err(|_| "the archive is too large".to_string())?;
    out.extend_from_slice(&central);
    u32le(&mut out, 0x0605_4b50);
    for x in [0u16, 0, count, count] {
        u16le(&mut out, x);
    }
    u32le(&mut out, cd_size);
    u32le(&mut out, cd_offset);
    u16le(&mut out, 0);
    Ok(out)
}

fn rd16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}
fn rd32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]))
}

/// Reads a stored ZIP into `(name, bytes)` entries. Refuses compressed or
/// encrypted entries, bad offsets, CRC mismatches and duplicate names.
pub fn read(b: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let bad = |why: &str| Err(format!("not a valid evidence pack: {why}"));
    // The end-of-central-directory record is in the last 64 KiB + 22 bytes.
    let start = b.len().saturating_sub(65_557);
    let Some(eocd) = (start..b.len().saturating_sub(21)).rev().find(|&i| rd32(b, i) == Some(0x0605_4b50)) else {
        return bad("no end of central directory");
    };
    let count = usize::from(rd16(b, eocd + 10).unwrap_or(0));
    let cd_offset = rd32(b, eocd + 16).unwrap_or(0) as usize;
    if count > MAX_ENTRIES {
        return bad("too many entries");
    }
    let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(count);
    let mut total = 0usize;
    let mut at = cd_offset;
    for _ in 0..count {
        if rd32(b, at) != Some(0x0201_4b50) {
            return bad("broken central directory");
        }
        let flags = rd16(b, at + 8).unwrap_or(0xffff);
        let method = rd16(b, at + 10).unwrap_or(0xffff);
        let crc = rd32(b, at + 16).unwrap_or(0);
        let size = rd32(b, at + 20).unwrap_or(0) as usize;
        let usize_ = rd32(b, at + 24).unwrap_or(0) as usize;
        let (n, extra, comment) = (
            usize::from(rd16(b, at + 28).unwrap_or(0)),
            usize::from(rd16(b, at + 30).unwrap_or(0)),
            usize::from(rd16(b, at + 32).unwrap_or(0)),
        );
        let local = rd32(b, at + 42).unwrap_or(u32::MAX) as usize;
        let name = b.get(at + 46..at + 46 + n).ok_or("name out of bounds")?;
        let name = String::from_utf8(name.to_vec()).map_err(|_| "a name isn't UTF-8".to_string())?;
        if method != 0 || flags & 1 != 0 || size != usize_ {
            return bad(&format!("{name} is compressed or encrypted"));
        }
        if name.starts_with('/') || name.contains('\\') || name.split('/').any(|p| p == "..") {
            return bad(&format!("unsafe entry name {name:?}"));
        }
        total = total.saturating_add(size);
        if total > MAX_TOTAL {
            return bad("too large");
        }
        if rd32(b, local) != Some(0x0403_4b50) {
            return bad(&format!("{name}: broken local header"));
        }
        let ln = usize::from(rd16(b, local + 26).unwrap_or(0));
        let le = usize::from(rd16(b, local + 28).unwrap_or(0));
        let data_at = local + 30 + ln + le;
        let data = b.get(data_at..data_at + size).ok_or_else(|| format!("{name}: data out of bounds"))?;
        if crc32(data) != crc {
            return bad(&format!("{name}: checksum mismatch"));
        }
        if out.iter().any(|(x, _)| *x == name) {
            return bad(&format!("{name} appears twice"));
        }
        out.push((name, data.to_vec()));
        at += 46 + n + extra + comment;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_bad_input() {
        let entries = vec![
            ("manifest.json".to_string(), b"{\"a\":1}".to_vec()),
            ("exchanges/1.request.http".to_string(), b"GET / HTTP/1.1\r\n\r\n".to_vec()),
            ("empty.txt".to_string(), vec![]),
        ];
        let z = write(&entries).unwrap();
        assert_eq!(read(&z).unwrap(), entries);

        // A flipped data byte fails the checksum.
        let mut bad = z.clone();
        let i = bad.windows(7).position(|w| w == b"{\"a\":1}").unwrap();
        bad[i + 5] = b'2';
        assert!(read(&bad).unwrap_err().contains("checksum"));
        assert!(read(b"not a zip").is_err());
        assert!(write(&[("../x".into(), vec![])]).is_err());
        for n in 0..z.len().min(300) {
            let _ = read(&z[..n]);
        }
    }
}
