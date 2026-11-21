//! Existing engines feed the core (section 20.1): Falco and Tetragon over
//! their JSON outputs, Suricata over EVE JSON. Each adapter maps one native
//! event to an OCSF SecurityEvent with the IVAR extension.

pub mod falco;
pub mod suricata;
pub mod tetragon;

use ivar_contracts::SecurityEvent;

/// Parse one JSON line from the named engine.
pub fn parse(engine: &str, line: &str, seq: u64, now: i64) -> Option<SecurityEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    match engine {
        "falco" => falco::map(&v, seq, now),
        "tetragon" => tetragon::map(&v, seq, now),
        "suricata" => suricata::map(&v, seq, now),
        _ => None,
    }
}

pub(crate) fn rfc3339_ms(s: &str) -> Option<i64> {
    // 2026-11-19T02:15:00.123456789Z
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let time = rest.trim_end_matches('Z');
    let time = time.split(['+']).next()?;
    let mut t = time.split(':');
    let (hh, mm) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let sec: f64 = t.next()?.parse().ok()?;
    // Days from civil (Howard Hinnant's algorithm).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + hh * 3600 + mm * 60) as f64 * 1000.0 + sec * 1000.0) as i64)
}

#[cfg(test)]
mod tests {
    #[test]
    fn time() {
        assert_eq!(super::rfc3339_ms("1970-01-02T00:00:01.5Z"), Some(86_401_500));
        assert_eq!(super::rfc3339_ms("2026-11-19T02:15:00Z"), Some(1_795_054_500_000));
    }
}
