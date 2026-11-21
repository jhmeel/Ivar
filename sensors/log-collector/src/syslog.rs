//! Syslog parsing: RFC 5424 and RFC 3164.

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Message {
    pub priority: u8,
    pub hostname: String,
    pub app: String,
    pub message: String,
}

pub fn parse(line: &str) -> Message {
    let line = line.trim_end();
    let (pri, rest) = match line.strip_prefix('<').and_then(|r| r.split_once('>')) {
        Some((p, r)) => (p.parse().unwrap_or(13), r),
        None => (13, line),
    };
    // RFC 5424: VERSION TIMESTAMP HOSTNAME APP PROCID MSGID SD MSG
    if rest.starts_with("1 ") {
        let f: Vec<&str> = rest.splitn(8, ' ').collect();
        let msg = f.get(7).map(|m| if m.starts_with('[') { m.split_once("] ").map(|x| x.1).unwrap_or(m) } else { m.trim_start_matches("- ") }).unwrap_or("");
        return Message { priority: pri, hostname: f.get(2).copied().unwrap_or("").into(), app: f.get(3).copied().unwrap_or("").into(), message: msg.into() };
    }
    // RFC 3164: "Mmm dd hh:mm:ss HOST TAG: MSG"
    let f: Vec<&str> = rest.splitn(5, ' ').filter(|s| !s.is_empty()).collect();
    if f.len() >= 5 && f[0].len() == 3 {
        let (app, msg) = f[4].split_once(": ").unwrap_or(("", f[4]));
        return Message { priority: pri, hostname: f[3].into(), app: app.into(), message: msg.into() };
    }
    Message { priority: pri, message: rest.into(), ..Default::default() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn both_formats() {
        let m = super::parse("<134>1 2026-11-19T02:15:00Z fw-1 fortigate - - - logid=0100044547 type=event");
        assert_eq!((m.hostname.as_str(), m.message.as_str()), ("fw-1", "logid=0100044547 type=event"));
        let m = super::parse("<189>Nov 19 02:15:00 edge-rtr %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]");
        assert_eq!(m.hostname, "edge-rtr");
    }
}
