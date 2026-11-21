//! A PostgreSQL wire protocol proxy. It reads the startup message (user and
//! database), each simple Query and extended Parse, and counts DataRow
//! messages from the server, so every statement becomes an event with the
//! rows it read. When the local decision blocks the session's identity in
//! enforce mode, the proxy answers with an ErrorResponse and ends the session.

use crate::sql::classify;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

pub fn serve(sensor: Arc<Sensor>, listen: &str, upstream: &str) -> anyhow::Result<()> {
    let l = TcpListener::bind(listen)?;
    for conn in l.incoming() {
        let client = conn?;
        let s = sensor.clone();
        let up = upstream.to_string();
        std::thread::spawn(move || {
            if let Err(e) = session(s, client, &up) {
                eprintln!("ivar pgproxy: {e}");
            }
        });
    }
    Ok(())
}

fn read_exact_vec(s: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    Ok(b)
}

/// Parse a startup message body into its key and value pairs.
pub fn startup_params(body: &[u8]) -> Vec<(String, String)> {
    let parts: Vec<String> = body.get(4..).unwrap_or(&[]).split(|b| *b == 0).map(|s| String::from_utf8_lossy(s).to_string()).collect();
    parts.chunks(2).filter(|c| c.len() == 2 && !c[0].is_empty()).map(|c| (c[0].clone(), c[1].clone())).collect()
}

pub fn error_response(message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (code, val) in [(b'S', "FATAL"), (b'C', "42501"), (b'M', message)] {
        body.push(code);
        body.extend_from_slice(val.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut msg = vec![b'E'];
    msg.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    msg.extend(body);
    msg
}

struct Pending {
    sql: String,
    rows: u64,
}

fn session(sensor: Arc<Sensor>, mut client: TcpStream, upstream: &str) -> anyhow::Result<()> {
    let peer = client.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let mut server = TcpStream::connect(upstream)?;
    // Startup: length, then protocol version and parameters. SSLRequest is
    // refused so the proxy sees plaintext; TLS terminates at the proxy listener.
    let mut len = [0u8; 4];
    client.read_exact(&mut len)?;
    let mut body = read_exact_vec(&mut client, u32::from_be_bytes(len) as usize - 4)?;
    if body.get(0..4) == Some(&[0x04, 0xd2, 0x16, 0x2f]) {
        client.write_all(b"N")?;
        client.read_exact(&mut len)?;
        body = read_exact_vec(&mut client, u32::from_be_bytes(len) as usize - 4)?;
    }
    let params = startup_params(&body);
    let user = params.iter().find(|(k, _)| k == "user").map(|(_, v)| v.clone()).unwrap_or_default();
    let db = params.iter().find(|(k, _)| k == "database").map(|(_, v)| v.clone()).unwrap_or_default();
    server.write_all(&len)?;
    server.write_all(&body)?;

    let pending: Arc<Mutex<Option<Pending>>> = Arc::new(Mutex::new(None));
    let (mut c_read, mut s_write) = (client.try_clone()?, server.try_clone()?);
    let (mut s_read, mut c_write) = (server, client);

    // Server to client: count DataRow, emit on CommandComplete.
    let (p2, sensor2, user2, db2, peer2) = (pending.clone(), sensor.clone(), user.clone(), db.clone(), peer.clone());
    let down = std::thread::spawn(move || -> std::io::Result<()> {
        loop {
            let mut h = [0u8; 5];
            s_read.read_exact(&mut h)?;
            let n = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize - 4;
            let b = read_exact_vec(&mut s_read, n)?;
            match h[0] {
                b'D' => {
                    if let Some(p) = p2.lock().unwrap().as_mut() {
                        p.rows += 1;
                    }
                }
                b'C' => {
                    if let Some(p) = p2.lock().unwrap().take() {
                        let st = classify(&p.sql);
                        let mut e = sensor2
                            .event(ocsf_class::DATASTORE_ACTIVITY, if st.schema_change { v::DB_SCHEMA_CHANGE } else { v::DB_QUERY })
                            .user(&user2, "service")
                            .src_ip(&peer2)
                            .attr("database", &db2)
                            .attr("table", &st.tables.first().cloned().unwrap_or_default())
                            .attr("operation", &st.operation)
                            .records(p.rows);
                        if st.destructive {
                            e = e.destructive();
                        }
                        sensor2.emit(e.build());
                    }
                }
                _ => {}
            }
            c_write.write_all(&h)?;
            c_write.write_all(&b)?;
        }
    });

    // Client to server: record statements and apply the local decision.
    loop {
        let mut h = [0u8; 5];
        if c_read.read_exact(&mut h).is_err() {
            break;
        }
        let n = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize - 4;
        let b = read_exact_vec(&mut c_read, n)?;
        let sql = match h[0] {
            b'Q' => Some(String::from_utf8_lossy(b.split(|x| *x == 0).next().unwrap_or(&[])).to_string()),
            b'P' => b.split(|x| *x == 0).nth(1).map(|s| String::from_utf8_lossy(s).to_string()),
            _ => None,
        };
        if let Some(sql) = sql {
            let probe = sensor.event(ocsf_class::DATASTORE_ACTIVITY, v::DB_QUERY).user(&user, "service").src_ip(&peer).build();
            if let Some(verdict) = sensor.should_block(&sensor.decide(&probe)) {
                let mut cw = c_read.try_clone()?;
                cw.write_all(&error_response(&format!("session ended by security policy ({})", verdict.verdict_id)))?;
                let _ = s_write.write_all(&[b'X', 0, 0, 0, 4]);
                break;
            }
            *pending.lock().unwrap() = Some(Pending { sql, rows: 0 });
        }
        s_write.write_all(&h)?;
        s_write.write_all(&b)?;
        if h[0] == b'X' {
            break;
        }
    }
    let _ = s_write.shutdown(std::net::Shutdown::Both);
    let _ = down.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::sign::Keyring;
    use ivar_sensor_kit::SensorConfig;
    use std::net::TcpListener;

    fn msg(t: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![t];
        m.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn counts_rows_per_statement() {
        // A fake PostgreSQL server: returns three DataRows then CommandComplete.
        let srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut c, _) = srv.accept().unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let _ = read_exact_vec(&mut c, u32::from_be_bytes(len) as usize - 4).unwrap();
            let mut h = [0u8; 5];
            c.read_exact(&mut h).unwrap();
            let _ = read_exact_vec(&mut c, u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize - 4).unwrap();
            for _ in 0..3 {
                c.write_all(&msg(b'D', &[0, 1, 0, 0, 0, 1, b'x'])).unwrap();
            }
            c.write_all(&msg(b'C', b"SELECT 3\0")).unwrap();
            c.write_all(&msg(b'Z', b"I")).unwrap();
        });
        let sensor = Arc::new(Sensor::new(SensorConfig { state_dir: std::env::temp_dir().join("ivar-pg-test").display().to_string(), ..Default::default() }, Keyring::default()));
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let s2 = sensor.clone();
        std::thread::spawn(move || {
            let (c, _) = proxy.accept().unwrap();
            let _ = session(s2, c, &srv_addr);
        });
        let mut c = TcpStream::connect(proxy_addr).unwrap();
        let mut startup = vec![0, 3, 0, 0];
        startup.extend_from_slice(b"user\0lookup-svc\0database\0cpr\0\0");
        let mut m = ((startup.len() + 4) as u32).to_be_bytes().to_vec();
        m.extend(startup);
        c.write_all(&m).unwrap();
        c.write_all(&msg(b'Q', b"select * from persons\0")).unwrap();
        let mut got = vec![0u8; 3 * 12 + 14 + 6];
        c.read_exact(&mut got).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(sensor.buffered().0, 1, "one statement event with its rows");
    }

    #[test]
    fn error_response_shape() {
        let e = error_response("x");
        assert_eq!(e[0], b'E');
        assert_eq!(u32::from_be_bytes([e[1], e[2], e[3], e[4]]) as usize, e.len() - 1);
    }
}
