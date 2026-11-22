//! Windows collection and enforcement.

use crate::model::{self, WinLogon, WinProcess};
use ivar_contracts::sign::Keyring;
use ivar_sensor_kit::{HttpUplink, Sensor, SensorConfig};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_ITEMS};
use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::System::EventLog::{EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn processes() -> Vec<WinProcess> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                let len = e.szExeFile.iter().position(|c| *c == 0).unwrap_or(e.szExeFile.len());
                out.push(WinProcess { pid: e.th32ProcessID, ppid: e.th32ParentProcessID, name: String::from_utf16_lossy(&e.szExeFile[..len]) });
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

fn terminate(pid: u32) -> bool {
    unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => {
                let ok = TerminateProcess(h, 1).is_ok();
                let _ = CloseHandle(h);
                ok
            }
            Err(_) => false,
        }
    }
}

fn tcp_connections() -> Vec<(u32, String, u16)> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        let mut buf = vec![0u8; size as usize];
        if GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != 0 {
            return vec![];
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID, table.dwNumEntries as usize);
        rows.iter()
            .map(|r| {
                let b = r.dwRemoteAddr.to_le_bytes();
                (r.dwOwningPid, format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), u16::from_be(r.dwRemotePort as u16))
            })
            .collect()
    }
}

fn query(channel: &str, xpath: &str, after_record: u64) -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let ch = wide(channel);
        let q = wide(xpath);
        let Ok(h) = EvtQuery(EVT_HANDLE::default(), PCWSTR(ch.as_ptr()), PCWSTR(q.as_ptr()), (EvtQueryChannelPath.0 | EvtQueryReverseDirection.0) as u32) else { return out };
        loop {
            let mut events = [0isize; 16];
            let mut returned = 0u32;
            if EvtNext(h, &mut events, 1000, 0, &mut returned).is_err() {
                let _ = ERROR_NO_MORE_ITEMS;
                break;
            }
            for raw in &events[..returned as usize] {
                let ev = EVT_HANDLE(*raw);
                let mut used = 0u32;
                let mut props = 0u32;
                let _ = EvtRender(EVT_HANDLE::default(), ev, EvtRenderEventXml.0 as u32, 0, None, &mut used, &mut props);
                let mut buf = vec![0u16; (used as usize / 2) + 1];
                if EvtRender(EVT_HANDLE::default(), ev, EvtRenderEventXml.0 as u32, used, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut props).is_ok() {
                    let xml = String::from_utf16_lossy(&buf[..(used as usize / 2).saturating_sub(1)]);
                    let rid: u64 = model::xml_system(&xml, "EventRecordID").parse().unwrap_or(0);
                    if rid > after_record {
                        out.push(xml);
                    }
                }
                let _ = EvtClose(ev);
            }
            if out.len() > 500 {
                break;
            }
        }
        let _ = EvtClose(h);
    }
    out
}

pub fn run() -> anyhow::Result<()> {
    let cfg_path = std::env::args().skip_while(|a| a != "--config").nth(1).unwrap_or_else(|| r"C:\ProgramData\ivar\agent.yaml".into());
    let mut cfg = SensorConfig::from_file(&cfg_path).unwrap_or_default();
    cfg.sensor_type = "host".into();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = sensor.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut up = HttpUplink::for_sensor(&cfg);
            s.run(&mut up, &|| stop.load(Ordering::Relaxed));
        });
    }
    let mut seen: BTreeSet<u32> = processes().into_iter().map(|p| p.pid).collect();
    let mut seen_conn: BTreeSet<(u32, String, u16)> = BTreeSet::new();
    let (mut last_sec, mut last_sys) = (0u64, 0u64);
    loop {
        let procs = processes();
        let names: BTreeMap<u32, String> = procs.iter().map(|p| (p.pid, p.name.clone())).collect();
        for p in procs.iter().filter(|p| !seen.contains(&p.pid)) {
            let ev = model::process_event(&sensor, &host, p, names.get(&p.ppid).map(String::as_str).unwrap_or(""));
            let d = sensor.decide(&ev);
            let mut ev = ev;
            if sensor.should_block(&d).is_some() && terminate(p.pid) {
                if let Some(x) = ev.ivar.as_mut() {
                    x.attributes.insert("enforced".into(), "terminated".into());
                }
            }
            sensor.emit(ev);
        }
        seen = procs.iter().map(|p| p.pid).collect();
        for c in tcp_connections() {
            if seen_conn.insert(c.clone()) {
                let ev = model::connection_event(&sensor, &host, c.0, names.get(&c.0).map(String::as_str).unwrap_or(""), &c.1, c.2);
                if sensor.should_block(&sensor.decide(&ev)).is_some() {
                    terminate(c.0);
                }
                sensor.emit(ev);
            }
        }
        for xml in query("Security", "*[System[(EventID=4624 or EventID=4625 or EventID=4720)]]", last_sec) {
            let l = WinLogon {
                event_id: model::xml_system(&xml, "EventID").parse().unwrap_or(0),
                user: model::xml_data(&xml, "TargetUserName"),
                ip: model::xml_data(&xml, "IpAddress"),
                logon_type: model::xml_data(&xml, "LogonType"),
                record_id: model::xml_system(&xml, "EventRecordID").parse().unwrap_or(0),
            };
            last_sec = last_sec.max(l.record_id);
            sensor.emit(model::logon_event(&sensor, &host, &l));
        }
        for xml in query("System", "*[System[(EventID=7045)]]", last_sys) {
            last_sys = last_sys.max(model::xml_system(&xml, "EventRecordID").parse().unwrap_or(0));
            sensor.emit(model::service_event(&sensor, &host, &model::xml_data(&xml, "ServiceName"), &model::xml_data(&xml, "ImagePath")));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
