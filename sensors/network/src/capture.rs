//! Raw packet capture with an AF_PACKET socket.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
pub fn run(iface: &str, stop: &AtomicBool, mut on_frame: impl FnMut(&[u8])) -> anyhow::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32);
        if fd < 0 {
            anyhow::bail!("AF_PACKET socket: {} (needs CAP_NET_RAW)", std::io::Error::last_os_error());
        }
        let name = std::ffi::CString::new(iface)?;
        let index = libc::if_nametoindex(name.as_ptr());
        if index == 0 {
            anyhow::bail!("unknown interface {iface}");
        }
        let mut addr: libc::sockaddr_ll = std::mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = index as i32;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) != 0 {
            anyhow::bail!("bind {iface}: {}", std::io::Error::last_os_error());
        }
        let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
        let mut buf = vec![0u8; 65_536];
        while !stop.load(Ordering::Relaxed) {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n > 0 {
                on_frame(&buf[..n as usize]);
            }
        }
        libc::close(fd);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run(_iface: &str, _stop: &AtomicBool, _on_frame: impl FnMut(&[u8])) -> anyhow::Result<()> {
    anyhow::bail!("raw capture is implemented for Linux; use the Suricata EVE input elsewhere")
}
