//! ivar-windows-agent: the Windows host sensor.
//!
//! Collects new processes (Toolhelp snapshots), TCP connections with their
//! owning process (GetExtendedTcpTable), logons and account creation from
//! the Security log (4624, 4625, 4720) and new services from the System log
//! (7045). Enforcement: terminate a blocked process after capturing its
//! details; connections are cut by terminating their owner.

mod model;
#[cfg(windows)]
mod win;

fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        win::run()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("ivar-windows-agent runs on Windows; use ivar-linux-agent on Linux")
    }
}
