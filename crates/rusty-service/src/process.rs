//! Real implementations of the supervisor's traits: a child process and the router RPC.

use crate::supervisor::{Child, Control, Launcher};
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

pub struct RouterProcess {
    pub exe: PathBuf,
    pub args: Vec<String>,
    /// Router stdout and stderr go here (appended), so a router that dies at start says why.
    pub console_log: Option<PathBuf>,
    #[cfg(windows)]
    job: Option<job::Job>,
}

impl RouterProcess {
    pub fn new(exe: PathBuf, args: Vec<String>) -> Self {
        RouterProcess {
            exe,
            args,
            console_log: None,
            #[cfg(windows)]
            job: None,
        }
    }
}

/// A job object that ends every process in it when its last handle closes. The router is
/// put in one so that if rusty-service itself is killed, the router goes with it instead of
/// running on unsupervised (and holding the RPC port so the next start can't work).
#[cfg(windows)]
mod job {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    pub struct Job(HANDLE);

    // The handle is only used from the supervisor thread; it's closed when the process exits.
    unsafe impl Send for Job {}

    impl Job {
        pub fn new() -> io::Result<Job> {
            unsafe {
                let h = CreateJobObjectW(None, PCWSTR::null()).map_err(io::Error::other)?;
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    h,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
                .map_err(io::Error::other)?;
                Ok(Job(h))
            }
        }

        pub fn assign(&self, child: &std::process::Child) -> io::Result<()> {
            unsafe {
                AssignProcessToJobObject(self.0, HANDLE(child.as_raw_handle() as _))
                    .map_err(io::Error::other)
            }
        }
    }
}

pub struct Proc(std::process::Child);

impl Child for Proc {
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        Ok(self.0.try_wait()?.map(|s| s.code().unwrap_or(-1)))
    }
    fn kill(&mut self) -> io::Result<()> {
        self.0.kill()
    }
}

impl Launcher for RouterProcess {
    type C = Proc;
    fn spawn(&mut self) -> io::Result<Proc> {
        let mut cmd = Command::new(&self.exe);
        cmd.args(&self.args).stdin(Stdio::null());
        if let Some(path) = &self.console_log {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            cmd.stdout(f.try_clone()?).stderr(f);
        }
        if let Some(dir) = self.exe.parent() {
            if !dir.as_os_str().is_empty() {
                cmd.current_dir(dir);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let child = cmd.spawn().map_err(|e| {
            io::Error::new(e.kind(), format!("can't start {}: {e}", self.exe.display()))
        })?;
        #[cfg(windows)]
        {
            if self.job.is_none() {
                self.job = Some(job::Job::new()?);
            }
            if let Err(e) = self.job.as_ref().unwrap().assign(&child) {
                let mut child = child;
                let _ = child.kill();
                return Err(io::Error::new(
                    e.kind(),
                    format!("can't tie the router to the service: {e}"),
                ));
            }
        }
        Ok(Proc(child))
    }
}

pub struct RpcControl {
    pub addr: String,
    pub auth: Option<String>,
}

impl Control for RpcControl {
    fn ready(&mut self) -> bool {
        rusty_rpc::Client::connect(&self.addr, Duration::from_millis(500))
            .and_then(|c| c.with_auth(self.auth.clone()).version())
            .is_ok()
    }
    fn halt(&mut self) {
        if let Ok(c) = rusty_rpc::Client::connect(&self.addr, Duration::from_secs(2)) {
            let _ = c.with_auth(self.auth.clone()).halt();
        }
    }
    fn exits(&mut self) -> Option<Vec<crate::guard::ExitView>> {
        let l = rusty_rpc::Client::connect(&self.addr, Duration::from_secs(2))
            .and_then(|c| c.with_auth(self.auth.clone()).list_exits())
            .ok()?;
        Some(
            l.exits
                .into_iter()
                .map(|e| crate::guard::ExitView {
                    address: e.address,
                    live: e.session_live && e.exit_capable,
                })
                .collect(),
        )
    }
    fn unmap(&mut self, address: &str) -> Result<(), String> {
        rusty_rpc::Client::connect(&self.addr, Duration::from_secs(5))
            .and_then(|c| c.with_auth(self.auth.clone()).unmap_exit(address))
            .map_err(|e| e.to_string())
    }
}
