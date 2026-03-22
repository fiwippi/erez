use std::{
    future::Future,
    io::{BufRead, BufReader, Write},
    os::fd::OwnedFd,
    pin::Pin,
    process::Output,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use nix::{
    fcntl::OFlag,
    mount::MsFlags,
    sched::CloneFlags,
    sys::{signal::Signal, stat::Mode},
    unistd::Pid,
};
use rand::Rng;
use tokio::{
    runtime::Runtime,
    sync::{mpsc, oneshot},
};

const NET_NS_PREFIX: &str = "erez";

/// A persistent Linux network namespace.
#[derive(Debug, Clone)]
pub struct NetNs {
    inner: Arc<NetNsInner>,
}

#[derive(Debug)]
struct NetNsInner {
    display_name: String,
    system_name: String,
}

impl NetNs {
    pub async fn new(name: &str) -> anyhow::Result<NetNs> {
        let system_name = {
            let id: u16 = rand::rng().random();
            format!("{NET_NS_PREFIX}_{name}_{id:04x}")
        };
        rtnetlink::NetworkNamespace::add(system_name.clone()).await?;
        Ok(NetNs {
            inner: Arc::new(NetNsInner {
                display_name: name.to_string(),
                system_name,
            }),
        })
    }

    pub fn display_name(&self) -> &str {
        &self.inner.display_name
    }

    pub fn system_name(&self) -> &str {
        &self.inner.system_name
    }

    pub fn path(&self) -> String {
        format!("/var/run/netns/{}", self.inner.system_name)
    }
}

impl Drop for NetNsInner {
    fn drop(&mut self) {
        // We need to use the std::process::Command abstraction
        // to remove the namespace instead of rtnetlink, because
        // we cannot perform async calls when dropping.
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.system_name])
            .output();
    }
}

/// A task executor pinned to a set of Linux namespaces.
#[derive(Debug, Clone)]
pub struct Ns {
    inner: Arc<NsInner>,
}

impl Ns {
    pub fn builder(net_ns: NetNs) -> NsBuilder {
        NsBuilder {
            net_ns,
            mount_name: None,
            // Also mount /tmp by default so that regardless
            // of additional mounts, each namespace has its
            // own private scratch space.
            mount_dirs: vec!["/tmp".to_string()],
        }
    }

    pub async fn net(name: &str) -> anyhow::Result<Ns> {
        let net = NetNs::new(name).await?;
        Self::builder(net).build().await
    }

    pub fn display_name(&self) -> &str {
        &self.inner.display_name
    }

    pub fn pid(&self) -> Pid {
        self.inner.pid
    }

    pub fn net_ns(&self) -> &NetNs {
        &self.inner.net_ns
    }

    pub fn spawn<F, R>(&self, future: F) -> JoinHandle<R>
    where
        F: Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        let (ret_tx, ret_rx) = oneshot::channel();
        let task: BoxedTask = Box::pin(async move {
            let ret = future.await;
            let _ = ret_tx.send(ret);
        });

        // If this fails to send, joining on the task
        // instantly returns, because ret_rx will be
        // dropped.
        let _ = self.inner.task_tx.send(task);

        JoinHandle { ret_rx }
    }

    pub async fn spawn_process(&self, cmd: &str, args: &[&str]) -> anyhow::Result<NsChild> {
        let cmd = cmd.to_string();
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();

        let result: Result<_, anyhow::Error> = self
            .spawn(async move {
                let child = tokio::process::Command::new(&cmd)
                    .args(&args)
                    // New process group so terminal Ctrl+C doesn't reach daemon processes.
                    .process_group(0)
                    .spawn()?;
                let pid = child.id().expect("fresh process always has a PID");
                Ok(pid)
            })
            .await?;

        let pid = Pid::from_raw(result? as i32);
        self.inner.children.lock().unwrap().push(pid);
        Ok(NsChild { pid })
    }

    pub async fn exec(&self, cmd: &str, args: &[&str]) -> anyhow::Result<Output> {
        let cmd = cmd.to_string();
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let output = self
            .spawn(async move {
                tokio::process::Command::new(&cmd)
                    .args(&args)
                    .output()
                    .await
            })
            .await??;
        Ok(output)
    }

    pub async fn exec_checked(&self, cmd: &str, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let output = self.exec(cmd, args).await?;
        if !output.status.success() {
            anyhow::bail!(
                "{} exited with code {:?}, stderr: {:?}",
                cmd,
                output.status.code().unwrap(),
                String::from_utf8_lossy(&output.stderr).trim(),
            );
        }
        Ok(output.stdout)
    }
}

#[must_use]
pub struct NsBuilder {
    net_ns: NetNs,
    mount_name: Option<String>,
    mount_dirs: Vec<String>,
}

impl NsBuilder {
    pub fn mount(mut self, name: &str, dirs: &[&str]) -> Self {
        self.mount_name = Some(name.to_string());
        self.mount_dirs = dirs.iter().map(ToString::to_string).collect();
        self
    }

    pub async fn build(self) -> anyhow::Result<Ns> {
        // Derive stderr's display name from the namespaces we're entering.
        let display_name = match &self.mount_name {
            Some(mnt) => format!("{}:{mnt}", self.net_ns.display_name()),
            None => self.net_ns.display_name().to_string(),
        };

        // A thread may only belong to one ns of each type.
        // To ensure all commands/tasks are run in same ns,
        // we pin a dedicated thread to solely run in it.
        let (pid_tx, pid_rx) = oneshot::channel::<anyhow::Result<Pid>>();
        let (task_tx, task_rx) = mpsc::unbounded_channel::<BoxedTask>();
        let thread_handle = thread::Builder::new()
            .name(format!("ns_{display_name}"))
            .spawn({
                let net_ns_system_name = self.net_ns.system_name().to_string();
                let display_name = display_name.clone();
                move || {
                    dedicated_thread(
                        &net_ns_system_name,
                        &self.mount_dirs,
                        display_name,
                        pid_tx,
                        task_rx,
                    );
                }
            })?;
        let pid = pid_rx.await??;

        Ok(Ns {
            inner: Arc::new(NsInner {
                display_name,
                pid,
                task_tx,
                children: Mutex::new(Vec::new()),
                _thread: thread_handle,
                net_ns: self.net_ns,
            }),
        })
    }
}

#[derive(Debug)]
struct NsInner {
    /// Human-readable name derived from the namespaces
    /// this executor entered (e.g. "edge/bird").
    display_name: String,

    /// PID of the dedicated thread.
    pid: Pid,

    /// Channel for sending tasks to the dedicated thread.
    task_tx: mpsc::UnboundedSender<BoxedTask>,

    /// Child processes tracked for cleanup on drop.
    children: Mutex<Vec<Pid>>,

    // Held to keep the net namespace alive.
    net_ns: NetNs,

    /// Held to keep the dedicated thread alive.
    _thread: thread::JoinHandle<()>,
}

impl Drop for NsInner {
    fn drop(&mut self) {
        // Linux keeps processes alive even after their
        // namespace is deleted, so we cleanup manually.
        for &pid in self.children.get_mut().unwrap().iter() {
            let _ = nix::sys::signal::kill(pid, Signal::SIGTERM);
        }
    }
}

/// A handle to a child process running inside a namespace.
pub struct NsChild {
    pid: Pid,
}

impl NsChild {
    pub fn exists(&self) -> bool {
        nix::sys::signal::kill(self.pid, None).is_ok()
    }

    /// Send SIGTERM to the child process.
    pub fn terminate(&self) -> anyhow::Result<()> {
        nix::sys::signal::kill(self.pid, Signal::SIGTERM)?;
        Ok(())
    }
}

impl Drop for NsChild {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub struct JoinHandle<R> {
    ret_rx: oneshot::Receiver<R>,
}

impl<R> JoinHandle<R> {
    pub async fn join(self) -> anyhow::Result<R> {
        self.ret_rx.await.map_err(|e| anyhow::anyhow!(e))
    }
}

// Allows us to await the handle directly instead
// of joining and then awaiting separately.
impl<R: Send + 'static> std::future::IntoFuture for JoinHandle<R> {
    type Output = anyhow::Result<R>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.join())
    }
}

type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

fn dedicated_thread(
    net_ns_system_name: &str,
    mount_dirs: &[String],
    display_name: String,
    pid_tx: oneshot::Sender<anyhow::Result<Pid>>,
    mut task_rx: mpsc::UnboundedReceiver<BoxedTask>,
) {
    // Spawn up a single-threaded runtime to only
    // process tasks on the dedicated thread.
    let init_rt = (|| -> anyhow::Result<Runtime> {
        enter_netns(net_ns_system_name)?;
        enable_loopback()?;
        disable_dad()?;

        if !mount_dirs.is_empty() {
            let dirs: Vec<&str> = mount_dirs.iter().map(String::as_str).collect();
            mount_tmpfs(&dirs)?;
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(rt)
    })();
    let rt = match init_rt {
        Ok(rt) => rt,
        Err(e) => {
            let _ = pid_tx.send(Err(anyhow::anyhow!(e)));
            return;
        }
    };

    // Redirect stderr to a pipe and spawn a reader thread
    // that prepends [display_name] to each line being
    // written to stderr.
    match redirect_stderr() {
        Ok((pipe_r, dup_stderr)) => {
            thread::spawn(move || pipe_with_prefix(pipe_r, dup_stderr, &display_name));
        }
        Err(e) => {
            let _ = pid_tx.send(Err(e));
            return;
        }
    }

    // Signal the namespace thread has been set up successfully.
    let _ = pid_tx.send(Ok(nix::unistd::gettid()));

    // Now we can accept incoming tasks and
    // run them on our dedicated thread.
    rt.block_on(async move {
        while let Some(task) = task_rx.recv().await {
            tokio::spawn(task);
        }
    });
    rt.shutdown_background();
}

// Join the given network namespace so the calling
// thread gets its own isolated network stack.
fn enter_netns(name: &str) -> anyhow::Result<()> {
    let path = format!("/var/run/netns/{name}");
    let fd = nix::fcntl::open(path.as_str(), OFlag::O_RDONLY, Mode::empty())?;
    nix::sched::setns(&fd, CloneFlags::CLONE_NEWNET)?;
    Ok(())
}

// Create a new mount namespace and mount empty tmpfs
// over the given directories, making anything written
// there private to the mount namespace.
fn mount_tmpfs(dirs: &[&str]) -> anyhow::Result<()> {
    nix::sched::unshare(CloneFlags::CLONE_NEWNS)?;

    // Make the entire mount tree private so that
    // mounts we create don't propagate back to
    // the parent, and parent mounts aren't shown
    // to us.
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    // An empty, in-memory filesystem is mounted over these directories,
    // hiding their original contents and making anything written there
    // private to the mount namespace.
    for dir in dirs {
        nix::mount::mount(
            Some("tmpfs"),
            *dir,
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )?;
    }
    Ok(())
}

// Turn on the loopback interface, which is disabled
// by default in new namespaces. This allows us to
// spin up arbitrary servers.
fn enable_loopback() -> anyhow::Result<()> {
    let status = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .output()?
        .status;
    if !status.success() {
        anyhow::bail!("Failed bringing up loopback: exit {status}");
    }
    Ok(())
}

/// Disable IPv6 Duplicate Address Detection (DAD), which
/// delays address usability by ~1s in new namespaces.
fn disable_dad() -> anyhow::Result<()> {
    std::fs::write("/proc/sys/net/ipv6/conf/all/accept_dad", "0")?;
    std::fs::write("/proc/sys/net/ipv6/conf/default/accept_dad", "0")?;
    Ok(())
}

fn redirect_stderr() -> anyhow::Result<(OwnedFd, OwnedFd)> {
    // Give the thread its own fd table, so that
    // redirecting stderr into the pipe doesn't
    // affect other threads.
    nix::sched::unshare(CloneFlags::CLONE_FILES)?;

    // We duplicate the original stderr fd,
    // so that we can write to the terminal
    // ourselves.
    let dup_stderr = nix::unistd::dup(std::io::stderr())?;

    // Create a pipe and redirect writing for
    // the original stderr fd into it, (this
    // doesn't affect our duplicated fd).
    let (pipe_rx, pipe_tx) = nix::unistd::pipe()?;
    nix::unistd::dup2_stderr(pipe_tx)?;

    Ok((pipe_rx, dup_stderr))
}

static STDERR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

static STDERR_SUPPRESSED: AtomicBool = AtomicBool::new(false);

pub fn set_stderr_suppressed(suppressed: bool) {
    STDERR_SUPPRESSED.store(suppressed, Ordering::Relaxed);
}

fn pipe_with_prefix(input: OwnedFd, output: OwnedFd, prefix: &str) {
    let mut reader = BufReader::new(std::fs::File::from(input));
    let mut writer = std::fs::File::from(output);
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("/tmp/ns.log")
        .unwrap();

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                // Write the raw line to the log file (no prefix).
                let _ = log.write_all(line.as_bytes());

                // Write to stderr with [name] prefix, if not suppressed.
                if !STDERR_SUPPRESSED.load(Ordering::Relaxed) {
                    // Stop multiple writes causing corrupted output.
                    let _guard = STDERR_LOCK.lock().unwrap();
                    let _ = write!(writer, "[{prefix}] {line}");
                }
            }
        }
    }
}

pub async fn cleanup_netns() -> anyhow::Result<()> {
    let ns_dir = std::path::Path::new("/var/run/netns");
    if !ns_dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(ns_dir)? {
        let name = {
            let entry = entry?;
            let name = entry.file_name();
            name.to_string_lossy().to_string()
        };
        if name.starts_with(&format!("{NET_NS_PREFIX}_")) {
            let _ = rtnetlink::NetworkNamespace::del(name).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    async fn wait_for_process_reap() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn exec_returns_stdout() {
        let ns = Ns::net("test").await.unwrap();
        let output = ns.exec("echo", &["hello"]).await.unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "hello\n");
    }

    #[tokio::test]
    async fn inflight_task_fails_on_ns_drop() {
        let ns = Ns::net("test").await.unwrap();
        let handle = ns.spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        drop(ns);
        let result = handle.await;
        assert!(
            result.is_err(),
            "in-flight task should fail when ns is dropped"
        );
    }

    #[tokio::test]
    async fn isolation_between_mntns_and_host() {
        let net_ns = NetNs::new("test").await.unwrap();
        let ns = Ns::builder(net_ns)
            .mount("test", &["/tmp"])
            .build()
            .await
            .unwrap();

        const PATH: &str = "/tmp/private";
        ns.spawn(async {
            tokio::fs::write(PATH, "cake").await.unwrap();
        })
        .await
        .unwrap();

        let content = ns
            .spawn(async { tokio::fs::read_to_string(PATH).await.unwrap() })
            .await
            .unwrap();
        assert_eq!(content, "cake", "file should be visible within the ns");

        assert!(
            !std::path::Path::new(PATH).exists(),
            "file in ns should be invisible from outside"
        );
    }

    #[tokio::test]
    async fn isolation_between_netns_and_host() {
        let ns = Ns::net("test").await.unwrap();

        let socket_addr = ns
            .spawn(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tokio::spawn(async move {
                    while let Ok((mut stream, _)) = listener.accept().await {
                        let _ = stream.write_all(b"cake").await;
                    }
                });
                addr
            })
            .await
            .unwrap();

        let msg = ns
            .spawn(async move {
                let mut stream = TcpStream::connect(socket_addr).await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                buf
            })
            .await
            .unwrap();
        assert_eq!(&msg, b"cake", "should receive data from inside the ns");

        let result = tokio::net::TcpStream::connect(socket_addr).await;
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "listener must be unreachable from outside the ns"
        );
    }

    #[tokio::test]
    async fn isolation_between_netns_and_netns() {
        let ns_a = Ns::net("a").await.unwrap();
        let ns_b = Ns::net("b").await.unwrap();

        let socket_addr = ns_a
            .spawn(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tokio::spawn(async move { while let Ok((_, _)) = listener.accept().await {} });
                addr
            })
            .await
            .unwrap();

        let err = ns_b
            .spawn(async move {
                tokio::net::TcpStream::connect(socket_addr)
                    .await
                    .unwrap_err()
            })
            .await
            .unwrap();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "ns_b must not reach ns_a's listener"
        );
    }

    #[tokio::test]
    async fn loopback_reachable_inside_ns() {
        let ns = Ns::net("test").await.unwrap();
        let output = ns
            .exec("ping", &["-c", "1", "-W", "1", "127.0.0.1"])
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "ping to loopback should succeed inside ns"
        );
    }

    #[tokio::test]
    async fn netns_lifecycle() {
        let ns = NetNs::new("test").await.unwrap();
        let path = ns.path();
        assert!(
            std::path::Path::new(&path).exists(),
            "namespace must exist in /var/run/netns after creation"
        );
        drop(ns);
        assert!(
            !std::path::Path::new(&path).exists(),
            "namespace must be removed from /var/run/netns after drop"
        );
    }

    #[tokio::test]
    async fn netns_unique_system_names() {
        let a = NetNs::new("dup").await.unwrap();
        let b = NetNs::new("dup").await.unwrap();
        assert_ne!(
            a.system_name(),
            b.system_name(),
            "same display name must produce different system names"
        );
    }

    #[tokio::test]
    async fn process_stopped_on_ns_teardown() {
        let ns = Ns::net("test").await.unwrap();
        let child = ns.spawn_process("sleep", &["60"]).await.unwrap();
        assert!(child.exists());
        drop(ns);
        wait_for_process_reap().await;
        assert!(!child.exists());
    }

    #[tokio::test]
    async fn process_stopped_on_terminate() {
        let ns = Ns::net("test").await.unwrap();
        let child = ns.spawn_process("sleep", &["60"]).await.unwrap();
        assert!(child.exists());
        child.terminate().unwrap();
        wait_for_process_reap().await;
        assert!(!child.exists());
    }
}
