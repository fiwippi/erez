use std::cell::{Cell, RefCell};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Once;
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::time::sleep;

thread_local! {
    // Used to suppress panic output during assert_eventually retries. We catch
    // panics with catch_unwind, but the default panic hook still prints to stderr
    // before the unwind is caught. This flag lets our custom hook silently discard
    // those expected panics. It's thread-local so concurrent tests on different
    // threads can independently control suppression.
    #[doc(hidden)]
    static SUPPRESS_PANIC_OUTPUT: Cell<bool> = const { Cell::new(false) };

    // Captures the source location and message from the last suppressed panic.
    // The panic payload from catch_unwind only contains the message text — the
    // source location is only available to the panic hook via PanicInfo. We
    // capture both here so the final error output can point to the exact inner
    // assertion that failed.
    #[doc(hidden)]
    static LAST_PANIC_INFO: RefCell<Option<String>> = const { RefCell::new(None) };
}

// Ensures the custom panic hook is installed exactly once across all threads
// and all calls to assert_eventually.
#[doc(hidden)]
static INSTALL_HOOK: Once = Once::new();

/// Repeatedly evaluates a block containing assertions until all pass or the
/// timeout is reached. On timeout, panics with the last assertion failure
/// message.
#[macro_export]
macro_rules! assert_eventually {
    ($body:expr, $timeout:expr) => {{
    if let Err(panic_info) = $crate::assert::assert_eventually(|| async { $body }, $timeout).await {
        let mut msg = format!("assertion not met within {:?}", $timeout);
        if !panic_info.is_empty() {
            msg.push_str("\n");
            msg.push_str(&panic_info);
        }
        panic!("{msg}");
    }}};
    // Support a trailing comma.
    ($body:expr, $timeout:expr,) => {{
        $crate::assert_eventually!($body, $timeout)
    }};
    ($body:expr, $timeout:expr, $($arg:tt)+) => {{
    if let Err(panic_info) = $crate::assert::assert_eventually(|| async { $body }, $timeout).await {
        let mut msg = format!("assertion not met within {:?}: {}", $timeout, format_args!($($arg)+));
        if !panic_info.is_empty() {
            msg.push_str("\n");
            msg.push_str(&panic_info);
        }
        panic!("{msg}");
    }}};
}

#[doc(hidden)]
pub async fn assert_eventually<F, Fut>(mut f: F, timeout: Duration) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    INSTALL_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            SUPPRESS_PANIC_OUTPUT.with(|suppress| {
                if suppress.get() {
                    // We format the inner panic message cleanly.
                    let location = info
                        .location()
                        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
                    let message = info
                        .payload()
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| {
                            info.payload()
                                .downcast_ref::<&str>()
                                .map(ToString::to_string)
                        })
                        .unwrap_or_default();
                    LAST_PANIC_INFO.with(|cell| {
                        *cell.borrow_mut() = Some(match location {
                            Some(loc) => format!("at {loc}\n{message}"),
                            None => message,
                        });
                    });
                } else {
                    eprintln!("{info}");
                }
            });
        }));
    });

    let tick = Duration::from_millis(100);
    let deadline = Instant::now() + timeout;

    loop {
        SUPPRESS_PANIC_OUTPUT.with(|s| s.set(true));
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = tokio::time::timeout(remaining, AssertUnwindSafe(f()).catch_unwind()).await;
        SUPPRESS_PANIC_OUTPUT.with(|s| s.set(false));

        match result {
            // Assertion passed.
            Ok(Ok(())) => return Ok(()),
            // Assertion panicked.
            Ok(Err(_)) => {
                if Instant::now() >= deadline {
                    return Err(LAST_PANIC_INFO
                        .with(|c| c.borrow_mut().take())
                        .unwrap_or_default());
                }
                sleep(tick).await;
            }
            // Timed out.
            Err(_) => {
                return Err(LAST_PANIC_INFO
                    .with(|c| c.borrow_mut().take())
                    .unwrap_or_default());
            }
        }
    }
}
