use std::{borrow::Cow, io::Read, os::fd::AsFd};

use clap::{CommandFactory, Parser};
use libc::{VMIN, VTIME};
use nix::sys::{
    signal::SigHandler,
    termios::{self, LocalFlags, SetArg},
};
use reedline::{
    ColumnarMenu, DefaultCompleter, Emacs, FileBackedHistory, KeyCode, KeyModifiers, MenuBuilder,
    Prompt, PromptHistorySearchStatus, Reedline, ReedlineEvent, ReedlineMenu,
    default_emacs_keybindings,
};

use crate::ns::Ns;

#[derive(Debug, Parser)]
enum Command {
    /// Show info about all namespaces in the topology.
    Info,

    /// Run a command inside a namespace.
    Exec {
        /// Namespace display name.
        ns: String,

        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// Stream live log output from all namespaces.
    Logs,

    /// Clear the terminal.
    Clear,

    /// Exit the REPL.
    Exit,
}

pub fn run(namespaces: &[&Ns]) -> anyhow::Result<()> {
    let mut line_editor = build_line_editor(namespaces)?;
    let prompt = ReplPrompt {};

    loop {
        let sig = line_editor.read_line(&prompt);

        use reedline::Signal as S;
        let line = match sig {
            Ok(S::Success(l)) => l,
            Ok(S::CtrlC) => continue,
            Ok(S::CtrlD) => break,
            Err(e) => {
                eprintln!("REPL error: {e:?}");
                continue;
            }
        };
        if line.is_empty() {
            continue;
        }

        // Clap expects the first argument to be the program
        // name, we just specify an empty string instead.
        let mut args = shlex::split(&line).ok_or(anyhow::anyhow!("shlex parsing failed"))?;
        args.insert(0, String::new());
        match Command::try_parse_from(args) {
            Ok(cmd) => match cmd {
                Command::Info => dispatch_info(namespaces),
                Command::Exec { ns, cmd } => dispatch_exec(namespaces, &ns, &cmd),
                Command::Logs => dispatch_logs(),
                Command::Clear => dispatch_clear(&mut line_editor),
                Command::Exit => break,
            },
            Err(e) => {
                let _ = e.print();
            }
        }
    }

    Ok(())
}

fn dispatch_info(namespaces: &[&Ns]) {
    info::print_overview(namespaces);
}

mod info {
    use crate::ns::Ns;

    pub fn print_overview(namespaces: &[&Ns]) {
        print_table(
            "Overview",
            &["NAME", "NETNS PATH", "PID"],
            &namespaces
                .iter()
                .map(|ns| {
                    [
                        ns.display_name().to_string(),
                        ns.net_ns().path(),
                        ns.pid().to_string(),
                    ]
                })
                .collect::<Vec<_>>(),
        );
    }

    fn print_table<const N: usize>(title: &str, headers: &[&str; N], rows: &[[String; N]]) {
        let mut widths = [0; N];
        for (i, header) in headers.iter().enumerate() {
            widths[i] = header.len();
        }
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.len());
            }
        }

        println!("{title}:");

        let header_line: String = headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:<w$}", h, w = widths[i]))
            .collect::<Vec<_>>()
            .join("  ");
        println!("  {header_line}");

        for row in rows {
            let line: String = row
                .iter()
                .enumerate()
                .map(|(i, cell)| format!("{:<w$}", cell, w = widths[i]))
                .collect::<Vec<_>>()
                .join("  ");
            println!("  {line}");
        }
    }
}

fn dispatch_exec(namespaces: &[&Ns], ns_name: &str, cmd: &[String]) {
    let Some(ns) = namespaces.iter().find(|ns| ns.display_name() == ns_name) else {
        eprintln!("Unknown ns: {ns_name}");
        return;
    };

    let mut nsenter = std::process::Command::new("nsenter");
    nsenter.args(["--target", &ns.pid().to_string(), "--all", "--"]);
    nsenter.args(cmd);

    // Inherit the real terminal for full interactivity.
    nsenter.stdin(std::process::Stdio::inherit());
    nsenter.stdout(std::process::Stdio::inherit());
    nsenter.stderr(std::process::Stdio::inherit());

    // Ignore SIGINT in the REPL process so Ctrl+C only kills the child.
    let prev =
        unsafe { nix::sys::signal::signal(nix::sys::signal::Signal::SIGINT, SigHandler::SigIgn) }
            .unwrap();

    let _ = nsenter.status();

    // Restore previous SIGINT handler.
    unsafe {
        let _ = nix::sys::signal::signal(nix::sys::signal::Signal::SIGINT, prev);
    };
}

fn dispatch_logs() {
    println!("Streaming live output from all namespaces (press 'q' to stop)...");

    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let orig = termios::tcgetattr(fd).expect("tcgetattr");
    let mut raw = orig.clone();

    // See: https://man7.org/linux/man-pages/man3/termios.3.html

    // Make terminal input immediately available to read, instead
    // of buffering until a line-delimiter character is typed.
    raw.local_flags.remove(LocalFlags::ICANON);
    // Don't echo keypresses back to the terminal.
    raw.local_flags.remove(LocalFlags::ECHO);
    // Don't generate SIGINT, (and other signals) when receiving
    // the appropriate characters.
    raw.local_flags.remove(LocalFlags::ISIG);

    // Block indefinitely until at least one byte of information
    // is readable.
    raw.control_chars[VMIN] = 1;
    raw.control_chars[VTIME] = 0;

    // Apply immediately (TCSANOW) rather than draining output first,
    // since we want the input side to switch right away.
    termios::tcsetattr(fd, SetArg::TCSANOW, &raw).expect("tcsetattr");

    crate::ns::set_stderr_suppressed(false);

    // Read loop; only 'q' exits.
    let mut buf = [0u8; 1];
    while let Ok(1) = stdin.lock().read(&mut buf) {
        if buf[0] == b'q' {
            break;
        }
    }

    crate::ns::set_stderr_suppressed(true);
    termios::tcsetattr(fd, SetArg::TCSANOW, &orig).expect("tcsetattr restore");

    println!("Returning to REPL...");
}

fn dispatch_clear(line_editor: &mut Reedline) {
    let _ = line_editor.clear_screen();
}

fn build_line_editor(namespaces: &[&Ns]) -> anyhow::Result<Reedline> {
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );

    let line_editor = Reedline::create()
        .with_history(Box::new(FileBackedHistory::with_file(
            1000,
            "/tmp/.erez_console_history".into(),
        )?))
        .with_completer(build_completer(namespaces))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(
            ColumnarMenu::default().with_name("completion_menu"),
        )))
        .with_edit_mode(Box::new(Emacs::new(keybindings)));

    Ok(line_editor)
}

// reedline expects a boxed completer, so we box
// it when building instead of at a later point.
#[allow(clippy::unnecessary_box_returns)]
fn build_completer(namespaces: &[&Ns]) -> Box<DefaultCompleter> {
    let mut completions: Vec<String> = Vec::new();
    for sub in Command::command().get_subcommands() {
        let name = sub.get_name().to_string();

        let takes_ns = sub.get_arguments().any(|arg| arg.get_id() == "ns");
        if takes_ns {
            for ns in namespaces {
                completions.push(format!("{name} {}", ns.display_name()));
            }
        }

        completions.push(name);
    }

    // Some namespace names have an underscore or hyphen
    // in them, so we need to explicitly allow completing
    // against these characters; the default is a-z, A-Z.
    let mut completer = DefaultCompleter::with_inclusions(&['_', '-', ':']);
    completer.insert(completions);
    Box::new(completer)
}

struct ReplPrompt {}

impl Prompt for ReplPrompt {
    fn render_prompt_left(&self) -> Cow<str> {
        Cow::Borrowed("")
    }

    fn render_prompt_right(&self) -> Cow<str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(
        &self,
        _prompt_mode: reedline::PromptEditMode,
    ) -> std::borrow::Cow<str> {
        Cow::Borrowed(">> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: reedline::PromptHistorySearch,
    ) -> std::borrow::Cow<str> {
        let term = match history_search.status {
            PromptHistorySearchStatus::Passing => {
                if history_search.term.is_empty() {
                    String::new()
                } else {
                    format!("({}) ", history_search.term)
                }
            }
            PromptHistorySearchStatus::Failing => format!("(failing: {}) ", history_search.term),
        };
        Cow::Owned(term)
    }
}
