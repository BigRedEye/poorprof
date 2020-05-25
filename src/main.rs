use std::env;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::fmt::Write;
use inferno::flamegraph;

fn try_demangle_symbol(s: &str) -> String {
    let sym = match cpp_demangle::Symbol::new(s) {
        Ok(sym) => sym,
        Err(_) => return s.into(),
    };
    sym.to_string()
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Failed to set ^C handler");

    // FIXME(BigRedEye) clap
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("Usage: {} <pid>", args[0]);
        process::exit(1);
    }

    let pid = match args[1].parse() {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("error parsing PID: {}", e);
            process::exit(1);
        }
    };

    let mut stacks = Vec::new();

    while running.load(Ordering::SeqCst) {
        // FIXME(BigRedEye) Do not resolve symbols at runtime
        // FIXME(BigRedEye) Do not reattach every time
        let res = rstack::TraceOptions::new()
            .thread_names(false)
            .symbols(true)
            .trace(pid);
        let process = match res {
            Ok(threads) => threads,
            Err(e) => {
                eprintln!("Error tracing threads: {}", e);
                break;
            }
        };

        for thread in process.threads() {
            let mut stack = String::new();
            for frame in thread.frames().iter().rev() {
                let sym = match frame.symbol() {
                    Some(symbol) => try_demangle_symbol(symbol.name()),
                    None => "<unknown>".into()
                };
                write!(&mut stack, "{};", sym).unwrap();
            }
            if stack.len() > 0 {
                stack.pop();
            }
            write!(&mut stack, " 1").unwrap();
            stacks.push(stack);
        }
    }

    let mut opts = flamegraph::Options::default();
    flamegraph::from_lines(&mut opts, stacks.iter().map(String::as_str), std::io::stdout()).unwrap();
    eprintln!("Sucessfully dumped flamegrah with {} stacks", stacks.len());
}
