#![forbid(unsafe_code)]

fn main() {
    std::process::exit(e2ee_cli::entry(std::env::args_os().skip(1).collect()));
}
