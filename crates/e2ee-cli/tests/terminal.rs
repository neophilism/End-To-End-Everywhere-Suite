#![cfg(unix)]

use std::process::Command;

#[test]
fn real_terminal_hides_passwords_and_restores_echo_on_success_and_ctrl_c() {
    // Python's standard-library PTY bindings create a real controlling terminal
    // without introducing unsafe FFI into the Rust workspace or mocking input.
    let script = r#"
import os, pty, select, termios, time, tempfile, pathlib, shutil, sys
binary = sys.argv[1]
parent = pathlib.Path(tempfile.mkdtemp(prefix='e2ee-terminal-test-'))
password = b'local test terminal unlock phrase'
def scenario(cancel):
    path = parent / ('cancel' if cancel else 'success')
    pid, master = pty.fork()
    if pid == 0:
        os.execv(binary, [binary, '--state', str(path), '--software-vault', '--password-only', 'init', 'terminal-test'])
    transcript = bytearray()
    reaped = False
    def until(marker):
        deadline = time.monotonic() + 25
        while marker not in transcript:
            if time.monotonic() > deadline:
                raise AssertionError('terminal prompt timed out')
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                transcript.extend(os.read(master, 65536))
    def hidden():
        deadline = time.monotonic() + 2
        while termios.tcgetattr(master)[3] & termios.ECHO:
            if time.monotonic() > deadline:
                raise AssertionError('password echo stayed enabled')
            select.select([], [], [], 0.01)
    try:
        until(b'New vault passphrase: ')
        hidden()
        if cancel:
            os.write(master, b'\x03')
            until(b'e2ee: operation interrupted')
        else:
            os.write(master, password + b'\r')
            until(b'Confirm new passphrase: ')
            hidden()
            os.write(master, password + b'\r')
            until(b'Created local encrypted identity.')
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == (130 if cancel else 0)
        assert password not in transcript
        assert termios.tcgetattr(master)[3] & termios.ECHO
        assert path.exists() != cancel
    finally:
        if not reaped:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        os.close(master)
try:
    scenario(False)
    scenario(True)
finally:
    shutil.rmtree(parent)
"#;
    let result = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_e2ee"))
        .output()
        .expect("terminal regression checks require Python 3 on Unix");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
