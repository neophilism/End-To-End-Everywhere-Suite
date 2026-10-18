"""Pre-alpha local desktop file vault. Requires Tk and the Suite e2ee CLI."""
from __future__ import annotations

import os
import re
import subprocess
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

MAX_FILE_BYTES = 32 * 1024 * 1024


class VaultError(Exception):
    pass


def command(binary: str, state: str, action: str, context: str = "",
            source: str = "", destination: str = "", endpoint: str = "") -> list[str]:
    if not binary or not state:
        raise VaultError("Select the e2ee program and a local state directory.")
    prefix = [binary, "--state", state, "--software-vault",
              "--password-only", "--password-stdin"]
    if action == "init":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", endpoint):
            raise VaultError("Enter a simple endpoint ID (letters, digits, dot, dash or underscore).")
        if os.path.lexists(state):
            raise VaultError("Identity creation requires a new state directory.")
        return prefix + ["init", endpoint]
    if action not in {"seal-self-file", "open-self-file"}:
        raise VaultError("Unsupported vault action.")
    if not (1 <= len(context.encode("utf-8")) <= 256) or not all(
        33 <= ord(c) <= 126 for c in context
    ):
        raise VaultError("Context must be 1–256 printable ASCII characters without spaces.")
    if not Path(source).is_file():
        raise VaultError("Select a regular input file.")
    if Path(source).stat().st_size > MAX_FILE_BYTES:
        raise VaultError("Input exceeds the 32 MiB inline file limit.")
    if not destination or os.path.lexists(destination):
        raise VaultError("Choose a new destination; existing files are never overwritten.")
    if Path(source).resolve() == Path(destination).resolve():
        raise VaultError("Input and destination must differ.")
    return prefix + [action, context, source, destination]


def execute(argv: list[str], password: str, initializing: bool = False) -> None:
    if not 12 <= len(password.encode("utf-8")) <= 1024 or "\n" in password or "\r" in password:
        raise VaultError("Passphrase must be 12–1024 bytes without a line break.")
    credential = password + "\n"
    if initializing:
        credential += password + "\n"
    try:
        result = subprocess.run(argv, input=credential, text=True,
                                capture_output=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VaultError(
            "Operation did not complete normally. Inspect the selected destination "
            "and state before retrying."
        ) from exc
    if result.returncode:
        # CLI diagnostics are intentionally not displayed: they may contain an
        # independently retained anchor from a partially completed state save.
        raise VaultError(
            "The e2ee operation failed. Inspect the destination and state "
            "before retrying; run the CLI for detailed diagnostics."
        )


class VaultWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("End-To-End Everywhere • Local file vault (pre-alpha)")
        self.resizable(True, False)
        self.binary = tk.StringVar(value="e2ee")
        self.state = tk.StringVar()
        self.endpoint = tk.StringVar()
        self.password = tk.StringVar()
        self.context = tk.StringVar(value="personal-file")
        self.source = tk.StringVar()
        self.destination = tk.StringVar()
        frame = ttk.Frame(self, padding=16)
        frame.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        rows = [
            ("e2ee program", self.binary),
            ("Private state directory", self.state),
            ("New endpoint ID", self.endpoint),
            ("Vault passphrase", self.password),
            ("Shared file context", self.context),
            ("Selected input file", self.source),
            ("New output file", self.destination),
        ]
        for row, (label, variable) in enumerate(rows):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
            entry = ttk.Entry(frame, textvariable=variable, show="•" if variable is self.password else "")
            entry.grid(row=row, column=1, sticky="ew", padx=8, pady=3)
            if variable is self.source:
                ttk.Button(frame, text="Choose", command=self.choose_input).grid(row=row, column=2)
            if variable is self.destination:
                ttk.Button(frame, text="Choose", command=self.choose_output).grid(row=row, column=2)
        note = (
            "Files are encrypted on this device. Decrypted exports are private local "
            "files; other copies of the original remain where you saved them.\n"
            "Password-only mode has no independent identity pin or rollback protection. "
            "No native platform key store or synchronization is provided."
        )
        ttk.Label(frame, text=note, wraplength=550).grid(
            row=7, column=0, columnspan=3, sticky="w", pady=10
        )
        actions = ttk.Frame(frame)
        actions.grid(row=8, column=0, columnspan=3, sticky="ew")
        ttk.Button(actions, text="Create identity", command=lambda: self.perform("init")).pack(side="left", padx=3)
        ttk.Button(actions, text="Encrypt to self", command=lambda: self.perform("seal-self-file")).pack(side="left", padx=3)
        ttk.Button(actions, text="Verify and export", command=lambda: self.perform("open-self-file")).pack(side="left", padx=3)

    def choose_input(self) -> None:
        selected = filedialog.askopenfilename(parent=self)
        if selected:
            self.source.set(selected)

    def choose_output(self) -> None:
        selected = filedialog.asksaveasfilename(parent=self, confirmoverwrite=False)
        if selected:
            self.destination.set(selected)

    def perform(self, action: str) -> None:
        try:
            argv = command(self.binary.get(), self.state.get(), action,
                           self.context.get(), self.source.get(),
                           self.destination.get(), self.endpoint.get())
            if action == "open-self-file" and not messagebox.askyesno(
                "Export plaintext", "Save verified plaintext to the selected local file?",
                parent=self
            ):
                return
            execute(argv, self.password.get(), initializing=action == "init")
            messagebox.showinfo("Completed", "Operation completed. Keep the original "
                                "and exported files according to your own retention plan.",
                                parent=self)
        except VaultError as exc:
            messagebox.showerror("Vault operation", str(exc), parent=self)
        finally:
            self.password.set("")


if __name__ == "__main__":
    VaultWindow().mainloop()
