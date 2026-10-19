"""Pre-alpha desktop notes, contacts and manual QR transcript comparison.

The CLI owns cryptographic state and file publication. This view never treats
QR text as a trust decision and never persists the passphrase.
"""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from notes_core import ClientError, build_command, compare_qr, parse_qr, run_cli, verify_cli


class NotesContacts(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("End-To-End Everywhere — notes and contacts (pre-alpha)")
        self.geometry("850x750")
        self.binary = tk.StringVar(value=str(Path("e2ee").absolute()))
        self.state_dir = tk.StringVar()
        self.anchor = tk.StringVar()
        self.password_only = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Choose the CLI and an existing state directory.")
        self.busy = False
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._layout()
        self.after(100, self._drain)

    def _entry(self, parent: tk.Widget, label: str, variable: tk.StringVar, row: int,
               secret: bool = False) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(parent, textvariable=variable, show="•" if secret else "").grid(
            row=row, column=1, sticky="ew", padx=6, pady=4)

    def _layout(self) -> None:
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        common = ttk.LabelFrame(container, text="Local identity")
        common.grid(row=0, column=0, sticky="ew")
        common.columnconfigure(1, weight=1)
        self._entry(common, "CLI executable", self.binary, 0)
        self._entry(common, "State directory", self.state_dir, 1)
        self._entry(common, "Independent anchor (140 hex)", self.anchor, 2)
        ttk.Checkbutton(common, text="I accept password-only mode and its rollback risk",
                        variable=self.password_only).grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Label(common, text="Passphrase (held in memory for one operation)").grid(
            row=4, column=0, sticky="w", padx=6)
        self.passphrase = ttk.Entry(common, show="•")
        self.passphrase.grid(row=4, column=1, sticky="ew", padx=6)
        tabs = ttk.Notebook(container)
        tabs.grid(row=1, column=0, sticky="nsew", pady=10)
        container.rowconfigure(1, weight=1)
        notes = ttk.Frame(tabs, padding=8)
        contacts = ttk.Frame(tabs, padding=8)
        qr = ttk.Frame(tabs, padding=8)
        tabs.add(notes, text="Personal notes")
        tabs.add(contacts, text="Contacts")
        tabs.add(qr, text="QR transcript")
        for pane in (notes, contacts, qr):
            pane.columnconfigure(1, weight=1)
        self.note_context = tk.StringVar(value="personal-note")
        self.note_source = tk.StringVar()
        self.note_output = tk.StringVar()
        self._entry(notes, "Purpose context", self.note_context, 0)
        self._entry(notes, "Input file", self.note_source, 1)
        self._entry(notes, "New output file", self.note_output, 2)
        ttk.Button(notes, text="Choose input", command=lambda: self._choose(self.note_source)).grid(
            row=3, column=0, sticky="w")
        ttk.Button(notes, text="Choose new output", command=lambda: self._choose(self.note_output, save=True)).grid(
            row=3, column=1, sticky="w")
        ttk.Button(notes, text="Encrypt personal note", command=lambda: self._start(
            "seal-note", [self.note_context.get(), self.note_source.get(), self.note_output.get()]
        )).grid(row=4, column=0, sticky="w", pady=10)
        ttk.Button(notes, text="Open personal note", command=lambda: self._start(
            "open-note", [self.note_context.get(), self.note_source.get(), self.note_output.get()]
        )).grid(row=4, column=1, sticky="w", pady=10)
        ttk.Label(notes, text="Outputs must be new files. The CLI creates private files; this view does not display plaintext.",
                  wraplength=700).grid(row=5, column=0, columnspan=2, sticky="w")
        self.card_path = tk.StringVar()
        self.endpoint = tk.StringVar()
        self.fingerprint = tk.StringVar()
        self._entry(contacts, "Public contact card file", self.card_path, 0)
        ttk.Button(contacts, text="Choose card", command=lambda: self._choose(self.card_path)).grid(
            row=1, column=0, sticky="w")
        ttk.Button(contacts, text="Import as unverified", command=lambda: self._start(
            "import-card", [self.card_path.get()])).grid(row=1, column=1, sticky="w")
        self._entry(contacts, "Endpoint ID", self.endpoint, 2)
        self._entry(contacts, "Fingerprint from independent channel", self.fingerprint, 3)
        ttk.Button(contacts, text="List contacts", command=lambda: self._start("contacts", [])).grid(
            row=4, column=0, sticky="w", pady=8)
        ttk.Button(contacts, text="Verify independent fingerprint", command=self._verify_contact).grid(
            row=4, column=1, sticky="w", pady=8)
        ttk.Label(contacts, text="Import does not trust a contact. Compare the full fingerprint through a separate channel.",
                  wraplength=700).grid(row=5, column=0, columnspan=2, sticky="w")
        self.qr_payload = tk.StringVar()
        self.local_enrollment = tk.StringVar()
        self.local_digest = tk.StringVar()
        self._entry(qr, "QR payload text (paste or manual scan)", self.qr_payload, 0)
        self._entry(qr, "Local enrollment ID", self.local_enrollment, 1)
        self._entry(qr, "Local transcript digest", self.local_digest, 2)
        ttk.Button(qr, text="Inspect QR", command=self._inspect_qr).grid(row=3, column=0, sticky="w")
        ttk.Button(qr, text="Compare transcript", command=self._compare_qr).grid(row=3, column=1, sticky="w")
        ttk.Label(qr, text="Comparison is informational. Confirm on both devices before finalizing enrollment. QR text never verifies a contact.",
                  wraplength=700).grid(row=4, column=0, columnspan=2, sticky="w")
        self.output = tk.Text(container, height=8, state="disabled", wrap="word")
        self.output.grid(row=2, column=0, sticky="nsew")
        ttk.Label(container, textvariable=self.status).grid(row=3, column=0, sticky="w")
        container.rowconfigure(2, weight=1)

    def _choose(self, variable: tk.StringVar, save: bool = False) -> None:
        selection = filedialog.asksaveasfilename() if save else filedialog.askopenfilename()
        if selection:
            variable.set(selection)

    def _verify_contact(self) -> None:
        fingerprint = self.fingerprint.get().strip()
        if not messagebox.askyesno("Confirm independent comparison",
                                   "Did you compare all 64 fingerprint characters through an independent channel?\n"
                                   "A QR payload from enrollment does not establish contact trust."):
            return
        self._start("verify", [self.endpoint.get(), fingerprint])

    def _inspect_qr(self) -> None:
        try:
            value = parse_qr(self.qr_payload.get())
            self._display(f"QR enrollment ID: {value.enrollment_id}\nQR transcript digest: {value.digest}\nNo trust change.")
        except ClientError as exc:
            messagebox.showerror("Invalid QR", str(exc))

    def _compare_qr(self) -> None:
        try:
            matches = compare_qr(self.qr_payload.get(), self.local_enrollment.get(), self.local_digest.get())
            self._display("Transcript matches. Confirm independently on both devices; no trust changed." if matches
                          else "Transcript mismatch. Stop enrollment; no trust changed.")
        except ClientError as exc:
            messagebox.showerror("Invalid transcript", str(exc))

    def _start(self, action: str, arguments: list[str]) -> None:
        if self.busy:
            return
        password = self.passphrase.get()
        self.passphrase.delete(0, "end")
        try:
            verify_cli(self.binary.get())
            argv = build_command(self.binary.get(), self.state_dir.get(), action, arguments,
                                 self.anchor.get(), self.password_only.get())
        except ClientError as exc:
            messagebox.showerror("Cannot start", str(exc))
            return
        self.busy = True
        self.status.set(f"Running {action}…")
        threading.Thread(target=self._worker, args=(argv, password), daemon=True).start()

    def _worker(self, argv: list[str], password: str) -> None:
        try:
            self.events.put(("success", run_cli(argv, password)))
        except ClientError as exc:
            self.events.put(("error", exc))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                self.busy = False
                if kind == "error":
                    error = payload
                    if error.anchor:
                        self.anchor.set("")
                        self._display("A new anchor was emitted despite failure. Inspect state and retain it independently before retrying:\n" + error.anchor)
                    self.status.set(str(error))
                    messagebox.showerror("CLI operation", str(error))
                else:
                    output, anchor = payload
                    if anchor and not self.password_only.get():
                        self.anchor.set("")
                    self._display((output.strip() or "Operation completed.") +
                                  ("\nNew anchor: " + anchor + "\nRetain it independently before the next operation." if anchor else ""))
                    self.status.set("Operation completed. Retain any new anchor independently.")
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _display(self, value: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", value)
        self.output.configure(state="disabled")


if __name__ == "__main__":
    NotesContacts().mainloop()
