"""Tk desktop surface for the Suite local encrypted file vault."""
import tkinter as tk
from queue import Empty, Queue
from threading import Thread
from tkinter import filedialog, messagebox, ttk

from vault_core import VaultError, command, execute, verify_cli


class VaultWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("End-To-End Everywhere • Local file vault (pre-alpha)")
        self.resizable(True, False)
        self._busy = False
        self._results = Queue()
        self._controls = []
        self.protocol("WM_DELETE_WINDOW", self.close_window)
        self.binary = tk.StringVar()
        self.state = tk.StringVar()
        self.endpoint = tk.StringVar()
        self.password = tk.StringVar()
        self.anchor = tk.StringVar()
        self.password_only = tk.BooleanVar(value=False)
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
            ("Independent anchor (optional)", self.anchor),
            ("Shared file context", self.context),
            ("Selected input file", self.source),
            ("New output file", self.destination),
        ]
        for row, (label, variable) in enumerate(rows):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
            entry = ttk.Entry(frame, textvariable=variable, show="•" if variable is self.password else "")
            entry.grid(row=row, column=1, sticky="ew", padx=8, pady=3)
            self._controls.append(entry)
            if variable is self.binary:
                button = ttk.Button(frame, text="Choose", command=self.choose_program)
                button.grid(row=row, column=2)
                self._controls.append(button)
            if variable is self.source:
                button = ttk.Button(frame, text="Choose", command=self.choose_input)
                button.grid(row=row, column=2)
                self._controls.append(button)
            if variable is self.destination:
                button = ttk.Button(frame, text="Choose", command=self.choose_output)
                button.grid(row=row, column=2)
                self._controls.append(button)
        note = (
            "Files are encrypted on this device. Decrypted exports are private local "
            "files; other copies of the original remain where you saved them.\n"
            "Password-only mode has no independent identity pin or rollback protection. "
            "No native platform key store or synchronization is provided."
        )
        mode = ttk.Checkbutton(frame, text="I accept password-only mode without rollback protection",
                               variable=self.password_only)
        mode.grid(row=8, column=0, columnspan=3, sticky="w")
        self._controls.append(mode)
        ttk.Label(frame, text=note, wraplength=550).grid(
            row=9, column=0, columnspan=3, sticky="w", pady=10
        )
        actions = ttk.Frame(frame)
        actions.grid(row=10, column=0, columnspan=3, sticky="ew")
        for title, action in [("Create identity", "init"),
                              ("Encrypt to self", "seal-self-file"),
                              ("Verify and export", "open-self-file")]:
            button = ttk.Button(actions, text=title, command=lambda kind=action: self.perform(kind))
            button.pack(side="left", padx=3)
            self._controls.append(button)
        self.status = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status).grid(row=11, column=0, columnspan=3, sticky="w")

    def choose_program(self) -> None:
        selected = filedialog.askopenfilename(parent=self)
        if selected:
            self.binary.set(selected)

    def choose_input(self) -> None:
        selected = filedialog.askopenfilename(parent=self)
        if selected:
            self.source.set(selected)

    def choose_output(self) -> None:
        selected = filedialog.asksaveasfilename(parent=self, confirmoverwrite=False)
        if selected:
            self.destination.set(selected)

    def show_anchor(self, anchor: str, uncertain: bool = False) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Retain independent anchor")
        dialog.transient(self)
        guidance = ("Operation reported an error after emitting an anchor. Retain it "
                    "independently and inspect state before retrying. " if uncertain else
                    "Identity created. Copy this token to a separate trusted place. ")
        ttk.Label(dialog, text=guidance +
                  "This token protects against local archive rollback; losing it may prevent recovery.",
                  wraplength=520).pack(padx=16, pady=10)
        field = ttk.Entry(dialog, width=82)
        field.insert(0, anchor)
        field.configure(state="readonly")
        field.pack(padx=16, pady=8)
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
        dialog.grab_set()
        self.wait_window(dialog)

    def close_window(self) -> None:
        if self._busy:
            messagebox.showwarning("Vault operation", "Wait for this file operation to finish before closing.", parent=self)
        else:
            self.destroy()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.status.set("Working with local encrypted files…" if busy else "Ready")
        for control in self._controls:
            control.state(["disabled"] if busy else ["!disabled"])

    def poll_result(self) -> None:
        try:
            new_anchor, error = self._results.get_nowait()
        except Empty:
            self.after(100, self.poll_result)
            return
        self.set_busy(False)
        if error:
            messagebox.showerror("Vault operation", str(error), parent=self)
            if error.anchor:
                self.anchor.set(error.anchor)
                self.show_anchor(error.anchor, uncertain=True)
        elif new_anchor:
            self.anchor.set(new_anchor)
            self.password_only.set(False)
            self.show_anchor(new_anchor)
        else:
            messagebox.showinfo("Completed", "Operation completed. Keep the original "
                                "and exported files according to your own retention plan.",
                                parent=self)

    def perform(self, action: str) -> None:
        if self._busy:
            return
        try:
            argv = command(self.binary.get(), self.state.get(), action,
                           self.context.get(), self.source.get(),
                           self.destination.get(), self.endpoint.get(),
                           self.anchor.get(), self.password_only.get())
            if action == "open-self-file" and not messagebox.askyesno(
                "Export plaintext", "Save verified plaintext to the selected local file?",
                parent=self
            ):
                return
            password = self.password.get()
            self.password.set("")
            self.set_busy(True)

            def work() -> None:
                try:
                    verify_cli(argv[0])
                    self._results.put((execute(argv, password), None))
                except VaultError as exc:
                    self._results.put((None, exc))
                except Exception:
                    self._results.put((None, VaultError(
                        "Unexpected local client failure. Inspect selected files and state before retrying.")))

            Thread(target=work, daemon=True).start()
            self.after(100, self.poll_result)
        except VaultError as exc:
            messagebox.showerror("Vault operation", str(exc), parent=self)
        finally:
            self.password.set("")


if __name__ == "__main__":
    VaultWindow().mainloop()
