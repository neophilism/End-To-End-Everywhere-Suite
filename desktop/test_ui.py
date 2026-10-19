"""Headless state tests for the optional Tk desktop surface."""
import queue
import unittest
from unittest.mock import patch


class Variable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Control:
    def __init__(self):
        self.disabled = False

    def state(self, states):
        self.disabled = "disabled" in states


class DesktopStateTests(unittest.TestCase):
    def test_operation_handoff_blocks_overlap_and_clears_passphrase(self):
        try:
            import vault
        except ImportError as exc:
            self.skipTest(f"optional Tk unavailable: {exc}")

        class Window:
            set_busy = vault.VaultWindow.set_busy
            poll_result = vault.VaultWindow.poll_result
            perform = vault.VaultWindow.perform

            def __init__(self):
                self._busy = False
                self._results = queue.Queue()
                self._controls = [Control()]
                self.status = Variable("Ready")
                self.binary = Variable("/trusted/e2ee")
                self.state = Variable("/private/state")
                self.endpoint = Variable("me")
                self.password = Variable("throwaway-test-passphrase")
                self.anchor = Variable("a" * 140)
                self.password_only = Variable(False)
                self.context = Variable("personal-file")
                self.source = Variable("/selected")
                self.destination = Variable("/new")
                self.scheduled = None

            def after(self, _milliseconds, callback):
                self.scheduled = callback

        window = Window()

        class InlineThread:
            def __init__(self, target, daemon):
                self.target = target

            def start(self):
                self.target()

        argv = ["/trusted/e2ee", "open-self-file", "context", "in", "out"]
        with patch.object(vault, "command", return_value=argv), \
             patch.object(vault, "Thread", InlineThread), \
             patch.object(vault, "verify_cli") as verify, \
             patch.object(vault, "execute", return_value=None) as execute, \
             patch.object(vault.messagebox, "showinfo") as info:
            window.perform("seal-self-file")
            self.assertTrue(window._busy)
            self.assertTrue(window._controls[0].disabled)
            self.assertEqual(window.password.get(), "")
            window.perform("seal-self-file")
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(verify.call_count, 1)
            self.assertEqual(execute.call_args.args[1], "throwaway-test-passphrase")
            window.scheduled()
            self.assertFalse(window._busy)
            self.assertFalse(window._controls[0].disabled)
            self.assertEqual(window.status.get(), "Ready")
            info.assert_called_once()


if __name__ == "__main__":
    unittest.main()
