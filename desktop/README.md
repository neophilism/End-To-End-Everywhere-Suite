# Pre-alpha desktop file vault

On macOS or Linux with Python 3.10 or newer, Tk, and the locally built Suite `e2ee` executable:

```sh
python3 desktop/vault.py
# Or, from an extracted pre-alpha engineering artifact:
python3 vault.py
```

Choose the built executable by its absolute path (not a symlink) and a **new** private state directory, enter an endpoint ID and a passphrase of at least 12 bytes, then create the identity. Pick a file and a new output path to encrypt it to your own identity. For export, select the encrypted delivery and a new destination, and confirm plaintext export. The application first queries the selected program's public capability inventory and requires its local vault features. This self-reported inventory does not authenticate a substituted executable; choose a trusted build and protect its file path. It then invokes the Suite CLI with the passphrase on a private stdin pipe. It does not put it in command arguments, environment variables, logs or shell commands. The CLI handles private atomic output and verified self-signatures; the desktop surface never interprets decrypted file content. Operations run in a worker so the window stays responsive, with controls locked until the result is known.

Creation displays a new 140-character anchor. Retain it in a separate trusted place, then supply it for later operations to detect identity/archive rollback. Self-file encryption and opening do not change the archive or rotate the anchor. If the anchor is unavailable, the explicit password-only checkbox permits a weaker local mode without independent identity pin or rollback protection. The interface has no platform key store, sync, or automatic source deletion. Keep the passphrase and original files according to your retention needs. Decrypted exports are ordinary private local files, not protected after another application reads or copies them. The 32 MiB inline limit and Unix private-file output restriction still apply. Do not use this pre-alpha interface for production secrets.

The pre-alpha artifact job also runs `desktop/integration_smoke.py` against its freshly built CLI on macOS and Linux, using throwaway state and test data. This is a command-line integration check; it does not establish visual accessibility or signed release provenance.

Run controller tests without opening a display:

```sh
python3 -m unittest discover -s desktop -p 'test_*.py' -v
```
