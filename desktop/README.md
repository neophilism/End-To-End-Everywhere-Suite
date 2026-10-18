# Pre-alpha desktop file vault

On macOS or Linux with Python 3, Tk, and the locally built Suite `e2ee` executable:

```sh
python3 desktop/vault.py
```

Choose the executable and a **new** private state directory, enter an endpoint ID and a passphrase of at least 12 bytes, then create the identity. Pick a file and a new output path to encrypt it to your own identity. For export, select the encrypted delivery and a new destination, and confirm plaintext export. The application invokes the Suite CLI with the passphrase on a private stdin pipe. It does not put it in command arguments, environment variables, logs or shell commands. The CLI handles private atomic output and verified self-signatures; the desktop surface never interprets decrypted file content.

This initial desktop path deliberately uses the CLI's password-only mode. It has no independent identity pin or rollback protection, platform key store, sync, or automatic source deletion. Keep the passphrase and original files according to your retention needs. Decrypted exports are ordinary private local files, not protected after another application reads or copies them. The 32 MiB inline limit and Unix private-file output restriction still apply. Do not use this pre-alpha interface for production secrets.

Run controller tests without opening a display:

```sh
python3 -m unittest discover -s desktop -p 'test_*.py' -v
```
