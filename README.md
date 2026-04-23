# vpn-protocol-rs (Python educational VPN)

Minimal, self-contained implementation of an **educational VPN-like protocol** in pure Python.

It does **not** configure kernel-level tunnels, routing, or virtual interfaces. Instead, it focuses on the *protocol* pieces:

- encrypted, authenticated framing over a reliable byte stream (TCP)
- shared-secret key agreement (via passphrase-derived key)
- simple client/server that forwards traffic over the encrypted channel

This is designed to be small, easy to read, and runnable on a vanilla Python installation.

> Warning: The crypto in this project is **homebrew and educational only**. Do **not** use this for real security or in production.

---

## Why this is technically interesting

This project sketches the core building blocks of a VPN protocol:

- **Symmetric key derivation** from a passphrase using SHA-256
- **Per-frame nonces** and a stream-cipher-like keystream derived from `(key, nonce, counter)`
- **Authenticated encryption** by combining ciphertext with HMAC-SHA256 over `(nonce || ciphertext)`
- **Length-prefixed framing** that can sit on top of any reliable byte stream
- A minimal **client/server tunnel** that proxies application data through that encrypted framing layer
- **Extras for exploration**: optional payload compression, PBKDF2 key stretching with salt, and session key rotation.

You can read the whole implementation in `vpn_protocol.py` in a few hundred lines and see how the pieces fit together.

Again: this is *not* a correct or vetted cryptographic construction. It exists to make the protocol mechanics concrete without any external dependencies.

---

## Layout

- `vpn_protocol.py` – framing + symmetric crypto + tunnel helpers
- `main.py` – command-line interface (`server` and `client` subcommands)
- `tests/` – unit tests for the crypto + framing layer

---

## Requirements

- Python 3.10+ (standard library only)

No extra dependencies or virtualenv are required, but you can of course make one if you want.

---

## Running the tests

From the project directory:

```bash
python -m pytest
```

If you don't have `pytest` installed, you can also run the tests with the built-in unittest runner:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## How to run the minimal VPN tunnel

This project exposes two roles: **server** and **client**. The server knows the ultimate target service; the client exposes a local port that forwards through the encrypted tunnel.

### 1. Start the VPN server

On the machine that can reach your target service:

```bash
python main.py server \
  --listen-host 0.0.0.0 \
  --listen-port 9000 \
  --target-host 127.0.0.1 \
  --target-port 8000 \
  --passphrase "correct horse battery staple" \
  --salt "demo-salt" \
  --iterations 100000 \
  --compress \
  --rekey-interval 500
```

This will:

- listen for a VPN client on `0.0.0.0:9000`
- forward decrypted traffic to `127.0.0.1:8000` (e.g. a local HTTP server)

### 2. Start the VPN client

On the machine you want to connect from:

```bash
python main.py client \
  --listen-host 127.0.0.1 \
  --listen-port 10000 \
  --server-host <server-ip-or-hostname> \
  --server-port 9000 \
  --passphrase "correct horse battery staple" \
  --salt "demo-salt" \
  --iterations 100000 \
  --compress \
  --rekey-interval 500
```

This will:

- listen on `127.0.0.1:10000`
- connect to the VPN server at `<server-ip-or-hostname>:9000`
- forward data through the encrypted tunnel to the server's configured target

### 3. Connect an app through the tunnel

Point a TCP-speaking client at the local client port, e.g.:

```bash
curl http://127.0.0.1:10000/
```

If the server is forwarding to a web server on `127.0.0.1:8000`, you should see the HTTP response through the encrypted tunnel.

---

## Design notes & limitations

- This is a **single-connection** tunnel for simplicity (one client connection, one target connection).
- The protocol uses a custom stream-cipher-like construction on top of SHA-256. It's intentionally simple to read but not hardened.
- There is no key exchange; both sides must agree on the passphrase out of band.
- There's no negotiation of ciphers or protocol versions.
- There is no routing table, IP encapsulation, or multi-client support – it's a point-to-point encrypted TCP forwarder.

These limitations keep the code small enough to serve as a teaching aid.

Feature notes:

- `--compress` wraps payloads in zlib and only keeps compressed data if it shrinks the payload.
- `--salt` and `--iterations` feed PBKDF2-HMAC-SHA256 for slower, salted key derivation.
- `--rekey-interval` rotates the session key every N frames using an HMAC-based ratchet (0 disables rotation).

---

## Git setup

This project is local-only by default. To turn it into a Git repository and push to GitHub, run the following **inside** the `vpn-protocol-rs` folder.

### Initialize and commit locally

```bash
git init
git add .
git commit -m "Initial commit: minimal educational VPN protocol in Python"
```

### Push to a new GitHub repo

1. Create a new empty repository on GitHub via the web UI (no README, no .gitignore).
2. Then run these commands, replacing the URL with your repo's URL:

```bash
git remote add origin https://github.com/<your-username>/vpn-protocol-rs.git
git branch -M main
git push -u origin main
```

That's it – the project will be live on GitHub.

---

## GitHub Pages deployment

This repository includes a GitHub Actions workflow at:

- `.github/workflows/deploy-pages.yml`

On pushes to `main`, it deploys the `docs/` folder to GitHub Pages.

After merging to `main`, enable Pages in your repository settings:

1. Go to **Settings → Pages**
2. Under **Build and deployment**, choose **Source: GitHub Actions**
3. Save

Once the workflow completes, your site will be available at:

`https://ericfinland.github.io/VPN-protocol/`
