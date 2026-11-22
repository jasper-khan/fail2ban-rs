# fail2ban-rs

Rust implementation of the Fail2Ban 1.1.1 command line, configuration, and daemon.
It uses the original jail, filter, and action configuration formats, Unix socket protocol,
and SQLite v4 state. [Fail2Ban 1.1.1](https://github.com/fail2ban/fail2ban/releases/tag/1.1.1) is the compatibility reference.

## Build and test

```bash
cargo build --locked --bins
export FAIL2BAN_111_SOURCE=/path/to/fail2ban-1.1.1
cargo test --locked
```

Use Linux and the Rust toolchain pinned in `rust-toolchain.toml`. The reference integration
tests use Python 3 to run the original tools from `FAIL2BAN_111_SOURCE`.

## Build and install a release

With Zig and `cargo-zigbuild` installed, build the Linux amd64 and arm64 archives.

```bash
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
bash scripts/build-release.sh 1.1.1
```

Run the installer for your architecture from the release directory.

```bash
cd dist/v1.1.1
sha256sum -c fail2ban-rs-1.1.1-linux-amd64.tar.gz.sha256
sudo bash ../../scripts/install.sh fail2ban-rs-1.1.1-linux-amd64.tar.gz
```

The installer puts `fail2ban-client`, `fail2ban-server`, and `fail2ban-regex` in `/usr/local/bin`.
Configuration is under `/etc/fail2ban` and the default database is
`/var/lib/fail2ban/fail2ban.sqlite3`. Enable jails in `jail.local` or `jail.d` and install the
system commands required by the configured actions.

```bash
sudo fail2ban-client -t
sudo systemctl enable --now fail2ban.service
sudo fail2ban-client status
```

For an existing Fail2Ban installation, see the [migration and rollback guide](docs/MIGRATION_AND_ROLLBACK.md).

## Compatibility status

The native SMTP action currently accepts `ssl=false`. STARTTLS and third-party Python
actions are pending.

## License

The package contains the upstream GPL license in `COPYING` and retains the fork's
original MIT license notice in `LICENSE`.
