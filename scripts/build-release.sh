#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1)
if [[ "${1:-}" != "$version" || $# -gt 2 ]]; then
    echo "Usage: $0 $version [x86_64-unknown-linux-musl|aarch64-unknown-linux-musl]" >&2
    exit 1
fi

targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
if [[ $# -eq 2 ]]; then
    targets=("$2")
fi
checksum=(sha256sum)
if ! command -v sha256sum >/dev/null; then
    checksum=(shasum -a 256)
fi

output="dist/v$version"
mkdir -p "$output"
reference=f60978618a101427b06924fc932b44350fec2b63
reference_archive="$output/fail2ban-1.1.1-source.tar.gz"
reference_sha=0a089e14d452e90a62f9f9fd1b7414d8bfb38f2997a11fee971cfd6d491fa48c
if [[ ! -f "$reference_archive" ]]; then
    curl --fail --silent --show-error --location \
        "https://codeload.github.com/fail2ban/fail2ban/tar.gz/$reference" \
        --output "$reference_archive"
fi
printf '%s  %s\n' "$reference_sha" "$reference_archive" | "${checksum[@]}" -c -
path="fail2ban-$reference"

for target in "${targets[@]}"; do
    case "$target" in
        x86_64-unknown-linux-musl) arch=amd64 ;;
        aarch64-unknown-linux-musl) arch=arm64 ;;
        *) echo "Unsupported target: $target" >&2; exit 1 ;;
    esac
    cargo zigbuild --release --locked --bins --target "$target"

    name="fail2ban-rs-$version-linux-$arch"
    package="$output/$name"
    mkdir -p "$package/bin"
    for binary in fail2ban-server fail2ban-client fail2ban-regex; do
        install -m 0755 "${CARGO_TARGET_DIR:-target}/$target/release/$binary" "$package/bin/$binary"
    done
    tar -xzf "$reference_archive" --strip-components=1 -C "$package" \
        "$path/config" "$path/COPYING" \
        "$path/man/fail2ban.1" "$path/man/fail2ban-server.1" \
        "$path/man/fail2ban-client.1" "$path/man/fail2ban-regex.1" \
        "$path/man/jail.conf.5"
    install -m 0755 "${CARGO_TARGET_DIR:-target}/$target/release/apache-fakegooglebot" \
        "$package/config/filter.d/ignorecommands/apache-fakegooglebot"
    cp dist/fail2ban.service dist/fail2ban.socket scripts/install.sh LICENSE README.md "$package/"
    install -D -m 0644 docs/MIGRATION_AND_ROLLBACK.md "$package/docs/MIGRATION_AND_ROLLBACK.md"

    (
        cd "$output"
        tar -czf "$name.tar.gz" "$name"
        "${checksum[@]}" "$name.tar.gz" > "$name.tar.gz.sha256"
    )
    echo "Created $output/$name.tar.gz"
done
