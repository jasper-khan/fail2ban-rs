#!/usr/bin/env bash
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }

root="${DESTDIR:-}"
bin="$root/usr/local/bin"
units="$root/usr/local/lib/systemd/system"
config="$root/etc/fail2ban"
man="$root/usr/local/share/man"
state_dir="$root/usr/local/lib/fail2ban-rs"
stock_fakegooglebot_sha="0069a4f1828849673a23841e5b796bfd88e2fcdf1f4f5854f9723e7f3989f9da"

case "${1:-}" in
    -h|--help)
        echo "Usage: bash install.sh [archive.tar.gz|--uninstall]"
        exit 0
        ;;
esac
[[ -n "$root" || $(id -u) -eq 0 ]] || die "Run this installer as root."
[[ $(uname -s) == Linux ]] || die "Fail2Ban requires Linux."

is_stock_fakegooglebot() {
    local path="$1"
    [[ ! -L "$path" && -f "$path" ]] &&
        printf '%s  %s\n' "$stock_fakegooglebot_sha" "$path" | sha256sum --status -c -
}

if [[ "${1:-}" == --uninstall ]]; then
    if [[ -z "$root" ]] && {
        [[ -f "$units/fail2ban.service" || -f "$units/fail2ban.socket" ]]
    }; then
        systemctl disable --now fail2ban.socket fail2ban.service 2>/dev/null || true
    fi
    rm -f -- \
        "$bin/fail2ban-server" \
        "$bin/fail2ban-client" \
        "$bin/fail2ban-regex" \
        "$units/fail2ban.service" \
        "$units/fail2ban.socket" \
        "$state_dir/python.zip" \
        "$man/man1/fail2ban.1" \
        "$man/man1/fail2ban-server.1" \
        "$man/man1/fail2ban-client.1" \
        "$man/man1/fail2ban-regex.1" \
        "$man/man5/jail.conf.5"
    rmdir -- "$state_dir" 2>/dev/null || true
    if [[ -z "$root" ]]; then
        systemctl daemon-reload
    fi
    exit 0
fi

[[ $# -le 1 ]] || die "Usage: bash install.sh [archive.tar.gz|--uninstall]"
if [[ -z "$root" ]] && {
    systemctl is-active --quiet fail2ban.service ||
        systemctl is-active --quiet fail2ban.socket
}; then
    die "Stop fail2ban.service and fail2ban.socket before replacing the binaries."
fi

version="${FAIL2BAN_VERSION:-1.1.2}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid Fail2Ban version."
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "Unsupported architecture $(uname -m)." ;;
esac
name="fail2ban-rs-$version-linux-$arch"
work=$(mktemp -d)
cleanup() {
    rm -f -- "$work/archive" "$work/checksum" "$work/members" "$work/member"
    rmdir -- "$work"
}
trap cleanup EXIT
if [[ $# -eq 0 ]]; then
    url="https://github.com/jasper-khan/fail2ban-rs/releases/download/v$version/$name.tar.gz"
    curl --fail --location --output "$work/archive" "$url"
    curl --fail --location --output "$work/checksum" "$url.sha256"
    archive="$work/archive"
    checksum="$work/checksum"
else
    archive="$1"
    checksum="$1.sha256"
fi
read -r digest _ < "$checksum"
[[ "$digest" =~ ^[[:xdigit:]]{64}$ ]] || die "Invalid release checksum."
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
tar -tzf "$archive" > "$work/members"
mkdir -p "$config/fail2ban.d" "$config/jail.d" "$root/var/lib/fail2ban"

install_member() {
    tar -xOzf "$archive" "$name/$1" > "$work/member"
    install -D -m "$2" "$work/member" "$3"
}
for binary in fail2ban-server fail2ban-client fail2ban-regex; do
    install_member "bin/$binary" 0755 "$bin/$binary"
done
install_member fail2ban.service 0644 "$units/fail2ban.service"
install_member fail2ban.socket 0644 "$units/fail2ban.socket"
for page in fail2ban fail2ban-server fail2ban-client fail2ban-regex; do
    install_member "man/$page.1" 0644 "$man/man1/$page.1"
done
install_member man/jail.conf.5 0644 "$man/man5/jail.conf.5"

while IFS= read -r member; do
    case "$member" in
        "$name/config/"|"$name/config/"*/) continue ;;
        "$name/config/"*)
            relative="${member#"$name/config/"}"
            case "/$relative/" in */../*) die "Invalid config archive member." ;; esac
            dest="$config/$relative"
            if [[ -L "$dest" ]]; then
                continue
            fi
            mode=0644
            if [[ "$relative" == filter.d/ignorecommands/apache-fakegooglebot ]]; then
                mode=0755
                if is_stock_fakegooglebot "$dest"; then
                    install_member "config/$relative" "$mode" "$dest"
                fi
            fi
            if [[ ! -e "$dest" ]]; then
                install_member "config/$relative" "$mode" "$dest"
            fi
            ;;
    esac
done < "$work/members"

if [[ -z "$root" ]]; then
    systemctl daemon-reload
    echo 'Start Fail2Ban with systemctl enable --now fail2ban.service.'
fi
