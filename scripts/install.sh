#!/usr/bin/env bash
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }

root="${DESTDIR:-}"
bin="$root/usr/local/bin"
units="$root/usr/local/lib/systemd/system"
python_library="$root/usr/local/lib/fail2ban-rs/python.zip"
unit_state="$root/usr/local/lib/fail2ban-rs/systemd-state"
config="$root/etc/fail2ban"
man="$root/usr/local/share/man"

case "${1:-}" in
    -h|--help)
        echo "Usage: bash install.sh [archive.tar.gz|--uninstall]"
        exit 0
        ;;
esac
[[ -n "$root" || $(id -u) -eq 0 ]] || die "Run this installer as root."
[[ $(uname -s) == Linux ]] || die "Fail2Ban requires Linux."

if [[ "${1:-}" == --uninstall ]]; then
    saved_service_enabled=""
    saved_socket_enabled=""
    if [[ -f "$unit_state" ]]; then
        while IFS='=' read -r k v; do
            case "$k" in
                fail2ban.service) saved_service_enabled="$v" ;;
                fail2ban.socket) saved_socket_enabled="$v" ;;
            esac
        done < "$unit_state"
    fi
    if [[ -z "$root" && -f "$units/fail2ban.service" ]]; then
        if [[ -n "$saved_service_enabled" || -n "$saved_socket_enabled" ]]; then
            systemctl stop fail2ban.socket fail2ban.service || true
        else
            systemctl disable --now fail2ban.socket fail2ban.service
        fi
    fi
    rm -f -- "$bin/fail2ban-server"
    rm -f -- "$bin/fail2ban-client"
    rm -f -- "$bin/fail2ban-regex"
    rm -f -- "$units/fail2ban.service"
    rm -f -- "$units/fail2ban.socket"
    rm -f -- "$python_library"
    rm -f -- "$unit_state"
    rmdir -- "$root/usr/local/lib/fail2ban-rs" 2>/dev/null || true
    rm -f -- "$man/man1/fail2ban.1"
    rm -f -- "$man/man1/fail2ban-server.1"
    rm -f -- "$man/man1/fail2ban-client.1"
    rm -f -- "$man/man1/fail2ban-regex.1"
    rm -f -- "$man/man5/jail.conf.5"
    if [[ -z "$root" ]]; then
        systemctl daemon-reload
        if [[ "$saved_service_enabled" == enabled ]]; then
            systemctl enable fail2ban.service || true
        elif [[ "$saved_service_enabled" == disabled ]]; then
            systemctl disable fail2ban.service || true
        fi
        if [[ "$saved_socket_enabled" == enabled ]]; then
            systemctl enable fail2ban.socket || true
        elif [[ "$saved_socket_enabled" == disabled ]]; then
            systemctl disable fail2ban.socket || true
        fi
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
    rm -f -- "$work/archive"
    rm -f -- "$work/checksum"
    rm -f -- "$work/members"
    rm -f -- "$work/member"
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
if [[ -z "$root" && ! -f "$unit_state" ]]; then
    svc_state="disabled"
    sock_state="disabled"
    if systemctl is-enabled --quiet fail2ban.service 2>/dev/null; then
        svc_state="enabled"
    fi
    if systemctl is-enabled --quiet fail2ban.socket 2>/dev/null; then
        sock_state="enabled"
    fi
    install -d -m 0755 "$root/usr/local/lib/fail2ban-rs"
    printf 'fail2ban.service=%s\nfail2ban.socket=%s\n' "$svc_state" "$sock_state" > "$unit_state"
fi
for binary in fail2ban-server fail2ban-client fail2ban-regex; do
    install_member "bin/$binary" 0755 "$bin/$binary"
done
install_member fail2ban.service 0644 "$units/fail2ban.service"
install_member fail2ban.socket 0644 "$units/fail2ban.socket"
install_member python.zip 0644 "$python_library"
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
                if [[ -f "$dest" ]] && printf '%s  %s\n' \
                    0069a4f1828849673a23841e5b796bfd88e2fcdf1f4f5854f9723e7f3989f9da "$dest" | sha256sum --status -c -; then
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
