#!/usr/bin/env bash
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }

root="${DESTDIR:-}"
state_dir="$root/usr/local/lib/fail2ban-rs"
bin="$root/usr/local/bin"
units="$root/usr/local/lib/systemd/system"
python_library="$state_dir/python.zip"
unit_state="$state_dir/systemd-state"
unit_state_tmp="$state_dir/systemd-state.tmp"
backup_dir="$state_dir/backup"
backup_manifest="$state_dir/backup-manifest"
backup_manifest_tmp="$state_dir/backup-manifest.tmp"
stock_fakegooglebot_sha="0069a4f1828849673a23841e5b796bfd88e2fcdf1f4f5854f9723e7f3989f9da"
config="$root/etc/fail2ban"
man="$root/usr/local/share/man"
backup_targets=(
    usr/local/bin/fail2ban-server
    usr/local/bin/fail2ban-client
    usr/local/bin/fail2ban-regex
    usr/local/lib/systemd/system/fail2ban.service
    usr/local/lib/systemd/system/fail2ban.socket
    usr/local/share/man/man1/fail2ban.1
    usr/local/share/man/man1/fail2ban-server.1
    usr/local/share/man/man1/fail2ban-client.1
    usr/local/share/man/man1/fail2ban-regex.1
    usr/local/share/man/man5/jail.conf.5
)

case "${1:-}" in
    -h|--help)
        echo "Usage: bash install.sh [archive.tar.gz|--uninstall]"
        exit 0
        ;;
esac
[[ -n "$root" || $(id -u) -eq 0 ]] || die "Run this installer as root."
[[ $(uname -s) == Linux ]] || die "Fail2Ban requires Linux."

capture_unit_state() {
    local state
    state=$(systemctl is-enabled "$1" 2>/dev/null | head -n 1 || true)
    case "$state" in
        ""|not-found) printf 'absent' ;;
        *) printf '%s' "$state" ;;
    esac
}

restore_unit_state() {
    local unit="$1"
    local state="$2"
    case "$state" in
        enabled)
            systemctl disable --runtime "$unit" 2>/dev/null || true
            systemctl enable "$unit"
            ;;
        enabled-runtime)
            systemctl disable "$unit" 2>/dev/null || true
            systemctl enable --runtime "$unit"
            ;;
        disabled)
            systemctl disable --runtime "$unit" 2>/dev/null || true
            systemctl disable "$unit"
            ;;
        masked)
            systemctl disable --runtime "$unit" 2>/dev/null || true
            systemctl disable "$unit" 2>/dev/null || true
            systemctl unmask --runtime "$unit" 2>/dev/null || true
            systemctl mask "$unit"
            ;;
        masked-runtime)
            systemctl disable --runtime "$unit" 2>/dev/null || true
            systemctl disable "$unit" 2>/dev/null || true
            systemctl unmask "$unit" 2>/dev/null || true
            systemctl mask --runtime "$unit"
            ;;
        static|indirect|linked|linked-runtime|generated|transient|alias|not-found|absent|""|unknown)
            ;;
        *)
            printf 'Unsupported saved systemd state %s for %s\n' "$state" "$unit" >&2
            return 1
            ;;
    esac
}

is_stock_fakegooglebot() {
    local path="$1"
    [[ ! -L "$path" && -f "$path" ]] &&
        printf '%s  %s\n' "$stock_fakegooglebot_sha" "$path" | sha256sum --status -c -
}

backup_existing_path() {
    local rel="$1"
    local manifest="$2"
    local src="$root/$rel"
    local dst="$backup_dir/$rel"
    if [[ -e "$src" || -L "$src" ]]; then
        mkdir -p -- "$(dirname -- "$dst")"
        rm -f -- "$dst"
        cp -a -- "$src" "$dst"
        printf '%s\n' "$rel" >> "$manifest"
    fi
}

has_saved_backup_files() {
    [[ -d "$backup_dir" ]] || return 1
    local rel
    for rel in "${backup_targets[@]}" etc/fail2ban/filter.d/ignorecommands/apache-fakegooglebot; do
        if [[ -e "$backup_dir/$rel" || -L "$backup_dir/$rel" ]]; then
            return 0
        fi
    done
    [[ -n "$(find "$backup_dir" -mindepth 1 \( -type f -o -type l \) -print -quit 2>/dev/null)" ]]
}

verify_backed_up_files() {
    if [[ ! -f "$backup_manifest" ]]; then
        if has_saved_backup_files; then
            die "Missing backup manifest ($backup_manifest) while saved originals exist under $backup_dir; refusing to delete live or backup files."
        fi
        return 0
    fi
    local rel src
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        case "/$rel/" in
            */../*) die "Invalid backup manifest entry: $rel" ;;
        esac
        [[ "$rel" != /* ]] || die "Invalid backup manifest entry: $rel"
        src="$backup_dir/$rel"
        [[ -e "$src" || -L "$src" ]] || die "Missing backup file for rollback: $src"
    done < "$backup_manifest"
}

restore_backed_up_files() {
    [[ -f "$backup_manifest" ]] || return 0
    local rel src dst
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        case "/$rel/" in
            */../*) die "Invalid backup manifest entry: $rel" ;;
        esac
        [[ "$rel" != /* ]] || die "Invalid backup manifest entry: $rel"
        src="$backup_dir/$rel"
        dst="$root/$rel"
        if [[ -e "$src" || -L "$src" ]]; then
            mkdir -p -- "$(dirname -- "$dst")"
            rm -f -- "$dst"
            cp -a -- "$src" "$dst"
        fi
    done < "$backup_manifest"
}

cleanup_backup_files() {
    local rel
    local -a manifest_entries=()
    if [[ -f "$backup_manifest" ]]; then
        while IFS= read -r rel; do
            [[ -n "$rel" ]] || continue
            case "/$rel/" in */../*) continue ;; esac
            [[ "$rel" != /* ]] || continue
            manifest_entries+=("$rel")
        done < "$backup_manifest"
        # Retire the manifest before removing any backup copies so an interrupted
        # cleanup retry never treats restored live originals as removable.
        rm -f -- "$backup_manifest"
    fi
    rm -f -- "$backup_manifest_tmp"
    for rel in ${manifest_entries[@]+"${manifest_entries[@]}"} "${backup_targets[@]}" etc/fail2ban/filter.d/ignorecommands/apache-fakegooglebot; do
        rm -f -- "$backup_dir/$rel"
    done
    local dir
    for dir in \
        "$backup_dir/etc/fail2ban/filter.d/ignorecommands" \
        "$backup_dir/etc/fail2ban/filter.d" \
        "$backup_dir/etc/fail2ban" \
        "$backup_dir/etc" \
        "$backup_dir/usr/local/share/man/man1" \
        "$backup_dir/usr/local/share/man/man5" \
        "$backup_dir/usr/local/share/man" \
        "$backup_dir/usr/local/share" \
        "$backup_dir/usr/local/lib/systemd/system" \
        "$backup_dir/usr/local/lib/systemd" \
        "$backup_dir/usr/local/lib" \
        "$backup_dir/usr/local/bin" \
        "$backup_dir/usr/local" \
        "$backup_dir/usr" \
        "$backup_dir"
    do
        rmdir -- "$dir" 2>/dev/null || true
    done
}

if [[ "${1:-}" == --uninstall ]]; then
    if [[ ! -f "$backup_manifest" && ! -f "$python_library" ]]; then
        # No published backup manifest and no installed python.zip means either
        # fail2ban-rs was never installed or a first install stopped before its
        # first overwrite; clean partial staging state without deleting originals.
        cleanup_backup_files
        rm -f -- "$unit_state_tmp" "$unit_state"
        rmdir -- "$state_dir" 2>/dev/null || true
        exit 0
    fi
    verify_backed_up_files
    has_saved_state=0
    saved_service_enabled=""
    saved_socket_enabled=""
    if [[ -f "$unit_state" ]]; then
        has_saved_state=1
        while IFS='=' read -r k v; do
            case "$k" in
                fail2ban.service) saved_service_enabled="$v" ;;
                fail2ban.socket) saved_socket_enabled="$v" ;;
            esac
        done < "$unit_state"
    fi
    if [[ -z "$root" ]]; then
        if [[ "$has_saved_state" -eq 1 ]]; then
            systemctl stop fail2ban.socket fail2ban.service || true
            case "$saved_service_enabled" in
                absent|not-found|static|indirect)
                    systemctl disable --runtime fail2ban.service 2>/dev/null || true
                    systemctl disable fail2ban.service 2>/dev/null || true
                    ;;
            esac
            case "$saved_socket_enabled" in
                absent|not-found|static|indirect)
                    systemctl disable --runtime fail2ban.socket 2>/dev/null || true
                    systemctl disable fail2ban.socket 2>/dev/null || true
                    ;;
            esac
        elif [[ -f "$units/fail2ban.service" ]]; then
            systemctl disable --now fail2ban.socket fail2ban.service
        fi
    fi
    rm -f -- "$bin/fail2ban-server"
    rm -f -- "$bin/fail2ban-client"
    rm -f -- "$bin/fail2ban-regex"
    rm -f -- "$units/fail2ban.service"
    rm -f -- "$units/fail2ban.socket"
    rm -f -- "$python_library"
    rm -f -- "$man/man1/fail2ban.1"
    rm -f -- "$man/man1/fail2ban-server.1"
    rm -f -- "$man/man1/fail2ban-client.1"
    rm -f -- "$man/man1/fail2ban-regex.1"
    rm -f -- "$man/man5/jail.conf.5"
    restore_backed_up_files
    if [[ -z "$root" ]]; then
        systemctl daemon-reload
        if [[ "$has_saved_state" -eq 1 ]]; then
            restore_failed=0
            restore_unit_state fail2ban.service "$saved_service_enabled" || restore_failed=1
            restore_unit_state fail2ban.socket "$saved_socket_enabled" || restore_failed=1
            if [[ "$restore_failed" -ne 0 ]]; then
                die "Failed to restore prior systemd enablement state; saved state retained at $unit_state."
            fi
        fi
    fi
    cleanup_backup_files
    rm -f -- "$unit_state_tmp" "$unit_state"
    rmdir -- "$state_dir" 2>/dev/null || true
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
    rm -f -- "$backup_manifest_tmp" "$unit_state_tmp"
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
    svc_state=$(capture_unit_state fail2ban.service)
    sock_state=$(capture_unit_state fail2ban.socket)
    install -d -m 0755 "$state_dir"
    printf 'fail2ban.service=%s\nfail2ban.socket=%s\n' "$svc_state" "$sock_state" > "$unit_state_tmp"
    mv -f -- "$unit_state_tmp" "$unit_state"
fi
if [[ ! -f "$backup_manifest" && ! -f "$python_library" ]]; then
    cleanup_backup_files
    install -d -m 0755 "$state_dir"
    : > "$backup_manifest_tmp"
    for rel in "${backup_targets[@]}"; do
        backup_existing_path "$rel" "$backup_manifest_tmp"
    done
    if grep -Fxq "$name/config/filter.d/ignorecommands/apache-fakegooglebot" "$work/members" &&
        is_stock_fakegooglebot "$config/filter.d/ignorecommands/apache-fakegooglebot"; then
        backup_existing_path "etc/fail2ban/filter.d/ignorecommands/apache-fakegooglebot" "$backup_manifest_tmp"
    fi
    # Publish manifest only after every overwrite target is safely copied.
    mv -f -- "$backup_manifest_tmp" "$backup_manifest"
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
