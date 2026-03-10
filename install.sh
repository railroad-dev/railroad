#!/bin/sh
# install.sh — Installer for railyard
# Usage: curl -fsSL https://raw.githubusercontent.com/railyarddev/railyard/main/install.sh | sh
set -e

REPO="railyarddev/railyard"
BINARY="railyard"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { printf "  \033[1;34m>\033[0m %s\n" "$*"; }
ok()    { printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
warn()  { printf "  \033[1;33m!\033[0m %s\n" "$*"; }
err()   { printf "  \033[1;31m✗\033[0m %s\n" "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "Required command not found: $1"
}

# ---------------------------------------------------------------------------
# Detect platform
# ---------------------------------------------------------------------------

detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        darwin) OS_LABEL="apple-darwin" ;;
        linux)  OS_LABEL="unknown-linux-gnu" ;;
        *)      err "Unsupported operating system: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH_LABEL="x86_64" ;;
        arm64|aarch64) ARCH_LABEL="aarch64" ;;
        *)             err "Unsupported architecture: $ARCH" ;;
    esac

    TARGET="${ARCH_LABEL}-${OS_LABEL}"
}

# ---------------------------------------------------------------------------
# Pick install directory
# ---------------------------------------------------------------------------

pick_install_dir() {
    if [ -d "$HOME/.cargo/bin" ]; then
        INSTALL_DIR="$HOME/.cargo/bin"
    elif [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        # Create ~/.cargo/bin as fallback
        mkdir -p "$HOME/.cargo/bin"
        INSTALL_DIR="$HOME/.cargo/bin"
    fi
}

# ---------------------------------------------------------------------------
# Fetch latest release version from GitHub
# ---------------------------------------------------------------------------

fetch_latest_version() {
    need curl
    VERSION="$(
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/'
    )" || true

    if [ -z "$VERSION" ]; then
        warn "Could not determine latest release version"
        return 1
    fi
    info "Latest release: $VERSION"
    return 0
}

# ---------------------------------------------------------------------------
# Download pre-built binary
# ---------------------------------------------------------------------------

download_binary() {
    TARBALL="${BINARY}-${VERSION}-${TARGET}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

    info "Downloading ${TARBALL}..."

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    HTTP_CODE="$(curl -fsSL -o "${TMPDIR}/${TARBALL}" -w "%{http_code}" "$URL" 2>/dev/null)" || true

    if [ "$HTTP_CODE" != "200" ] && [ ! -s "${TMPDIR}/${TARBALL}" ]; then
        warn "Binary not available for ${TARGET} (HTTP ${HTTP_CODE})"
        return 1
    fi

    info "Extracting..."
    tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

    if [ ! -f "${TMPDIR}/${BINARY}" ]; then
        warn "Archive did not contain expected binary"
        return 1
    fi

    mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    chmod +x "${INSTALL_DIR}/${BINARY}"
    ok "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
    return 0
}

# ---------------------------------------------------------------------------
# Build from source via cargo
# ---------------------------------------------------------------------------

build_from_source() {
    info "Falling back to building from source..."
    if ! command -v cargo >/dev/null 2>&1; then
        err "cargo is required to build from source. Install Rust first: https://rustup.rs"
    fi
    info "Running: cargo install --git https://github.com/${REPO}.git"
    cargo install --git "https://github.com/${REPO}.git"
    ok "Built and installed ${BINARY} from source"
}

# ---------------------------------------------------------------------------
# Post-install: register hooks
# ---------------------------------------------------------------------------

post_install() {
    # Make sure the binary is on PATH for the hook registration step
    if ! command -v "$BINARY" >/dev/null 2>&1; then
        export PATH="${INSTALL_DIR}:${PATH}"
    fi

    if command -v "$BINARY" >/dev/null 2>&1; then
        info "Running ${BINARY} install to register hooks..."
        "$BINARY" install && ok "Hooks registered" || warn "Hook registration returned non-zero (you can retry with: ${BINARY} install)"
    else
        warn "Could not find ${BINARY} on PATH — skipping hook registration"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    printf "\n\033[1m  Railyard Installer\033[0m\n\n"

    detect_platform
    info "Detected platform: ${TARGET}"

    pick_install_dir
    info "Install directory: ${INSTALL_DIR}"

    INSTALLED=0
    if fetch_latest_version; then
        if download_binary; then
            INSTALLED=1
        fi
    fi

    if [ "$INSTALLED" -eq 0 ]; then
        build_from_source
    fi

    post_install

    printf "\n\033[1m  Done!\033[0m Run \033[1mrailyard --help\033[0m to get started.\n\n"
}

main
