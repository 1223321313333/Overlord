#!/usr/bin/env bash
# Overlord — Linux native installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/install.sh | bash
# or, if you already have the repo:
#   bash install.sh
#
# What it does:
#   1. Installs Bun (if missing)
#   2. Installs Go 1.22+ (if missing)
#   3. Clones the repo (if not already in it)
#   4. Installs server dependencies
#   5. Builds server + Go agent
#   6. Prints first-run instructions

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[overlord]${NC} $*"; }
ok()      { echo -e "${GREEN}[ok]${NC} $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC} $*"; }
die()     { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

REPO_URL="https://github.com/doesntbreaktos/Overlord.git"
GO_MIN_MAJOR=1; GO_MIN_MINOR=21
BUN_MIN="1.0.0"
INSTALL_DIR="${OVERLORD_DIR:-$HOME/overlord}"

# ── helpers ───────────────────────────────────────────────────────────────────

need_cmd() { command -v "$1" &>/dev/null || die "Required command not found: $1 — install it and retry."; }
have_cmd() { command -v "$1" &>/dev/null; }

version_ge() {
    # returns 0 if $1 >= $2 (both "1.21.4" style)
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# ── Bun ───────────────────────────────────────────────────────────────────────

install_bun() {
    info "Installing Bun..."
    if have_cmd curl; then
        curl -fsSL https://bun.sh/install | bash
    elif have_cmd wget; then
        wget -qO- https://bun.sh/install | bash
    else
        die "Neither curl nor wget found. Install one and retry."
    fi
    # The installer puts bun in $HOME/.bun/bin — add to PATH for this session
    export PATH="$HOME/.bun/bin:$PATH"
    ok "Bun installed: $(bun --version)"
}

check_bun() {
    if have_cmd bun; then
        ok "Bun $(bun --version) found"
    else
        install_bun
    fi
}

# ── Go ────────────────────────────────────────────────────────────────────────

install_go() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)   arch="amd64" ;;
        aarch64)  arch="arm64" ;;
        armv7*)   arch="armv6l" ;;
        *)        die "Unsupported architecture for automatic Go install: $arch" ;;
    esac

    info "Fetching latest Go release for linux/$arch..."
    local ver
    if have_cmd curl; then
        ver=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    elif have_cmd wget; then
        ver=$(wget -qO- "https://go.dev/VERSION?m=text" | head -1)
    fi
    ver="${ver:-go1.22.5}"
    local tarball="${ver}.linux-${arch}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    info "Downloading $url ..."
    if have_cmd curl; then
        curl -fsSL "$url" -o "/tmp/$tarball"
    else
        wget -q "$url" -O "/tmp/$tarball"
    fi

    info "Installing Go to /usr/local/go (needs sudo)..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/$tarball"
    rm -f "/tmp/$tarball"

    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $(go version) installed"
}

check_go() {
    if have_cmd go; then
        local ver
        ver=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
        local major minor
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -gt "$GO_MIN_MAJOR" ] || \
           ( [ "$major" -eq "$GO_MIN_MAJOR" ] && [ "$minor" -ge "$GO_MIN_MINOR" ] ); then
            ok "Go $ver found"
        else
            warn "Go $ver is older than required $GO_MIN_MAJOR.$GO_MIN_MINOR — reinstalling"
            install_go
        fi
    else
        install_go
    fi
}

# ── Repo ──────────────────────────────────────────────────────────────────────

ensure_repo() {
    if [ -f "Overlord-Server/package.json" ]; then
        ok "Already inside the Overlord repository"
        return
    fi
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Found existing clone at $INSTALL_DIR, pulling latest..."
        git -C "$INSTALL_DIR" pull --ff-only
    else
        info "Cloning $REPO_URL → $INSTALL_DIR ..."
        need_cmd git
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
    fi
    cd "$INSTALL_DIR"
    ok "Repository ready at $(pwd)"
}

# ── Build ─────────────────────────────────────────────────────────────────────

build_server() {
    info "Installing server dependencies..."
    cd Overlord-Server
    bun install --frozen-lockfile
    info "Building server (production)..."
    bun run build
    cd ..
    ok "Server built → Overlord-Server/dist/"
}

build_agent() {
    info "Building Go agent (windows/amd64)..."
    cd Overlord-Client
    GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ../Overlord-Server/data/builds/agent.exe ./cmd/agent/
    cd ..
    ok "Agent built → Overlord-Server/data/builds/agent.exe"
}

# ── Main ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}╔══════════════════════════════════╗${NC}"
echo -e "${CYAN}║      Overlord Installer          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════╝${NC}"
echo ""

check_bun
check_go
ensure_repo
build_server
mkdir -p Overlord-Server/data/builds
build_agent

echo ""
ok "Installation complete."
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo "  1. Start the server:"
echo "     bash scripts/start-prod.sh"
echo ""
echo "  2. Get the initial admin password (first run only):"
echo "     grep bootstrapPassword Overlord-Server/data/save.json"
echo ""
echo "  3. Open the panel:"
echo "     https://localhost:5173"
echo ""
