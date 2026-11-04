#!/usr/bin/env bash
# Overlord installer — Linux
#
# One-liner (Docker, recommended):
#   curl -fsSL https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/install.sh | bash
#
# One-liner (native, no Docker):
#   curl -fsSL https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/install.sh | MODE=native bash
#
# Flags when running directly:
#   bash install.sh docker    — Docker mode
#   bash install.sh native    — native (Bun + Go, build from source)
#   bash install.sh           — interactive menu

set -euo pipefail

# ── colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
else
  R='' G='' Y='' C='' B='' N=''
fi
info() { echo -e "${C}[overlord]${N} $*"; }
ok()   { echo -e "${G}[ok]${N} $*"; }
warn() { echo -e "${Y}[warn]${N} $*"; }
die()  { echo -e "${R}[error]${N} $*" >&2; exit 1; }

REPO_URL="https://github.com/doesntbreaktos/Overlord.git"
COMPOSE_URL="https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/docker-compose.yml"
INSTALL_DIR="${OVERLORD_DIR:-$HOME/overlord}"
GO_MIN_MINOR=21

have() { command -v "$1" &>/dev/null; }
need() { have "$1" || die "Required tool not found: $1 — install it and retry."; }

# ── mode selection ────────────────────────────────────────────────────────────

MODE="${MODE:-${1:-}}"

pick_mode() {
    echo ""
    echo -e "${B}How do you want to install Overlord?${N}"
    echo ""
    echo "  1) Docker  — pull the pre-built image, zero build time (recommended on Linux)"
    echo "  2) Native  — build from source with Bun + Go (recommended on Windows servers,"
    echo "               or when you want to modify the source)"
    echo ""
    printf "Enter 1 or 2: "
    local choice
    read -r choice
    case "$choice" in
        1) MODE=docker ;;
        2) MODE=native ;;
        *) die "Invalid choice: $choice" ;;
    esac
}

case "${MODE:-}" in
    docker|1) MODE=docker ;;
    native|2) MODE=native ;;
    "")
        # Non-interactive (piped): default to Docker
        if [ ! -t 0 ] && [ ! -t 1 ]; then
            MODE=docker
        else
            pick_mode
        fi
        ;;
    *) die "Unknown mode: $MODE  (use 'docker' or 'native')" ;;
esac

echo ""
echo -e "${C}╔══════════════════════════════════════╗${N}"
echo -e "${C}║   Overlord Installer — Linux         ║${N}"
echo -e "${C}║   Mode: ${B}${MODE}${N}${C}$(printf '%*s' $((26 - ${#MODE})) '')║${N}"
echo -e "${C}╚══════════════════════════════════════╝${N}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
#  DOCKER MODE
# ═══════════════════════════════════════════════════════════════════════════════

docker_mode() {
    # ── install Docker if missing ──────────────────────────────────────────────
    if ! have docker; then
        info "Docker not found — installing via convenience script..."
        need curl
        curl -fsSL https://get.docker.com | sh
        # Add current user to docker group so we don't need sudo for every command
        if getent group docker &>/dev/null; then
            sudo usermod -aG docker "$(whoami)" 2>/dev/null || true
            warn "Added $(whoami) to the docker group."
            warn "You may need to log out and back in for group changes to take effect."
            warn "For now, using sudo for docker commands."
            DOCKER_CMD="sudo docker"
        fi
    fi
    DOCKER_CMD="${DOCKER_CMD:-docker}"

    if ! $DOCKER_CMD compose version &>/dev/null 2>&1; then
        die "docker compose plugin not found. Install Docker Engine with the compose plugin: https://docs.docker.com/engine/install/"
    fi
    ok "Docker $($DOCKER_CMD --version | grep -oP '[0-9]+\.[0-9]+\.[0-9]+'  | head -1) with Compose ready"

    # ── get the compose file ───────────────────────────────────────────────────
    if [ -f "docker-compose.yml" ] && [ -f "Overlord-Server/package.json" ]; then
        ok "Already inside the Overlord repository — using local docker-compose.yml"
        COMPOSE_FILE="docker-compose.yml"
    else
        COMPOSE_DIR="$INSTALL_DIR-docker"
        mkdir -p "$COMPOSE_DIR"
        COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yml"
        if [ -f "$COMPOSE_FILE" ]; then
            info "Updating existing compose file at $COMPOSE_DIR ..."
        else
            info "Downloading docker-compose.yml → $COMPOSE_FILE ..."
        fi
        if have curl; then
            curl -fsSL "$COMPOSE_URL" -o "$COMPOSE_FILE"
        else
            need wget
            wget -q "$COMPOSE_URL" -O "$COMPOSE_FILE"
        fi
        cd "$COMPOSE_DIR"
        ok "Compose file ready at $(pwd)/docker-compose.yml"
    fi

    # ── pull and start ─────────────────────────────────────────────────────────
    info "Pulling latest image..."
    $DOCKER_CMD compose pull

    info "Starting Overlord..."
    $DOCKER_CMD compose up -d

    echo ""
    ok "Overlord is running."
    echo ""
    echo -e "${C}Get the initial admin password:${N}"
    echo "  $DOCKER_CMD compose exec overlord-server grep bootstrapPassword /app/data/save.json"
    echo ""
    echo -e "${C}Open the panel:${N}  https://localhost:5173"
    echo ""
    echo -e "${C}Update later:${N}"
    echo "  $DOCKER_CMD compose pull && $DOCKER_CMD compose up -d"
    echo ""
    echo -e "${C}Stop:${N}  $DOCKER_CMD compose down"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  NATIVE MODE
# ═══════════════════════════════════════════════════════════════════════════════

install_bun() {
    info "Installing Bun..."
    if have curl; then
        curl -fsSL https://bun.sh/install | bash
    else
        need wget
        wget -qO- https://bun.sh/install | bash
    fi
    export PATH="$HOME/.bun/bin:$PATH"
    have bun || die "Bun installed but not found in PATH — open a new shell and retry."
    ok "Bun $(bun --version) installed"
}

install_go() {
    local arch
    case "$(uname -m)" in
        x86_64)  arch=amd64 ;;
        aarch64) arch=arm64 ;;
        armv7*)  arch=armv6l ;;
        *)       die "Unsupported arch for automatic Go install: $(uname -m)" ;;
    esac
    info "Fetching latest Go release (linux/$arch)..."
    local ver
    if have curl; then
        ver=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    else
        ver=$(wget -qO- "https://go.dev/VERSION?m=text" | head -1)
    fi
    ver="${ver:-go1.22.5}"
    local tarball="${ver}.linux-${arch}.tar.gz"
    info "Downloading https://go.dev/dl/$tarball ..."
    if have curl; then
        curl -fsSL "https://go.dev/dl/$tarball" -o "/tmp/$tarball"
    else
        wget -q "https://go.dev/dl/$tarball" -O "/tmp/$tarball"
    fi
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/$tarball"
    rm -f "/tmp/$tarball"
    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $(go version) installed"
}

check_bun() {
    if have bun; then
        ok "Bun $(bun --version) found"
    else
        install_bun
    fi
}

check_go() {
    if have go; then
        local ver major minor
        ver=$(go version | grep -oP '[0-9]+\.[0-9]+' | head -1)
        major=${ver%%.*}; minor=${ver##*.}
        if [ "$major" -gt 1 ] || [ "$minor" -ge "$GO_MIN_MINOR" ]; then
            ok "Go $ver found"
            return
        fi
        warn "Go $ver < 1.$GO_MIN_MINOR — reinstalling"
    fi
    install_go
}

ensure_repo() {
    if [ -f "Overlord-Server/package.json" ]; then
        ok "Already inside the Overlord repository"
        return
    fi
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Pulling latest at $INSTALL_DIR ..."
        git -C "$INSTALL_DIR" pull --ff-only
    else
        need git
        info "Cloning $REPO_URL → $INSTALL_DIR ..."
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
    fi
    cd "$INSTALL_DIR"
    ok "Repository ready at $(pwd)"
}

native_mode() {
    check_bun
    check_go
    ensure_repo

    info "Installing server dependencies..."
    cd Overlord-Server
    bun install --frozen-lockfile

    info "Building server (production)..."
    bun run build
    bun run build:prod:linux
    cd ..

    info "Copying client source for runtime agent builds..."
    mkdir -p Overlord-Server/dist/Overlord-Client
    rsync -a --exclude=build --exclude=.git "$PWD/Overlord-Client/" "$PWD/Overlord-Server/dist/Overlord-Client/" 2>/dev/null \
        || cp -a "$PWD/Overlord-Client/." "$PWD/Overlord-Server/dist/Overlord-Client/"
    ok "Build complete"

    echo ""
    ok "Installation complete."
    echo ""
    echo -e "${C}Start the server:${N}"
    echo "  bash scripts/start-prod.sh"
    echo ""
    echo -e "${C}Get the initial admin password (first run only):${N}"
    echo "  grep bootstrapPassword Overlord-Server/data/save.json"
    echo ""
    echo -e "${C}Open the panel:${N}  https://localhost:5173"
    echo ""
}

# ── dispatch ──────────────────────────────────────────────────────────────────
case "$MODE" in
    docker) docker_mode ;;
    native) native_mode ;;
esac
