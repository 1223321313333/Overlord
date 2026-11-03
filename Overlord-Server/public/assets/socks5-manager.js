const toast =
  (typeof window !== "undefined" && window.createToast) ||
  (typeof window !== "undefined" && window.showToast) ||
  null;

const tableBody = document.getElementById("proxyTableBody");
const addProxyBtn = document.getElementById("addProxyBtn");
const addProxyModal = document.getElementById("addProxyModal");
const modalClientSelect = document.getElementById("modalClientSelect");
const modalPortInput = document.getElementById("modalPortInput");
const modalUsernameInput = document.getElementById("modalUsernameInput");
const modalPasswordInput = document.getElementById("modalPasswordInput");
const modalCancelBtn = document.getElementById("modalCancelBtn");
const modalAddBtn = document.getElementById("modalAddBtn");

let pollingInterval = null;

// Check if a clientId was provided via URL params (from context menu)
const urlParams = new URLSearchParams(window.location.search);
const preselectedClientId = urlParams.get("clientId") || "";

// ── Data fetching ─────────────────────────────────────────────────────────────

async function fetchProxies() {
  try {
    const res = await fetch("/api/proxy/list");
    if (!res.ok) return [];
    const data = await res.json();
    return data.proxies || [];
  } catch {
    return [];
  }
}

async function fetchClients() {
  try {
    const res = await fetch("/api/clients?page=1&pageSize=500");
    if (!res.ok) return [];
    const data = await res.json();
    return (data.items || []).filter((c) => c.online);
  } catch {
    return [];
  }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function formatTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  return d.toLocaleString();
}

function formatBytes(n) {
  if (!n) return "0 B";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MB";
  return (n / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

function clientLabel(clientMap, clientId) {
  const c = clientMap?.get(clientId);
  if (!c) return clientId;
  return [c.nickname, c.host, c.user].filter(Boolean).join(" · ") || clientId;
}

function renderTable(proxies, clientMap) {
  if (!proxies.length) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="7" class="px-4 py-12 text-center text-slate-500">
          <div class="flex flex-col items-center gap-2">
            <i class="fa-solid fa-network-wired text-3xl text-slate-600"></i>
            <p class="text-slate-400">No active proxies</p>
            <p class="text-xs">Click "Add Proxy" to start routing traffic through a client.</p>
          </div>
        </td>
      </tr>`;
    return;
  }

  tableBody.innerHTML = proxies
    .map(
      (p) => `
    <tr class="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
      <td class="px-4 py-3">
        <div class="flex items-center gap-2">
          <i class="fa-solid fa-desktop text-slate-400"></i>
          <div>
            <div class="text-sm">${escapeHtml(clientLabel(clientMap, p.clientId))}</div>
            <div class="text-xs text-slate-500 font-mono">${escapeHtml(p.clientId)}</div>
          </div>
        </div>
      </td>
      <td class="px-4 py-3">
        <div class="flex items-center gap-2">
          <span class="font-mono text-blue-300 font-semibold">${p.port}</span>
          ${p.hasAuth ? '<i class="fa-solid fa-lock text-xs text-yellow-400" title="Password protected"></i>' : ""}
          <button class="copy-btn text-slate-500 hover:text-slate-200 transition-colors" data-copy="socks5://${location.hostname}:${p.port}" title="Copy address">
            <i class="fa-solid fa-copy text-xs"></i>
          </button>
        </div>
      </td>
      <td class="px-4 py-3">
        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/30">
          <span class="w-1.5 h-1.5 rounded-full bg-green-400"></span>
          Active
        </span>
      </td>
      <td class="px-4 py-3 text-slate-300">${p.connections}</td>
      <td class="px-4 py-3 text-slate-400 text-xs">
        <span title="↑ to client / ↓ from client">↑${formatBytes(p.bytesToClient)} ↓${formatBytes(p.bytesFromClient)}</span>
      </td>
      <td class="px-4 py-3 text-slate-400 text-xs">${formatTime(p.createdAt)}</td>
      <td class="px-4 py-3 text-right">
        <button
          class="stop-btn px-3 py-1.5 rounded-lg bg-red-800/60 hover:bg-red-700 text-red-100 border border-red-600 transition-colors text-xs"
          data-port="${p.port}"
        >
          <i class="fa-solid fa-stop mr-1"></i>Stop
        </button>
      </td>
    </tr>`,
    )
    .join("");

  // wire up stop buttons
  tableBody.querySelectorAll(".stop-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const port = parseInt(btn.dataset.port);
      stopProxy(port);
    });
  });

  // wire up copy buttons
  tableBody.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(btn.dataset.copy).then(() => {
        if (toast) toast("Address copied!", "success");
      });
    });
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ── Actions ───────────────────────────────────────────────────────────────────

async function startProxy(clientId, port, username, password) {
  try {
    const body = { clientId, port };
    if (username) { body.username = username; body.password = password || ""; }
    const res = await fetch("/api/proxy/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.ok) {
      if (toast) toast(`Proxy started on port ${port}`, "success");
    } else {
      if (toast) toast(data.message || "Failed to start proxy", "error");
    }
    refresh();
  } catch (err) {
    if (toast) toast("Network error", "error");
  }
}

async function stopProxy(port) {
  try {
    const res = await fetch("/api/proxy/stop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ port }),
    });
    const data = await res.json();
    if (data.ok) {
      if (toast) toast(`Proxy on port ${port} stopped`, "success");
    } else {
      if (toast) toast(data.message || "Failed to stop proxy", "error");
    }
    refresh();
  } catch (err) {
    if (toast) toast("Network error", "error");
  }
}

async function refresh() {
  const [proxies, clients] = await Promise.all([fetchProxies(), fetchClients()]);
  const clientMap = new Map(clients.map((c) => [c.id, c]));
  renderTable(proxies, clientMap);
}

// ── Modal ─────────────────────────────────────────────────────────────────────

function showModal() {
  addProxyModal.classList.remove("hidden");
  loadClientsForModal();
}

function hideModal() {
  addProxyModal.classList.add("hidden");
  if (modalUsernameInput) modalUsernameInput.value = "";
  if (modalPasswordInput) modalPasswordInput.value = "";
}

async function loadClientsForModal() {
  modalClientSelect.innerHTML = '<option value="">Loading...</option>';
  const clients = await fetchClients();
  if (!clients.length) {
    modalClientSelect.innerHTML = '<option value="">No online clients</option>';
    return;
  }
  modalClientSelect.innerHTML = clients
    .map((c) => {
      const label = [c.nickname, c.host, c.user, c.id]
        .filter(Boolean)
        .join(" | ");
      const selected = c.id === preselectedClientId ? " selected" : "";
      return `<option value="${escapeHtml(c.id)}"${selected}>${escapeHtml(label)}</option>`;
    })
    .join("");
}

addProxyBtn.addEventListener("click", showModal);
modalCancelBtn.addEventListener("click", hideModal);
addProxyModal.addEventListener("click", (e) => {
  if (e.target === addProxyModal) hideModal();
});

modalAddBtn.addEventListener("click", () => {
  const clientId = modalClientSelect.value;
  const port = parseInt(modalPortInput.value);
  const username = modalUsernameInput?.value?.trim() || "";
  const password = modalPasswordInput?.value || "";
  if (!clientId) {
    if (toast) toast("Select a client", "error");
    return;
  }
  if (isNaN(port) || port < 1 || port > 65535) {
    if (toast) toast("Invalid port (1-65535)", "error");
    return;
  }
  hideModal();
  startProxy(clientId, port, username, password);
});

// ── Init ──────────────────────────────────────────────────────────────────────

refresh();
pollingInterval = setInterval(refresh, 5000);

// Auto-open modal if a clientId was provided via URL
if (preselectedClientId) {
  showModal();
}
