"use strict";

const $ = (s) => document.querySelector(s);
const tbody = (s) => document.querySelector(s + " tbody");

let token = localStorage.getItem("stash_token") || "";

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

// Encode a secret path while keeping "/" as a separator (matches the
// GET /v1/secret/{path...} route).
function pathURL(p) {
  return "/v1/secret/" + p.split("/").map(encodeURIComponent).join("/");
}

// authFetch adds the bearer token and surfaces the login overlay on 401.
async function authFetch(path, opts = {}) {
  const headers = Object.assign({}, opts.headers);
  if (token) headers["Authorization"] = "Bearer " + token;
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  if (r.status === 401) requireLogin();
  return r;
}

function apiJSON(method, path, body) {
  return authFetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ---------- login ----------

function requireLogin() {
  $("#login").hidden = false;
}

$("#login-form").addEventListener("submit", (e) => {
  e.preventDefault();
  token = $("#login-token").value.trim();
  localStorage.setItem("stash_token", token);
  $("#login-token").value = "";
  $("#login").hidden = true;
  refresh();
});

$("#logout").onclick = () => {
  token = "";
  localStorage.removeItem("stash_token");
  $("#logout").hidden = true;
  requireLogin();
};

// ---------- cluster status ----------

async function loadStatus() {
  const r = await authFetch("/v1/cluster/status");
  if (!r.ok) return;
  const s = await r.json();
  const badge = $("#node-badge");
  badge.textContent = `${s.node_id} · ${s.is_leader ? "leader" : "follower"} · ${s.sealed ? "sealed" : "unsealed"}`;
  badge.className = "badge " + (s.sealed ? "warn" : "ok");

  const body = tbody("#cluster");
  body.innerHTML = "";
  (s.servers || []).forEach((sv) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${esc(sv.id)}${sv.leader ? " 👑" : ""}</td>` +
      `<td>${esc(sv.address)}</td>` +
      `<td>${esc(sv.suffrage)}</td>` +
      `<td>${sv.leader ? "leader" : "—"}</td>`;
    body.appendChild(tr);
  });
  $("#logout").hidden = !token;
}

// ---------- secrets ----------

let allPaths = [];

async function loadSecrets() {
  const r = await authFetch("/v1/secrets");
  allPaths = r.ok ? (await r.json()).keys || [] : [];
  renderSecrets();
}

function renderSecrets() {
  const f = $("#filter").value.toLowerCase();
  const paths = allPaths.filter((p) => p.toLowerCase().includes(f));
  const body = tbody("#secrets");
  body.innerHTML = "";
  $("#empty").hidden = allPaths.length > 0;

  paths.forEach((p) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td class="path">${esc(p)}</td>` +
      `<td class="val"><span class="muted">••••••••</span></td>` +
      `<td class="row-actions">` +
      `<button data-act="copy">Copy</button> ` +
      `<button data-act="reveal">Reveal</button> ` +
      `<button data-act="history">History</button> ` +
      `<button data-act="edit">Edit</button> ` +
      `<button data-act="del" class="danger">Delete</button></td>`;
    tr.querySelector("[data-act=copy]").onclick = (e) => copySecret(p, e.currentTarget);
    tr.querySelector("[data-act=reveal]").onclick = (e) => toggleReveal(tr, p, e.currentTarget);
    tr.querySelector("[data-act=history]").onclick = (e) => toggleHistory(tr, p, e.currentTarget);
    tr.querySelector("[data-act=edit]").onclick = () => editSecret(p);
    tr.querySelector("[data-act=del]").onclick = () => del(p);
    body.appendChild(tr);
  });
}

// copySecret fetches a value and copies it WITHOUT rendering it on screen.
async function copySecret(path, btn) {
  const r = await authFetch(pathURL(path));
  if (!r.ok) {
    flash(btn, r.status === 503 ? "sealed" : r.status === 403 ? "denied" : "error");
    return;
  }
  const { value } = await r.json();
  copyValue(value, btn);
}

async function copyValue(value, btn) {
  flash(btn, (await copyText(value)) ? "Copied!" : "copy failed");
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      /* fall through */
    }
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch (e) {
    return false;
  }
}

function flash(btn, text) {
  if (!btn.dataset.label) btn.dataset.label = btn.textContent;
  btn.textContent = text;
  btn.disabled = true;
  setTimeout(() => {
    btn.textContent = btn.dataset.label;
    btn.disabled = false;
  }, 1200);
}

// toggleReveal flips a row between masked and shown.
async function toggleReveal(tr, path, btn) {
  const cell = tr.querySelector(".val");
  if (btn.dataset.shown === "1") {
    cell.innerHTML = '<span class="muted">••••••••</span>';
    btn.textContent = "Reveal";
    btn.dataset.shown = "";
    return;
  }
  const r = await authFetch(pathURL(path));
  if (!r.ok) {
    cell.innerHTML = `<span class="err">${r.status === 503 ? "sealed" : r.status === 403 ? "denied" : "error " + r.status}</span>`;
    return;
  }
  const { value } = await r.json();
  cell.textContent = "";
  const code = document.createElement("code");
  code.textContent = value;
  cell.appendChild(code);
  btn.textContent = "Hide";
  btn.dataset.shown = "1";
}

// toggleHistory shows/hides a per-secret version history row.
async function toggleHistory(tr, path, btn) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("history-row")) {
    next.remove();
    btn.textContent = "History";
    return;
  }
  const r = await authFetch("/v1/versions/" + path.split("/").map(encodeURIComponent).join("/"));
  if (!r.ok) return;
  const data = await r.json();
  const row = document.createElement("tr");
  row.className = "history-row";
  const td = document.createElement("td");
  td.colSpan = 3;

  const versions = data.versions || [];
  if (versions.length === 0) {
    td.innerHTML = '<span class="muted">no history</span>';
  } else {
    versions.forEach((v) => {
      const item = document.createElement("div");
      item.className = "history-item";
      const t = (v.time || "").replace("T", " ").replace(/\.\d+/, "").replace("Z", "");
      const label = document.createElement("span");
      label.className = "muted";
      label.textContent = `v${v.seq} · ${t}`;
      const view = document.createElement("button");
      view.className = "link";
      view.textContent = "View";
      view.onclick = () => viewVersion(item, path, v.seq);
      const restore = document.createElement("button");
      restore.className = "link";
      restore.textContent = "Restore";
      restore.onclick = () => restoreVersion(path, v.seq);
      item.append(label, " ", view, restore);
      td.appendChild(item);
    });
  }
  row.appendChild(td);
  tr.after(row);
  btn.textContent = "Hide";
}

async function viewVersion(item, path, seq) {
  const existing = item.querySelector("code");
  if (existing) {
    existing.remove();
    return;
  }
  const r = await authFetch(pathURL(path) + "?version=" + seq);
  if (!r.ok) return;
  const { value } = await r.json();
  const code = document.createElement("code");
  code.textContent = value;
  code.style.marginLeft = "8px";
  item.appendChild(code);
}

async function restoreVersion(path, seq) {
  if (!confirm(`Restore ${path} to v${seq}? This creates a new version with that value.`)) return;
  const r = await authFetch(pathURL(path) + "?version=" + seq);
  if (!r.ok) return;
  const { value } = await r.json();
  const pr = await apiJSON("PUT", pathURL(path), { value });
  if (pr.ok) {
    loadSecrets();
    loadAudit();
  }
}

async function editSecret(path) {
  const r = await authFetch(pathURL(path));
  if (!r.ok) return;
  const { value } = await r.json();
  $("#path").value = path;
  $("#value").value = value;
  $("#form-title").textContent = "Edit secret";
  $("#cancel").hidden = false;
  $("#path").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function del(path) {
  if (!confirm("Delete " + path + " ?")) return;
  const r = await authFetch(pathURL(path), { method: "DELETE" });
  if (r.ok) loadSecrets();
  else msg("Delete failed: " + r.status, true);
}

function msg(t, isErr) {
  const m = $("#form-msg");
  m.textContent = t;
  m.className = "msg " + (isErr ? "err" : "ok");
}

function resetForm() {
  $("#path").value = "";
  $("#value").value = "";
  $("#form-title").textContent = "Add secret";
  $("#cancel").hidden = true;
  msg("", false);
}

$("#secret-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const path = $("#path").value.trim();
  const value = $("#value").value;
  if (!path) return;
  const r = await apiJSON("PUT", pathURL(path), { value });
  if (r.ok) {
    msg("Saved.", false);
    resetForm();
    loadSecrets();
  } else {
    const j = await r.json().catch(() => ({}));
    msg("Save failed: " + (j.error || r.status), true);
  }
});

$("#cancel").onclick = resetForm;
$("#filter").addEventListener("input", renderSecrets);

// ---------- identities (admin only) ----------

async function loadIdentities() {
  const r = await authFetch("/v1/identities");
  if (!r.ok) {
    // 403 => not an admin; hide the panel.
    $("#identities-card").hidden = true;
    return;
  }
  const data = await r.json();
  $("#identities-card").hidden = false;
  const body = tbody("#identities");
  body.innerHTML = "";
  (data.identities || []).forEach((id) => {
    const tr = document.createElement("tr");
    const pol = id.admin
      ? "—"
      : (id.policies || []).map((p) => `${p.prefix || "*"}:${(p.caps || []).join("+")}`).join(", ");
    tr.innerHTML =
      `<td>${esc(id.name)}</td>` +
      `<td>${id.admin ? "✓" : ""}</td>` +
      `<td class="muted">${esc(pol)}</td>` +
      `<td class="row-actions"></td>`;
    const delBtn = document.createElement("button");
    delBtn.textContent = "Delete";
    delBtn.className = "danger";
    delBtn.onclick = () => delIdentity(id.name);
    tr.querySelector(".row-actions").appendChild(delBtn);
    body.appendChild(tr);
  });
}

async function delIdentity(name) {
  if (!confirm("Delete identity " + name + " ?")) return;
  const r = await authFetch("/v1/identities/" + encodeURIComponent(name), { method: "DELETE" });
  if (r.ok) loadIdentities();
}

$("#identity-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#id-name").value.trim();
  if (!name) return;
  const admin = $("#id-admin").checked;
  const caps = [];
  if ($("#cap-read").checked) caps.push("read");
  if ($("#cap-write").checked) caps.push("write");
  if ($("#cap-delete").checked) caps.push("delete");
  const policies = admin ? [] : [{ prefix: $("#id-prefix").value.trim(), caps }];

  const box = $("#id-token");
  const r = await apiJSON("POST", "/v1/identities", { name, admin, policies });
  if (r.status === 201) {
    const { token: t } = await r.json();
    box.hidden = false;
    box.className = "token-box";
    box.innerHTML = `New token for <b>${esc(name)}</b> (copy now — shown once):<br><code>${esc(t)}</code>`;
    $("#id-name").value = "";
    loadIdentities();
  } else {
    const j = await r.json().catch(() => ({}));
    box.hidden = false;
    box.className = "token-box err";
    box.textContent = "Create failed: " + (j.error || r.status);
  }
});

// ---------- audit (admin only) ----------

async function loadAudit() {
  const r = await authFetch("/v1/audit?limit=50");
  if (!r.ok) {
    $("#audit-card").hidden = true;
    return;
  }
  const data = await r.json();
  $("#audit-card").hidden = false;
  const badge = $("#audit-status");
  badge.textContent =
    (data.verified ? "chain intact ✓" : "chain BROKEN ✗") + " · " + (data.count || 0) + " entries";
  badge.className = "badge " + (data.verified ? "ok" : "warn");

  const body = tbody("#audit");
  body.innerHTML = "";
  (data.entries || []).forEach((e) => {
    const t = (e.time || "").replace("T", " ").replace(/\.\d+/, "").replace("Z", "");
    const rcls = e.result === "ok" ? "ok" : e.result === "denied" || e.result === "error" ? "err" : "muted";
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td class="muted">${esc(t)}</td>` +
      `<td>${esc(e.identity)}</td>` +
      `<td>${esc(e.action)}</td>` +
      `<td class="path">${esc(e.path)}</td>` +
      `<td class="${rcls}">${esc(e.result)}</td>`;
    body.appendChild(tr);
  });
}

// ---------- boot ----------

function refresh() {
  loadStatus();
  loadSecrets();
  loadIdentities();
  loadAudit();
}

refresh();
setInterval(() => {
  loadStatus();
  loadAudit();
}, 4000);
