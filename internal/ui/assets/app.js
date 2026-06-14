"use strict";

const $ = (s) => document.querySelector(s);
const tbody = (s) => document.querySelector(s + " tbody");

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

// Encode a secret path for the URL while keeping "/" as a separator
// (matches the GET /v1/secret/{path...} route).
function pathURL(p) {
  return "/v1/secret/" + p.split("/").map(encodeURIComponent).join("/");
}

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  return fetch(path, opt);
}

async function loadStatus() {
  try {
    const s = await (await fetch("/v1/cluster/status")).json();
    const badge = $("#node-badge");
    const role = s.is_leader ? "leader" : "follower";
    const state = s.sealed ? "sealed" : "unsealed";
    badge.textContent = `${s.node_id} · ${role} · ${state}`;
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
  } catch (e) {
    $("#node-badge").textContent = "unreachable";
    $("#node-badge").className = "badge warn";
  }
}

let allPaths = [];

async function loadSecrets() {
  try {
    const data = await (await fetch("/v1/secrets")).json();
    allPaths = data.keys || [];
  } catch (e) {
    allPaths = [];
  }
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
      `<button data-act="edit">Edit</button> ` +
      `<button data-act="del" class="danger">Delete</button></td>`;
    tr.querySelector("[data-act=copy]").onclick = (e) => copySecret(p, e.currentTarget);
    tr.querySelector("[data-act=reveal]").onclick = () => reveal(tr, p);
    tr.querySelector("[data-act=edit]").onclick = () => editSecret(p);
    tr.querySelector("[data-act=del]").onclick = () => del(p);
    body.appendChild(tr);
  });
}

// copySecret fetches a value and copies it to the clipboard WITHOUT rendering
// it on screen — the safer default for shoulder-surfing / screen-sharing.
async function copySecret(path, btn) {
  const r = await fetch(pathURL(path));
  if (!r.ok) {
    flash(btn, r.status === 503 ? "sealed" : "error");
    return;
  }
  const { value } = await r.json();
  copyValue(value, btn);
}

async function copyValue(value, btn) {
  flash(btn, (await copyText(value)) ? "Copied!" : "copy failed");
}

// copyText prefers the async Clipboard API (needs a secure context: https or
// localhost) and falls back to an off-screen textarea for plain-HTTP access
// over a LAN/tailnet IP. The value is never shown to the user either way.
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      /* fall through to legacy path */
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

// flash briefly replaces a button's label with feedback, then restores it.
function flash(btn, text) {
  if (!btn.dataset.label) btn.dataset.label = btn.textContent;
  btn.textContent = text;
  btn.disabled = true;
  setTimeout(() => {
    btn.textContent = btn.dataset.label;
    btn.disabled = false;
  }, 1200);
}

async function reveal(tr, path) {
  const cell = tr.querySelector(".val");
  const r = await fetch(pathURL(path));
  if (!r.ok) {
    cell.innerHTML = `<span class="err">${r.status === 503 ? "sealed" : "error " + r.status}</span>`;
    return;
  }
  const { value } = await r.json();
  cell.innerHTML = "";
  const code = document.createElement("code");
  code.textContent = value;
  const copy = document.createElement("button");
  copy.textContent = "Copy";
  copy.className = "link";
  copy.onclick = (e) => copyValue(value, e.currentTarget);
  const hide = document.createElement("button");
  hide.textContent = "Hide";
  hide.className = "link";
  hide.onclick = () => { cell.innerHTML = '<span class="muted">••••••••</span>'; };
  cell.append(code, " ", copy, hide);
}

async function editSecret(path) {
  const r = await fetch(pathURL(path));
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
  const r = await api("DELETE", pathURL(path));
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
  const r = await api("PUT", pathURL(path), { value });
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

loadStatus();
loadSecrets();
setInterval(loadStatus, 4000);
