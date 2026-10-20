// The project picker. A local app page, so it may call the app's commands;
// the ProxyMind UI itself is a remote page and has no IPC.
const invoke = window.__TAURI__ && window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);
const showError = (e) => {
  $("error").textContent = String(e);
  $("error").hidden = false;
};

if (location.hash.length > 1) {
  $("why").textContent = "Couldn't open " + decodeURIComponent(location.hash.slice(1));
  $("why").hidden = false;
}

const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "project";
let dir = "";

async function load() {
  if (!invoke) return showError("This page only works inside the ProxyMind app.");
  const p = await invoke("list_projects");
  dir = p.suggested_dir;
  $("path").value = `${dir}/project.pmproj`;
  const ul = $("recent");
  ul.textContent = "";
  if (!p.recent.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "None yet.";
    ul.append(li);
  }
  for (const r of p.recent) {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.textContent = r.path === p.current ? "Open (current)" : "Open";
    b.disabled = !r.exists;
    b.onclick = () => invoke("open_project", { path: r.path }).catch(showError);
    const span = document.createElement("span");
    span.textContent = r.path + (r.exists ? "" : " (missing)");
    li.append(b, span);
    ul.append(li);
  }
}

$("name").addEventListener("input", () => {
  if (dir) $("path").value = `${dir}/${slug($("name").value)}.pmproj`;
});
$("open").addEventListener("submit", (e) => {
  e.preventDefault();
  invoke("open_project", { path: $("open-path").value }).catch(showError);
});
$("create").addEventListener("submit", (e) => {
  e.preventDefault();
  const scope = $("scope").value.split("\n").map((s) => s.trim()).filter(Boolean);
  invoke("create_project", { path: $("path").value, name: $("name").value, scope }).catch(showError);
});
load().catch(showError);
