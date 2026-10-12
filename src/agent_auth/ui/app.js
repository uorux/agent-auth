// The admin panel. Everything shown comes from the admin API; every value is
// put into the page as text (agents choose their names, descriptions and
// justifications, so none of it is ever parsed as HTML).
"use strict";

const state = { csrf: "", tab: "agents", data: {} };
const TABS = [
  ["agents", "Agents"],
  ["projects", "Projects"],
  ["hosts", "Hosts and VMs"],
  ["rules", "Saved rules"],
  ["requests", "Requests"],
];

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== null && value !== undefined && value !== false) node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// replaceChildren would write a skipped piece (null) out as the text "null".
function put(node, ...children) {
  node.replaceChildren(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
}

function notice(text, bad) {
  const box = document.getElementById("notice");
  box.textContent = text || "";
  box.hidden = !text;
  box.className = bad ? "bad" : "";
}

async function api(method, path, body) {
  const headers = {};
  if (method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (resp.status === 401) {
    location.href = "/ui/login";
    throw new Error("signed out");
  }
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!resp.ok) {
    const detail = data && data.detail !== undefined ? data.detail : text;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

async function act(what, fn) {
  notice("");
  try {
    const out = await fn();
    await show(state.tab, true);
    return out;
  } catch (err) {
    if (err.message !== "signed out") notice(`${what}: ${err.message}`, true);
    return undefined;
  }
}

function ago(value) {
  if (!value) return "never";
  const secs = (Date.now() - new Date(value).getTime()) / 1000;
  if (secs < 90) return "just now";
  if (secs < 5400) return `${Math.round(secs / 60)} min ago`;
  if (secs < 129600) return `${Math.round(secs / 3600)} h ago`;
  return `${Math.round(secs / 86400)} d ago`;
}

function pill(text, kind) { return el("span", { class: `pill ${kind || ""}` }, text); }
function button(text, onclick, cls) { return el("button", { type: "button", class: cls || "act", onclick }, text); }

function table(columns, rows, empty) {
  if (!rows.length) return el("p", { class: "muted" }, empty || "Nothing here.");
  return el("div", { class: "scroll" },
    el("table", {},
      el("thead", {}, el("tr", {}, columns.map((c) => el("th", {}, c[0])))),
      el("tbody", {}, rows.map((row) => el("tr", {}, columns.map((c) => {
        const value = c[1](row);
        return el("td", { class: c[2] || "" }, value === null || value === undefined || value === "" ? el("span", { class: "muted" }, "–") : value);
      }))))));
}

function field(label, name, attrs) {
  return el("label", {}, label, el("input", Object.assign({ name, autocomplete: "off", spellcheck: "false" }, attrs || {})));
}

function choice(label, name, options) {
  return el("label", {}, label, el("select", { name }, options.map((o) => el("option", { value: o[0] }, o[1]))));
}

function values(form) {
  const out = {};
  for (const [key, value] of new FormData(form).entries()) out[key] = String(value).trim();
  return out;
}

function secretBox(title, lines, secret, after) {
  return el("div", { class: "box" },
    el("h3", {}, title),
    lines.map((line) => el("p", { class: "note" }, line)),
    el("pre", { class: "mono" }, secret),
    button("Copy", () => navigator.clipboard.writeText(secret).then(() => notice("Copied."))),
    after || null);
}

// ── Agents ───────────────────────────────────────────────────────────────

async function agentsView(view) {
  const agents = await api("GET", "/admin/agents");
  const filter = el("input", { class: "filter", placeholder: "Filter by name, project, host…", "aria-label": "Filter agents" });
  const result = document.getElementById("result");
  const shown = el("div", {});

  const form = el("form", { class: "row", onsubmit: async (event) => {
    event.preventDefault();
    const v = values(form);
    const body = { name: v.name || [v.runtime, v.project, v.host].filter(Boolean).join("-"), kind: v.kind, description: v.description };
    for (const key of ["runtime", "project", "host"]) if (v[key]) body[key] = v[key];
    if (!body.name) return notice("Give the agent a name, or the fields a name is made of.", true);
    const made = await act("Creating the agent", () => api("POST", "/admin/agents", body));
    if (made) keyBox(made, "created");
  } },
    field("Runtime", "runtime", { placeholder: "claude", list: "runtimes" }),
    field("Project", "project", { placeholder: "task-tracker" }),
    field("Host", "host", { placeholder: "galaxy" }),
    field("Name (default: runtime-project-host)", "name", { size: 30 }),
    choice("Kind", "kind", [["ephemeral", "ephemeral: a CLI agent, opens threads only"], ["service", "service: always on, receives threads"]]),
    field("Description", "description", { size: 30 }),
    el("button", { type: "submit", class: "primary" }, "Create agent"),
    el("datalist", { id: "runtimes" }, ["claude", "codex", "hermes"].map((r) => el("option", { value: r }))));

  function keyBox(agent, verb) {
    result.replaceChildren(secretBox(
      `API key for ${agent.name} (${verb})`,
      ["Shown once: the broker keeps only its hash. Put it in the agent's MCP server environment as AGENT_AUTH_API_KEY, with AGENT_AUTH_URL set to this broker.",
       "For an agent in a VM, do not create it here: the VM's orchestrator mints it (see Hosts and VMs)."],
      agent.api_key));
  }

  function draw() {
    const needle = filter.value.trim().toLowerCase();
    const rows = agents.filter((a) => !needle || [a.name, a.runtime, a.project, a.host, a.placement, a.kind].join(" ").toLowerCase().includes(needle));
    shown.replaceChildren(table([
      ["Name", (a) => el("span", { class: "mono" }, a.name)],
      ["Runtime", (a) => a.runtime],
      ["Project", (a) => a.project],
      ["Host", (a) => a.host],
      ["Where", (a) => (a.placement === "sandbox" ? "VM" : "host")],
      ["Kind", (a) => a.kind],
      ["Seen", (a) => ago(a.last_seen_at)],
      ["State", (a) => (a.disabled ? pill("disabled", "bad") : pill("active", "good"))],
      ["", (a) => el("span", {},
        button("Fields", async () => {
          const next = prompt(`runtime, project, host for ${a.name} (comma-separated; empty clears a field)`, [a.runtime || "", a.project || "", a.host || ""].join(", "));
          if (next === null) return;
          const [runtime, project, host] = next.split(",").map((s) => s.trim());
          await act("Setting the fields", () => api("PATCH", `/admin/agents/${a.id}/attributes`, { runtime: runtime || "", project: project || "", host: host || "" }));
        }),
        button("Rename", async () => {
          const name = prompt(`New name for ${a.name} (its key and saved rules follow)`, a.name);
          if (!name || name === a.name) return;
          await act("Renaming", () => api("POST", `/admin/agents/${a.id}/rename`, { name: name.trim() }));
        }),
        button("New key", async () => {
          if (!confirm(`Replace ${a.name}'s API key? The current one stops working at once.`)) return;
          const made = await act("Rotating the key", () => api("POST", `/admin/agents/${a.id}/rotate-key`));
          if (made) keyBox(made, "rotated");
        }),
        a.disabled ? null : button("Disable", async () => {
          if (!confirm(`Disable ${a.name} and every agent it minted? Their grants end. There is no enable here.`)) return;
          await act("Disabling", () => api("POST", `/admin/agents/${a.id}/disable`));
        }, "act danger"))],
    ], rows, "No agent matches."));
  }
  filter.addEventListener("input", draw);
  put(view,
    el("h2", {}, "New agent on a host"),
    el("p", { class: "note" }, "The fields are what policy matches on (\"its own project's repo\", \"the homelab Hermes\"); the name is a label. An agent cannot change its own fields."),
    form,
    el("h2", {}, `Agents (${agents.length})`), filter, shown);
  draw();
}

// ── Projects ─────────────────────────────────────────────────────────────

async function projectsView(view) {
  const data = await api("GET", "/admin/projects");
  const rows = Object.entries(data.projects).sort((a, b) => a[0].localeCompare(b[0])).map(([name, p]) => Object.assign({ name }, p));
  put(view,
    el("h2", {}, "Projects"),
    el("p", { class: "note" }, "A project is the name on its agents' records. Listing it in the policy file (projects:, in nixos-dots) with its repos is what gives its agents \"their own repo\" without asking; that file is edited in git, not here."),
    table([
      ["Project", (p) => el("span", { class: "mono" }, p.name)],
      ["In policy", (p) => (p.in_policy ? pill("listed", "good") : pill("not listed", "warn"))],
      ["Repos", (p) => (p.repos.length ? p.repos.join(", ") : null), "wrap"],
      ["Agents", (p) => (p.agents.length ? p.agents.join(", ") : null), "wrap"],
      ["Description", (p) => p.description, "wrap"],
    ], rows, "No projects yet."),
    el("h2", {}, "A project in an agent VM"),
    el("p", { class: "note" }, "The VM's own daemon creates projects and its orchestrator mints their agents; the broker cannot do it from here yet. On the host that runs the VM:"),
    el("pre", { class: "mono" }, "avm project-create <project>\navm claude <project>      # or: avm codex <project>\navm ls"),
    data.wiki ? el("p", { class: "note" }, `Wiki: ${data.wiki}. A project's agents write under projects/<project>/ there.`) : null);
}

// ── Hosts and VMs ────────────────────────────────────────────────────────

async function hostsView(view) {
  const [hosts, daemons] = await Promise.all([
    api("GET", "/admin/hosts").catch((err) => ({ error: err.message, hosts: [] })),
    api("GET", "/admin/daemons"),
  ]);
  const result = document.getElementById("result");
  const form = el("form", { class: "row", onsubmit: async (event) => {
    event.preventDefault();
    const v = values(form);
    if (!v.name) return notice("Which host?", true);
    const made = await act("Making a pairing code", () => api("POST", "/admin/daemons/pairing-codes", { role: v.role, name: v.name }));
    if (!made) return;
    const command = v.role === "host" ? "sudo agent-auth-hostd pair" : "avm pair";
    result.replaceChildren(secretBox(
      `Pairing code for ${v.name} (${v.role === "host" ? "hostd" : "the VM's sandboxd"})`,
      [`One use, valid until ${new Date(made.expires_at).toLocaleTimeString()}. On ${v.name}, run the command below and type the code at its prompt (never as an argument).`,
       v.role === "host" ? "Then enrol the host's TOTP secrets once: sudo agent-auth-hostd totp-enroll" : "That creates the VM's orchestrator agent at the broker."],
      made.code,
      el("pre", { class: "mono" }, command)));
  } },
    field("Host", "name", { placeholder: "carrack" }),
    choice("Daemon", "role", [["host", "hostd: commands on the host"], ["sandbox", "sandboxd: the agent VM"]]),
    el("button", { type: "submit", class: "primary" }, "Make pairing code"));

  const tiers = (h) => Object.entries(h.tiers || {}).map(([name, t]) => `${name}${t.shell ? " +shell" : ""}${t.armed || t.armed_until ? " (armed)" : ""}`).join(", ");
  put(view,
    el("h2", {}, "Hosts"),
    hosts.error ? el("p", { class: "note" }, hosts.error) : null,
    hosts.lockdown && (hosts.lockdown.hosts || []).length
      ? el("p", {}, pill(`lockdown: ${hosts.lockdown.hosts.includes("*") ? "everything" : hosts.lockdown.hosts.join(", ")}`, "bad"))
      : null,
    table([
      ["Host", (h) => el("span", { class: "mono" }, h.name)],
      ["State", (h) => (h.online ? pill("online", "good") : pill("offline", "bad"))],
      ["Tiers", (h) => tiers(h) || null],
      ["Lockdown", (h) => (h.lockdown ? pill("locked", "bad") : null)],
      ["VM", (h) => (h.vm ? (typeof h.vm === "object" ? (h.vm.state || h.vm.unit || "yes") : String(h.vm)) : null)],
      ["Commands", (h) => (h.templates || []).join(", ") || null, "wrap"],
    ], hosts.hosts, "No host is paired."),
    el("p", { class: "note" }, "Arming a tier, approving commands and lifting a lockdown are not here: they stay on Discord and the hosts' own TOTP codes."),
    el("h2", {}, "Pair a host or its VM"), form,
    el("h2", {}, "Paired daemons"),
    table([
      ["Host", (d) => el("span", { class: "mono" }, d.name)],
      ["Daemon", (d) => (d.role === "host" ? "hostd" : "sandboxd")],
      ["State", (d) => (d.online ? pill("online", "good") : pill("offline", "bad"))],
      ["Version", (d) => d.version],
      ["Seen", (d) => ago(d.last_seen_at)],
      ["Fingerprint", (d) => el("span", { class: "mono" }, d.fingerprint)],
      ["", (d) => button("Unpair", async () => {
        if (!confirm(`Unpair ${d.role === "host" ? "hostd" : "sandboxd"} on ${d.name}? It must be paired again to come back.`)) return;
        await act("Unpairing", () => api("DELETE", `/admin/daemons/${d.id}`));
      }, "act danger")],
    ], daemons, "No daemon is paired."));
}

// ── Saved rules ──────────────────────────────────────────────────────────

async function rulesView(view) {
  const rules = await api("GET", "/admin/rules");
  put(view,
    el("h2", {}, `Saved rules (${rules.length})`),
    el("p", { class: "note" }, "Rules you made from a Discord approval (\"always allow this\"). They are checked before the policy file's rules. Deleting one sends the next such request back to the file's rules, or to you. New ones are made on Discord, not here."),
    table([
      ["Action", (r) => (r.action === "auto_approve" ? pill("approve", "good") : pill(r.action, "bad"))],
      ["Agent", (r) => el("span", { class: "mono" }, r.agent_pattern)],
      ["For", (r) => r.delegator_pattern],
      ["Platform", (r) => r.platform],
      ["What", (r) => r.capability_pattern, "wrap"],
      ["Resource", (r) => el("span", { class: "mono" }, r.resource_pattern), "wrap"],
      ["Max", (r) => (r.max_duration_secs ? `${Math.round(r.max_duration_secs / 360) / 10} h` : null)],
      ["On", (r) => (r.enabled ? null : pill("off", "warn"))],
      ["Notes", (r) => r.notes, "wrap"],
      ["", (r) => button("Delete", async () => {
        if (!confirm(`Delete the rule for ${r.agent_pattern} on ${r.platform} ${r.resource_pattern}?`)) return;
        await act("Deleting the rule", () => api("DELETE", `/admin/rules/${r.id}`));
      }, "act danger")],
    ], rules, "No saved rules."));
}

// ── Requests ─────────────────────────────────────────────────────────────

async function requestsView(view) {
  const requests = await api("GET", "/admin/requests?limit=150");
  const kind = (s) => (s === "granted" ? "good" : s === "denied" || s === "provision_failed" || s === "llm_denied" ? "bad" : "warn");
  put(view,
    el("h2", {}, "Recent requests"),
    el("p", { class: "note" }, "Read-only. Requests are decided on Discord (and at your desk), never here."),
    table([
      ["When", (r) => ago(r.created_at)],
      ["Agent", (r) => el("span", { class: "mono" }, r.agent)],
      ["For", (r) => r.delegator],
      ["Platform", (r) => r.platform],
      ["What", (r) => r.capability],
      ["Resource", (r) => el("span", { class: "mono" }, r.resource), "wrap"],
      ["Status", (r) => pill(r.status, kind(r.status))],
      ["By", (r) => r.decision_source],
      ["Why", (r) => r.justification, "wrap"],
      ["Grant", (r) => (r.grant_id && r.status === "granted" ? button("Revoke", async () => {
        if (!confirm(`Revoke ${r.agent}'s grant on ${r.platform} ${r.resource}?`)) return;
        await act("Revoking", () => api("POST", `/admin/grants/${r.grant_id}/revoke?reason=${encodeURIComponent("revoked from the admin panel")}`));
      }, "act danger") : null)],
    ], requests, "No requests yet."));
}

const VIEWS = { agents: agentsView, projects: projectsView, hosts: hostsView, rules: rulesView, requests: requestsView };

async function show(tab, keepNotice) {
  state.tab = tab;
  history.replaceState(null, "", `#${tab}`);
  if (!keepNotice) {
    notice("");
    document.getElementById("result").replaceChildren();
  }
  for (const node of document.querySelectorAll("#tabs button")) node.className = node.dataset.tab === tab ? "on" : "";
  const view = document.getElementById("view");
  try {
    await VIEWS[tab](view);
  } catch (err) {
    if (err.message !== "signed out") notice(err.message, true);
  }
}

async function start() {
  const session = await api("GET", "/ui/session");
  state.csrf = session.csrf;
  document.getElementById("who").textContent = session.user;
  document.getElementById("logout").addEventListener("click", async () => {
    await fetch("/ui/logout", { method: "POST", headers: { "X-CSRF-Token": state.csrf }, credentials: "same-origin" });
    document.body.replaceChildren(el("main", { class: "message" }, el("h1", {}, "agent-auth"), el("p", {}, "Signed out."), el("p", {}, el("a", { href: "/ui/login" }, "Sign in"))));
  });
  document.getElementById("tabs").append(...TABS.map(([id, label]) => {
    const node = button(label, () => show(id), "");
    node.dataset.tab = id;
    return node;
  }));
  const wanted = location.hash.slice(1);
  await show(VIEWS[wanted] ? wanted : "agents");
}

start().catch((err) => { if (err.message !== "signed out") notice(err.message, true); });
