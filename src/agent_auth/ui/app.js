// The admin panel. Everything shown comes from the admin API; every value is
// put into the page as text (agents choose their names, descriptions and
// justifications, so none of it is ever parsed as HTML).
"use strict";

const state = { csrf: "", user: "", tab: "chat", data: {} };
const TABS = [
  ["chat", "Chat"],
  ["agents", "Agents"],
  ["projects", "Projects"],
  ["hosts", "Hosts and VMs"],
  ["conversations", "Conversations"],
  ["decisions", "Decisions"],
  ["commands", "Commands"],
  ["usage", "Model usage"],
  ["rules", "Saved rules"],
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
      ["", (a) => (a.kind === "operator" ? el("span", { class: "muted" }, "you, in Chat") : el("span", {},
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
        }, "act danger")))],
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

// ── Decisions ────────────────────────────────────────────────────────────

const SOURCES = { human: "a person", rule: "a saved rule", policy: "the policy file", llm: "the LLM reviewer" };

function statusKind(status) {
  if (status === "granted" || status === "done") return "good";
  if (["denied", "provision_failed", "llm_denied", "refused", "lost"].includes(status)) return "bad";
  return "warn";
}

async function decisionsView(view) {
  const source = el("select", { "aria-label": "Decided by" },
    [["", "Decided by anyone"], ["human", "A person"], ["rule", "A saved rule"], ["policy", "The policy file"], ["llm", "The LLM reviewer"]]
      .map((o) => el("option", { value: o[0] }, o[1])));
  const filter = el("input", { class: "filter", placeholder: "Filter by agent, resource, reason…", "aria-label": "Filter decisions" });
  const shown = el("div", {});
  let rows = [];
  function draw() {
    const needle = filter.value.trim().toLowerCase();
    const some = rows.filter((r) => !needle || [r.agent, r.for, r.platform, r.what, r.resource, r.reason, r.by, r.status].join(" ").toLowerCase().includes(needle));
    put(shown, table([
      ["When", (r) => el("span", { title: new Date(r.at).toLocaleString() }, ago(r.at))],
      ["Agent", (r) => el("span", { class: "mono" }, r.agent)],
      ["For", (r) => r.for],
      ["Platform", (r) => r.platform],
      ["What", (r) => r.what, "wrap"],
      ["Resource", (r) => el("span", { class: "mono" }, r.resource), "wrap"],
      ["Outcome", (r) => pill(r.status, statusKind(r.status))],
      ["Decided by", (r) => (r.source ? `${SOURCES[r.source] || r.source}${r.by && r.source === "human" ? ` (${r.by})` : ""}` : null)],
      ["Reason given", (r) => r.reason, "wrap"],
      ["Asked because", (r) => r.justification, "wrap"],
    ], some, "No decision matches."));
  }
  async function load() {
    rows = await api("GET", `/admin/log/decisions?limit=300${source.value ? `&source=${source.value}` : ""}`);
    draw();
  }
  source.addEventListener("change", () => load().catch((err) => notice(err.message, true)));
  filter.addEventListener("input", draw);
  put(view,
    el("h2", {}, "Decisions"),
    el("p", { class: "note" }, "Every request and who decided it: you, a rule you saved from Discord, a rule in the policy file, or the LLM reviewer. Read-only: requests are decided on Discord and at your desk."),
    el("form", { class: "row" }, el("label", {}, "Decided by", source), el("label", {}, "Filter", filter)),
    shown);
  await load();
}

// ── Commands ─────────────────────────────────────────────────────────────

async function commandsView(view) {
  const rows = await api("GET", "/admin/log/commands?limit=300");
  const result = document.getElementById("result");
  const took = (ms) => (ms === null || ms === undefined ? null : ms < 1000 ? `${ms} ms` : `${Math.round(ms / 100) / 10} s`);
  put(view,
    el("h2", {}, "Commands on hosts"),
    el("p", { class: "note" }, "What each host's daemon ran, or refused, for an agent. \"Admitted on\" is what the host itself accepted: a TOTP code, your approval at its desk, or an armed tier plus your approval."),
    table([
      ["When", (j) => el("span", { title: new Date(j.at).toLocaleString() }, ago(j.at))],
      ["Agent", (j) => el("span", { class: "mono" }, j.agent)],
      ["Host", (j) => j.host],
      ["As", (j) => (j.tier === "root" ? pill("root", "bad") : "user") ],
      ["Command", (j) => el("span", { class: "mono" }, `${j.shell ? "(shell) " : ""}${j.command}`), "wrap"],
      ["Outcome", (j) => pill(j.status === "done" ? `exit ${j.exit_code}` : j.status, j.status === "done" ? (j.exit_code === 0 ? "good" : "warn") : statusKind(j.status))],
      ["Admitted on", (j) => j.via],
      ["Took", (j) => took(j.duration_ms)],
      ["", (j) => button("Output", async () => {
        notice("");
        try {
          const d = await api("GET", `/admin/log/commands/${j.id}`);
          put(result, el("div", { class: "box" },
            el("h3", {}, `${d.agent} on ${d.host} as ${d.tier}`),
            el("pre", { class: "mono" }, d.command),
            d.justification ? el("p", { class: "note" }, `Asked because: ${d.justification}`) : null,
            d.error ? el("p", { class: "note" }, `Host said: ${d.error}`) : null,
            el("pre", { class: "mono output" }, d.output || "(no output)"),
            d.output_cut ? el("p", { class: "note" }, `Only the end is shown (${d.output_bytes} bytes in all).`) : null));
          result.scrollIntoView({ behavior: "smooth" });
        } catch (err) { notice(err.message, true); }
      })],
    ], rows, "No host has run anything yet."));
}

// ── Model usage ──────────────────────────────────────────────────────────

const dollars = (v) => (v >= 100 ? `$${Math.round(v)}` : `$${v.toFixed(2)}`);

function spendBar(value, most) {
  const pct = most > 0 ? Math.max(1, Math.round((value / most) * 100)) : 0;
  return el("span", { class: "spend" }, el("span", { class: "spend-bar", "data-pct": pct }), el("span", {}, dollars(value)));
}

async function usageView(view) {
  const data = await api("GET", "/admin/models/usage");
  if (!data.enabled) {
    put(view, el("h2", {}, "Model usage"),
      el("p", { class: "note" }, "No model gateway is set up (platforms.models in the policy file). Once it is, each agent gets its own LiteLLM key and its spend shows here."));
    return;
  }
  const byProject = new Map();
  for (const r of data.agents) {
    const key = r.project || "(no project)";
    byProject.set(key, (byProject.get(key) || 0) + r.spend);
  }
  const projects = [...byProject.entries()].map(([project, spend]) => ({ project, spend })).sort((a, b) => b.spend - a.spend);
  const mostAgent = Math.max(0, ...data.agents.map((r) => r.spend));
  const mostProject = Math.max(0, ...projects.map((r) => r.spend));
  const total = data.agents.reduce((sum, r) => sum + r.spend, 0);
  put(view,
    el("h2", {}, "Model usage"),
    el("p", { class: "note" }, `Counted by the gateway (${data.gateway}): each agent is a LiteLLM user, across every key the broker gave it. With subscriptions behind the gateway these are list prices, not a bill; they compare agents.`),
    data.error ? el("p", { class: "note" }, `The gateway did not answer: ${data.error}`) : null,
    el("p", {}, el("strong", {}, dollars(total)), el("span", { class: "muted" }, " in all")),
    el("h2", {}, "By project"),
    table([
      ["Project", (r) => el("span", { class: "mono" }, r.project)],
      ["Spend", (r) => spendBar(r.spend, mostProject), "wide"],
    ], projects, "Nothing spent yet."),
    el("h2", {}, "By agent"),
    table([
      ["Agent", (r) => el("span", { class: "mono" }, r.agent)],
      ["Runtime", (r) => r.runtime],
      ["Project", (r) => r.project],
      ["Host", (r) => r.host],
      ["Where", (r) => (r.placement === "sandbox" ? "VM" : "host")],
      ["Spend", (r) => spendBar(r.spend, mostAgent), "wide"],
      ["Budget", (r) => (r.max_budget ? dollars(r.max_budget) : null)],
    ], data.agents, "No agent has a key yet."));
  // Widths set here, not inline in markup: the page's CSP has no inline styles.
  for (const bar of view.querySelectorAll(".spend-bar")) bar.style.width = `${bar.dataset.pct}%`;
}

// ── Conversations between agents ─────────────────────────────────────────

const SVG_NS = "http://www.w3.org/2000/svg";
function svg(tag, attrs, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== null && value !== undefined && value !== false) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const W = 1120, H = 620;
const positions = new Map(); // agent name -> {x, y}, kept across refreshes so the picture holds still

// Hosts get a place each on an ellipse; agents settle near their host,
// pushed apart from each other and pulled along the conversations they had.
function layout(nodes, edges) {
  const hosts = [...new Set(nodes.map((n) => n.host || "(no host)"))].sort();
  const centre = new Map(hosts.map((h, i) => {
    const angle = (2 * Math.PI * i) / Math.max(hosts.length, 1) - Math.PI / 2;
    return [h, { x: W / 2 + (hosts.length > 1 ? W * 0.34 : 0) * Math.cos(angle), y: H / 2 + (hosts.length > 1 ? H * 0.3 : 0) * Math.sin(angle) }];
  }));
  const pts = nodes.map((n, i) => {
    const c = centre.get(n.host || "(no host)");
    const kept = positions.get(n.name);
    const angle = i * 2.399963; // golden angle: spread without randomness
    return { n, c, x: kept ? kept.x : c.x + 46 * Math.cos(angle), y: kept ? kept.y : c.y + 46 * Math.sin(angle), dx: 0, dy: 0 };
  });
  const index = new Map(pts.map((p) => [p.n.name, p]));
  for (let step = 0; step < 320; step += 1) {
    const heat = 1 - step / 320;
    for (const p of pts) { p.dx = (p.c.x - p.x) * 0.03; p.dy = (p.c.y - p.y) * 0.03; }
    for (let i = 0; i < pts.length; i += 1) {
      for (let j = i + 1; j < pts.length; j += 1) {
        const a = pts[i], b = pts[j];
        // Names are wide and sit under their dots: sideways distance counts
        // for less, so neighbours end up beside each other only when far
        // apart, and otherwise above and below.
        let ex = (a.x - b.x) / 2.6, ey = a.y - b.y;
        if (ex === 0 && ey === 0) ey = 1;
        const d2 = Math.max(ex * ex + ey * ey, 25);
        const d = Math.sqrt(d2);
        const push = 9000 / d2;
        ex /= d; ey /= d;
        a.dx += ex * push * 2.6; a.dy += ey * push; b.dx -= ex * push * 2.6; b.dy -= ey * push;
      }
    }
    for (const e of edges) {
      const a = index.get(e.from), b = index.get(e.to);
      if (!a || !b) continue;
      const ex = b.x - a.x, ey = b.y - a.y;
      const d = Math.max(Math.hypot(ex, ey), 1);
      const pull = (d - 300) * 0.006;
      a.dx += (ex / d) * pull; a.dy += (ey / d) * pull; b.dx -= (ex / d) * pull; b.dy -= (ey / d) * pull;
    }
    for (const p of pts) {
      const move = Math.min(Math.hypot(p.dx, p.dy), 14 * heat + 0.5);
      const d = Math.max(Math.hypot(p.dx, p.dy), 0.001);
      p.x = Math.min(Math.max(p.x + (p.dx / d) * move, 110), W - 110);
      p.y = Math.min(Math.max(p.y + (p.dy / d) * move, 50), H - 56);
    }
  }
  for (const p of pts) positions.set(p.n.name, { x: p.x, y: p.y });
  return { index, hosts };
}

// Under a dot: the name without what its surroundings already say (the host
// is the region's title, the dashed ring is the VM). The whole name is in
// the hover and in the table.
function shortName(node) {
  let name = node.name;
  if (node.placement === "sandbox" && name.endsWith("-sandbox")) name = name.slice(0, -"-sandbox".length);
  if (node.host && name.endsWith(`-${node.host}`)) name = name.slice(0, -node.host.length - 1);
  return name || node.name;
}

function runtimeClass(node) {
  return ["claude", "codex", "hermes"].includes(node.runtime) ? `rt-${node.runtime}` : "rt-other";
}

async function conversationsView(view) {
  const range = el("select", { "aria-label": "Period" }, [[1, "the last hour"], [24, "the last 24 hours"], [168, "the last 7 days"], [720, "the last 30 days"]].map((o) => el("option", { value: o[0], selected: o[0] === 24 }, o[1])));
  const stage = el("div", { class: "graph" });
  const tip = el("div", { class: "tip", hidden: true });
  const list = el("div", {});
  const result = document.getElementById("result");
  let picked = null; // {from, to} or {agent}

  function showTip(event, lines) {
    put(tip, lines.map((line, i) => el("div", { class: i ? "muted" : "" }, line)));
    tip.hidden = false;
    const box = stage.getBoundingClientRect();
    tip.style.left = `${Math.min(event.clientX - box.left + 14, box.width - 250)}px`;
    tip.style.top = `${event.clientY - box.top + 14}px`;
  }
  const hideTip = () => { tip.hidden = true; };

  async function openThread(id) {
    notice("");
    try {
      const t = await api("GET", `/admin/a2a/threads/${id}`);
      put(result, el("div", { class: "box" },
        el("h3", {}, `${t.from} → ${t.to}${t.topic ? `: ${t.topic}` : ""}`),
        el("p", { class: "note" }, `${t.state}${t.close_reason ? ` (${t.close_reason})` : ""}, opened ${new Date(t.opened).toLocaleString()}. What agents wrote to each other, as text.`),
        t.requests.length ? el("p", { class: "note" }, `Access ${t.to} asked for on ${t.from}'s behalf: ${t.requests.map((r) => `${r.platform} ${r.what} on ${r.resource} (${r.status})`).join("; ")}`) : null,
        t.messages.map((m) => el("div", { class: "msg" },
          el("div", { class: "muted" }, `#${m.seq} ${m.from}${m.type ? ` · ${m.type}` : ""} · ${new Date(m.at).toLocaleTimeString()}`),
          el("pre", { class: "mono output" }, m.text + (m.cut ? "\n… (cut)" : ""))))));
      result.scrollIntoView({ behavior: "smooth" });
    } catch (err) { notice(err.message, true); }
  }

  function drawList(data) {
    const rows = data.threads.filter((t) => !picked || (picked.agent ? t.from === picked.agent || t.to === picked.agent : t.from === picked.from && t.to === picked.to));
    put(list,
      el("h2", {}, picked ? (picked.agent ? `Conversations of ${picked.agent} (${rows.length})` : `${picked.from} → ${picked.to} (${rows.length})`) : `Conversations (${rows.length})`),
      picked ? el("p", {}, button("Show all", () => { picked = null; drawList(data); })) : null,
      table([
        ["Last", (t) => el("span", { title: new Date(t.last).toLocaleString() }, ago(t.last))],
        ["From", (t) => el("span", { class: "mono" }, t.from)],
        ["To", (t) => el("span", { class: "mono" }, t.to)],
        ["Topic", (t) => t.topic, "wrap"],
        ["", (t) => button("Read", () => openThread(t.id))],
        ["State", (t) => pill(t.state === "pending_open" ? "waiting" : t.close_reason && t.close_reason !== "closed" ? `closed: ${t.close_reason}` : t.state, t.state === "open" ? "good" : t.state === "pending_open" ? "warn" : "")],
        ["Messages", (t) => t.messages],
        ["Access asked", (t) => t.requests || null],
      ], rows, "No conversations in this period."));
  }

  function draw(data) {
    const { index, hosts } = layout(data.nodes, data.edges);
    const recent = (e) => e.open > 0 || Date.now() - new Date(e.last).getTime() < 10 * 60 * 1000;
    const pair = new Set(data.edges.map((e) => `${e.from}>${e.to}`));
    const regions = hosts.map((h) => {
      const mine = [...index.values()].filter((p) => (p.n.host || "(no host)") === h);
      if (!mine.length) return null;
      const x0 = Math.min(...mine.map((p) => p.x)) - 96, x1 = Math.max(...mine.map((p) => p.x)) + 96;
      const y0 = Math.min(...mine.map((p) => p.y)) - 36, y1 = Math.max(...mine.map((p) => p.y)) + 42;
      return svg("g", {},
        svg("rect", { class: "host", x: x0, y: y0, width: x1 - x0, height: y1 - y0, rx: 16 }),
        svg("text", { class: "host-name", x: x0 + 12, y: y0 + 16 }, h));
    });
    const lines = data.edges.map((e) => {
      const a = index.get(e.from), b = index.get(e.to);
      if (!a || !b) return null;
      const ex = b.x - a.x, ey = b.y - a.y, d = Math.max(Math.hypot(ex, ey), 1);
      // Bend, so the two directions between a pair do not lie on each other.
      const bend = pair.has(`${e.to}>${e.from}`) ? 26 : 12;
      const mx = (a.x + b.x) / 2 - (ey / d) * bend, my = (a.y + b.y) / 2 + (ex / d) * bend;
      const sx = a.x + (ex / d) * 13, sy = a.y + (ey / d) * 13, tx = b.x - (ex / d) * 17, ty = b.y - (ey / d) * 17;
      const path = `M${sx.toFixed(1)},${sy.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${tx.toFixed(1)},${ty.toFixed(1)}`;
      const width = (1.2 + Math.min(Math.log2(1 + e.messages), 5) * 0.7).toFixed(1);
      const over = (event) => showTip(event, [`${e.from} → ${e.to}`, `${e.threads} conversation${e.threads === 1 ? "" : "s"}, ${e.open} open`, `${e.messages} messages`, e.requests ? `${e.requests} access request${e.requests === 1 ? "" : "s"} made on its behalf` : null, `last ${ago(e.last)}`].filter(Boolean));
      return svg("g", { class: `edge${e.open ? " open" : ""}` },
        svg("path", { class: "line", d: path, "stroke-width": width, "marker-end": `url(#arrow${e.open ? "-open" : ""})` }),
        recent(e) ? svg("path", { class: "flow", d: path, "stroke-width": width }) : null,
        svg("text", { class: "count", x: mx, y: my - 4, "text-anchor": "middle" }, e.messages),
        svg("path", { class: "hit", d: path, onmousemove: over, onmouseleave: hideTip, onclick: () => { picked = { from: e.from, to: e.to }; drawList(data); } }));
    });
    const dots = [...index.values()].map((p) => {
      const n = p.n;
      const cls = `node ${runtimeClass(n)}${n.alive ? " alive" : ""}`;
      const over = (event) => showTip(event, [n.name, [n.runtime, n.project, n.host, n.placement === "sandbox" ? "in the VM" : null].filter(Boolean).join(" · "), n.alive ? "connected now" : "not connected"]);
      const shape = n.runtime === "orchestrator"
        ? svg("rect", { class: "mark", x: -10, y: -10, width: 20, height: 20, rx: 5 })
        : svg("circle", { class: "mark", r: 10 });
      return svg("g", { class: cls, transform: `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`, onmousemove: over, onmouseleave: hideTip, onclick: () => { picked = { agent: n.name }; drawList(data); } },
        n.alive ? svg("circle", { class: "pulse", r: 10 }) : null,
        n.placement === "sandbox" ? svg("circle", { class: "vm", r: 15 }) : null,
        shape,
        svg("text", { class: "name", y: 27, "text-anchor": "middle" }, shortName(n)));
    });
    const arrow = (id) => svg("marker", { id, viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse", markerUnits: "userSpaceOnUse" }, svg("path", { d: "M0,1 L9,5 L0,9 z" }));
    const picture = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Which agents talked to which. The table below lists the same conversations." },
      svg("defs", {}, arrow("arrow"), arrow("arrow-open")),
      regions, lines, dots);
    put(stage, data.nodes.length ? picture : el("p", { class: "muted pad" }, "No agent is connected and none talked in this period."), tip);
    drawList(data);
  }

  async function load() {
    draw(await api("GET", `/admin/a2a/graph?hours=${range.value}`));
  }
  range.addEventListener("change", () => { picked = null; load().catch((err) => notice(err.message, true)); });
  const key = (cls, text, square) => el("span", { class: "key" }, el("span", { class: `swatch ${cls}${square ? " square" : ""}` }), text);
  put(view,
    el("h2", {}, "Who talks to whom"),
    el("p", { class: "note" }, "An arrow runs from the agent that opened conversations to the one that answered; thicker means more messages, and the number is the message count. Moving dashes mark a conversation that is open or was active in the last ten minutes. Click an agent or an arrow to list its conversations."),
    el("form", { class: "row" }, el("label", {}, "Period", range), button("Refresh", () => load().catch((err) => notice(err.message, true)), "act")),
    el("div", { class: "legend" },
      key("rt-claude", "claude"), key("rt-codex", "codex"), key("rt-hermes", "hermes"), key("rt-other", "orchestrator", true), key("rt-other", "other"),
      key("hollow", "not connected"), key("ring", "in an agent VM")),
    stage, list);
  await load();
  clearInterval(state.timer);
  state.timer = setInterval(() => { if (state.tab === "conversations" && !document.hidden) load().catch(() => {}); }, 20000);
}

// ── Chat ─────────────────────────────────────────────────────────────────

// The operator's conversations with agents: a2a threads opened from here.
// `gen` stops an old long-poll loop when another conversation is opened or
// the tab is left.
const chat = { open: null, seq: 0, gen: 0, to: null };

function said(m) {
  if (m.text !== null && m.text !== undefined) return m.text;
  if (m.type === "result") return m.summary || "";
  return JSON.stringify(m.payload, null, 1);
}

function stateLabel(t) {
  if (t.state === "pending_open") return pill("waiting for an answer", "warn");
  if (t.state === "open") return pill("open", "good");
  return pill(t.close_reason && t.close_reason !== "closed" ? `closed: ${t.close_reason}` : "closed", "");
}

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

async function chatView(view) {
  const [peers, threads] = await Promise.all([api("GET", "/admin/chat/peers"), api("GET", "/admin/chat/threads")]);
  const side = el("aside", { class: "chat-side" });
  const pane = el("section", { class: "chat-pane" });
  chat.gen += 1;

  function drawSide(list) {
    put(side,
      button("New conversation", () => { chat.open = null; drawSide(list); drawNew(); }, "primary wide"),
      list.length ? null : el("p", { class: "muted" }, "No conversations yet."),
      el("ul", { class: "chat-list" }, list.map((t) => el("li", {},
        el("button", { type: "button", class: t.id === chat.open ? "on" : "", onclick: () => openConversation(t.id) },
          el("span", { class: "chat-to" }, el("span", { class: "mono" }, t.to), " ", el("span", { class: "muted" }, ago(t.last))),
          t.topic ? el("span", { class: "chat-topic" }, t.topic) : null,
          el("span", { class: "chat-preview muted" }, `${t.last_from_operator ? "You: " : ""}${t.preview}`),
          stateLabel(t))))));
  }

  async function refreshSide() {
    try { drawSide(await api("GET", "/admin/chat/threads")); } catch (err) { /* the next refresh will do */ }
  }

  function composer(onsend, placeholder) {
    const text = el("textarea", { rows: 3, placeholder, "aria-label": "Message" });
    const send = el("button", { type: "submit", class: "primary" }, "Send");
    const form = el("form", { class: "composer", onsubmit: async (event) => {
      event.preventDefault();
      const body = text.value.trim();
      if (!body) return;
      send.disabled = true;
      notice("");
      try {
        await onsend(body);
        text.value = "";
      } catch (err) {
        if (err.message !== "signed out") notice(`Sending: ${err.message}`, true);
      } finally {
        send.disabled = false;
        text.focus();
      }
    } }, text, el("div", { class: "composer-bar" }, el("span", { class: "muted" }, "Enter sends, Shift+Enter for a new line"), send));
    text.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); form.requestSubmit(); }
    });
    return { form, text };
  }

  function drawNew(to) {
    chat.gen += 1;
    history.replaceState(null, "", "#chat");
    const listening = peers.filter((p) => p.reachable);
    const asleep = peers.filter((p) => !p.reachable);
    const pick = el("select", { name: "to", "aria-label": "Agent" },
      listening.map((p) => el("option", { value: p.name, selected: p.name === to }, p.name)),
      asleep.length ? el("optgroup", { label: "Not listening now" }, asleep.map((p) => el("option", { value: p.name, disabled: true }, p.name))) : null);
    const topic = el("input", { name: "topic", placeholder: "optional", maxlength: 256, autocomplete: "off" });
    const { form, text } = composer(async (body) => {
      const opened = await api("POST", "/admin/chat/threads", { to: pick.value, topic: topic.value.trim() || null, text: body });
      await openConversation(opened.thread_id);
    }, "What do you want to say?");
    put(pane,
      el("h2", {}, "New conversation"),
      el("p", { class: "note" }, "You write as operator. Only service agents receive conversations (Hermes, the VMs' orchestrators); a Claude Code session in a terminal cannot be written to. What an agent asks for on your behalf is decided where every request is: rules, the reviewer, or you on Discord."),
      listening.length
        ? el("div", { class: "row" }, el("label", {}, "To", pick), el("label", {}, "Topic", topic))
        : el("p", { class: "note" }, "No agent is listening for conversations right now."),
      listening.length ? form : null);
    if (listening.length) text.focus();
  }

  function bubble(m) {
    const mine = m.from === "operator";
    const who = mine ? (m.operator && m.operator !== state.user ? m.operator : "You") : m.from;
    return el("div", { class: `bubble${mine ? " mine" : ""}${m.type === "result" ? " result" : ""}` },
      el("div", { class: "bubble-head muted" }, who, " · ", el("span", { title: new Date(m.at).toLocaleString() }, new Date(m.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })),
        m.type && m.type !== "message" ? ` · ${m.type}` : null),
      m.type === "result" && m.status ? pill(m.status, statusKind(m.status === "done" ? "done" : m.status === "failed" ? "denied" : "")) : null,
      el("div", { class: "bubble-text" }, said(m)));
  }

  async function openConversation(id) {
    const gen = (chat.gen += 1);
    chat.open = id;
    history.replaceState(null, "", `#chat/${id}`);
    chat.seq = 0;
    notice("");
    const head = el("div", { class: "chat-head" });
    const log = el("div", { class: "chat-log", role: "log", "aria-live": "polite" });
    const asked = el("div", {});
    const foot = el("div", {});
    put(pane, head, log, asked, foot);
    const { form, text } = composer(async (body) => {
      await api("POST", `/admin/chat/threads/${id}/messages`, { text: body });
      await pull(0);
    }, "Reply…");
    let last = null;

    function drawHead(t) {
      chat.to = t.peer;
      put(head,
        el("div", {}, el("h2", {}, el("span", { class: "mono" }, t.peer), t.topic ? el("span", { class: "muted" }, ` · ${t.topic}`) : null),
          el("div", { class: "muted small" }, stateLabel(t), " ", t.state === "closed" ? null : (t.peer_alive ? "connected" : "not seen in the last two minutes"))),
        t.state === "closed" ? null : button("End conversation", async () => {
          if (!confirm(`End this conversation with ${t.peer}?`)) return;
          try { await api("POST", `/admin/chat/threads/${id}/close`, { reason: "ended from the admin panel" }); await pull(0); } catch (err) { notice(err.message, true); }
        }, "act"));
      if (t.state === "open") put(foot, form);
      else if (t.state === "pending_open") put(foot, el("p", { class: "note" }, `Waiting for ${t.peer} to take the conversation; you can write again once it answers.`));
      else put(foot, el("p", { class: "note" }, `Ended${t.close_reason && t.close_reason !== "closed" ? ` (${t.close_reason})` : ""}${t.close_note ? `: ${t.close_note}` : ""}. `,
        button(`New conversation with ${t.peer}`, () => { chat.open = null; refreshSide(); drawNew(t.peer); }, "act")));
    }

    async function pull(wait) {
      const out = await api("GET", `/admin/chat/threads/${id}?after_seq=${chat.seq}&wait=${wait}`);
      if (chat.gen !== gen) return out; // left behind: another view owns chat.seq now
      const fresh = out.messages.filter((m) => m.seq > chat.seq);
      const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
      for (const m of fresh) { log.append(bubble(m)); chat.seq = Math.max(chat.seq, m.seq); }
      if (fresh.length && (atBottom || fresh.some((m) => m.from === "operator"))) log.scrollTop = log.scrollHeight;
      put(asked, out.requests.length ? el("p", { class: "note" }, `Asked for on your behalf: ${out.requests.map((r) => `${r.platform} ${r.what} on ${r.resource} (${r.status})`).join("; ")}`) : null);
      const changed = !last || last.state !== out.thread.state || last.peer_alive !== out.thread.peer_alive;
      if (changed) {
        const focused = document.activeElement === text;
        drawHead(out.thread);
        if (focused || (!last && out.thread.state === "open")) text.focus();
      }
      if (fresh.length || changed) refreshSide();
      last = out.thread;
      return out;
    }

    try {
      await pull(0);
    } catch (err) {
      if (err.message !== "signed out") notice(err.message, true);
      return;
    }
    // Not awaited: it runs while the conversation is on screen.
    (async () => {
      while (chat.gen === gen && state.tab === "chat" && last && last.state !== "closed") {
        if (document.hidden) { await sleep(3000); continue; }
        try { await pull(25); } catch (err) {
          if (err.message === "signed out") return;
          await sleep(5000);
        }
      }
    })();
  }

  put(view, el("div", { class: "chat" }, side, pane));
  drawSide(threads);
  const resume = chat.open && threads.some((t) => t.id === chat.open) ? chat.open : null;
  if (resume) await openConversation(resume);
  else drawNew();
}

const VIEWS = { usage: usageView, chat: chatView, agents: agentsView, projects: projectsView, hosts: hostsView, conversations: conversationsView, decisions: decisionsView, commands: commandsView, rules: rulesView };

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
  state.user = session.user;
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
  // #chat/<conversation> opens that conversation.
  const [wanted, thread] = location.hash.slice(1).split("/");
  if (wanted === "chat" && thread) chat.open = thread;
  await show(VIEWS[wanted] ? wanted : "chat");
}

start().catch((err) => { if (err.message !== "signed out") notice(err.message, true); });
