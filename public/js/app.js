/* ── Threat-Informed Defense Planner — frontend ─────────────────────── */

const API = "";   // same origin; set to http://localhost:5000 for local dev

let allGroups      = [];
let selectedGroup  = null;
let dettectYaml    = "";
let lastResults    = null;
let activeFilter   = "all";

// ── Initialise ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  await loadGroups();
  wireCollapse();
  wireUpload();
  wireFilters();
  wireSampleBtn();
  wireAnalyze();
  wireExport();
});

// ── Collapse panel ──────────────────────────────────────────────────────
function wireCollapse() {
  const toggle = document.getElementById("step-group-toggle");
  const btn    = document.getElementById("btn-collapse-group");
  const panel  = document.getElementById("group-panel");

  function setCollapsed(collapsed) {
    panel.classList.toggle("collapsed", collapsed);
    btn.classList.toggle("collapsed", collapsed);
    btn.setAttribute("aria-expanded", String(!collapsed));
    btn.textContent = collapsed ? "▲" : "▲";
  }

  toggle.addEventListener("click", () => {
    setCollapsed(!panel.classList.contains("collapsed"));
  });
}

function collapseGroupPanel() {
  document.getElementById("group-panel").classList.add("collapsed");
  document.getElementById("btn-collapse-group").classList.add("collapsed");
  document.getElementById("btn-collapse-group").setAttribute("aria-expanded", "false");
}

// ── Load groups ─────────────────────────────────────────────────────────
async function loadGroups() {
  const grid = document.getElementById("group-grid");
  try {
    const res = await fetch(`${API}/api/groups`);
    allGroups  = await res.json();
    renderGroupGrid(allGroups);
  } catch (e) {
    grid.innerHTML = `<p style="color:var(--critical)">Failed to load groups: ${e.message}</p>`;
  }
}

function renderGroupGrid(groups) {
  const grid = document.getElementById("group-grid");
  if (!groups.length) {
    grid.innerHTML = '<p style="color:var(--text-muted)">No groups match.</p>';
    return;
  }
  grid.innerHTML = groups.map(g => `
    <div class="group-card ${selectedGroup?.id === g.id ? "selected" : ""}"
         data-id="${g.id}" tabindex="0" role="button" aria-pressed="${selectedGroup?.id === g.id}">
      <div class="group-id">${g.id}</div>
      <div class="group-name">${g.name}</div>
      <div class="group-aliases">${g.aliases.slice(0, 4).join(" · ")}</div>
      <div class="group-meta">
        <span class="group-tech-count">⚔ ${g.tech_count} techniques</span>
      </div>
    </div>
  `).join("");

  grid.querySelectorAll(".group-card").forEach(card => {
    card.addEventListener("click",   () => selectGroup(card.dataset.id));
    card.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") selectGroup(card.dataset.id); });
  });
}

function selectGroup(id) {
  selectedGroup = allGroups.find(g => g.id === id) || null;
  renderGroupGrid(
    document.getElementById("group-search").value
      ? allGroups.filter(g => matchGroup(g, document.getElementById("group-search").value))
      : allGroups
  );
  updateAnalyzeBtn();

  // Update badge and collapse panel
  const badge = document.getElementById("selected-group-badge");
  if (selectedGroup) {
    badge.textContent = selectedGroup.name;
    badge.classList.remove("hidden");
    collapseGroupPanel();
  } else {
    badge.classList.add("hidden");
  }
}

function matchGroup(g, q) {
  const lq = q.toLowerCase();
  return g.name.toLowerCase().includes(lq)
    || g.id.toLowerCase().includes(lq)
    || g.aliases.some(a => a.toLowerCase().includes(lq));
}

document.getElementById("group-search").addEventListener("input", e => {
  const q = e.target.value.trim();
  renderGroupGrid(q ? allGroups.filter(g => matchGroup(g, q)) : allGroups);
});

// ── Upload / sample ─────────────────────────────────────────────────────
function wireUpload() {
  const area   = document.getElementById("upload-area");
  const input  = document.getElementById("yaml-file");
  const status = document.getElementById("yaml-status");

  input.addEventListener("change", () => handleFile(input.files[0]));

  area.addEventListener("dragover",  e => { e.preventDefault(); area.classList.add("drag-over"); });
  area.addEventListener("dragleave", () => area.classList.remove("drag-over"));
  area.addEventListener("drop",      e => {
    e.preventDefault();
    area.classList.remove("drag-over");
    handleFile(e.dataTransfer.files[0]);
  });
}

function handleFile(file) {
  if (!file) return;
  const status = document.getElementById("yaml-status");
  const label  = document.getElementById("upload-text");
  const reader = new FileReader();
  reader.onload = e => {
    dettectYaml = e.target.result;
    label.textContent = `✓ ${file.name}`;
    status.textContent = "YAML loaded";
    status.className   = "yaml-status";
  };
  reader.onerror = () => {
    status.textContent = "Failed to read file";
    status.className   = "yaml-status error";
  };
  reader.readAsText(file);
}

function wireSampleBtn() {
  document.getElementById("btn-sample").addEventListener("click", async () => {
    const status = document.getElementById("yaml-status");
    const label  = document.getElementById("upload-text");
    try {
      const res = await fetch("/sample/dettect_sample.yaml");
      dettectYaml = await res.text();
      label.textContent = "✓ dettect_sample.yaml";
      status.textContent = "Sample YAML loaded";
      status.className   = "yaml-status";
    } catch (e) {
      status.textContent = "Could not load sample";
      status.className   = "yaml-status error";
    }
  });
}

// ── Analyse ─────────────────────────────────────────────────────────────
function updateAnalyzeBtn() {
  const btn  = document.getElementById("btn-analyze");
  const hint = document.getElementById("analyze-hint");
  if (selectedGroup) {
    btn.disabled     = false;
    hint.textContent = `Selected: ${selectedGroup.name} (${selectedGroup.id})`;
  } else {
    btn.disabled     = true;
    hint.textContent = "Select a threat actor to continue";
  }
}

function wireAnalyze() {
  document.getElementById("btn-analyze").addEventListener("click", runAnalysis);
}

async function runAnalysis() {
  if (!selectedGroup) return;

  showLoading(true);
  document.getElementById("results-section").classList.add("hidden");

  try {
    const res = await fetch(`${API}/api/analyze`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        group_id:    selectedGroup.id,
        dettect_yaml: dettectYaml,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || res.statusText);
    }

    lastResults = await res.json();
    renderResults(lastResults);
    document.getElementById("results-section").classList.remove("hidden");
    document.getElementById("results-section").scrollIntoView({ behavior: "smooth", block: "start" });

  } catch (e) {
    alert(`Analysis failed: ${e.message}`);
  } finally {
    showLoading(false);
  }
}

// ── Render results ──────────────────────────────────────────────────────
function renderResults(data) {
  const { group, results, coverage } = data;

  // Header
  document.getElementById("results-group-name").textContent = `${group.name} (${group.id})`;
  document.getElementById("results-group-desc").textContent = group.description;
  document.getElementById("results-group-url").href         = group.url;

  // Summary
  document.getElementById("s-critical").textContent = coverage.critical_gaps;
  document.getElementById("s-high").textContent     = coverage.high_gaps;
  document.getElementById("s-covered").textContent  = coverage.techniques_covered;
  document.getElementById("s-total").textContent    = coverage.techniques_total;

  renderTable(results);
}

function renderTable(results) {
  const q     = (document.getElementById("results-search")?.value || "").toLowerCase();
  const tbody = document.getElementById("results-body");

  const filtered = results.filter(r => {
    if (activeFilter !== "all" && r.priority !== activeFilter) return false;
    if (q && !r.technique_id.toLowerCase().includes(q) && !r.technique_name.toLowerCase().includes(q)) return false;
    return true;
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:32px">No techniques match current filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(r => buildRow(r)).join("");

  // Wire expand buttons
  tbody.querySelectorAll(".expand-btn").forEach(btn => {
    btn.addEventListener("click", () => toggleDetail(btn.dataset.tid));
  });
}

function buildRow(r) {
  const tactics = r.tactics.map(t => `<span class="tactic-pill">${t}</span>`).join("");
  const visHtml  = scorePips(r.visibility_score, 5);
  const detHtml  = scorePips(r.detection_score,  5);
  const d3fClass = r.d3fend_count > 0 ? "has-controls" : "no-controls";
  const d3fLabel = r.d3fend_count > 0 ? `✓ ${r.d3fend_count}` : "—";

  return `
    <tr data-tid="${r.technique_id}">
      <td>
        <div class="tech-id"><a href="${r.technique_url}" target="_blank">${r.technique_id}</a></div>
        <div class="tech-name">${r.technique_name}</div>
      </td>
      <td>${tactics}</td>
      <td>${visHtml}</td>
      <td>${detHtml}</td>
      <td><span class="d3fend-count ${d3fClass}">${d3fLabel}</span></td>
      <td><span class="priority-badge ${r.priority}">${r.priority}</span></td>
      <td><button class="expand-btn" data-tid="${r.technique_id}" title="Show D3FEND controls">▼</button></td>
    </tr>
    <tr class="detail-row hidden" id="detail-${r.technique_id}">
      <td colspan="7">${buildDetail(r)}</td>
    </tr>
  `;
}

function scorePips(score, max) {
  const zeroClass = score === 0 ? " zero" : "";
  const pips = Array.from({ length: max }, (_, i) =>
    `<div class="score-pip ${i < score ? `filled${zeroClass}` : ""}"></div>`
  ).join("");
  return `<div class="score-bar"><div class="score-pip-row">${pips}</div><span class="score-num">${score}/${max}</span></div>`;
}

function buildDetail(r) {
  let d3html = "";
  if (r.d3fend && r.d3fend.length) {
    d3html = `<div class="d3fend-list">${r.d3fend.map(c => `
      <div class="d3fend-item">
        <a href="${c.url}" target="_blank">${c.technique}</a>
        <div class="d3fend-tactic">${c.tactic || "Countermeasure"} · ${c.id}</div>
      </div>`).join("")}</div>`;
  } else {
    d3html = `<p class="no-d3fend">No D3FEND countermeasures mapped for this technique yet.</p>`;
  }

  return `
    <div class="detail-inner">
      <h4>D3FEND Countermeasures</h4>
      ${d3html}
      <div class="detail-links">
        <a href="${r.technique_url}" target="_blank" class="btn btn-ghost">View on ATT&CK ↗</a>
        <a href="https://d3fend.mitre.org/attack-mapping/" target="_blank" class="btn btn-ghost">D3FEND Mapping ↗</a>
      </div>
    </div>`;
}

function toggleDetail(tid) {
  const row = document.getElementById(`detail-${tid}`);
  const btn = document.querySelector(`.expand-btn[data-tid="${tid}"]`);
  if (!row) return;
  const isHidden = row.classList.toggle("hidden");
  if (btn) btn.textContent = isHidden ? "▼" : "▲";
}

// ── Filters ─────────────────────────────────────────────────────────────
function wireFilters() {
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeFilter = btn.dataset.filter;
      if (lastResults) renderTable(lastResults.results);
    });
  });

  document.getElementById("results-search").addEventListener("input", () => {
    if (lastResults) renderTable(lastResults.results);
  });
}

// ── Export CSV ──────────────────────────────────────────────────────────
function wireExport() {
  document.getElementById("btn-export").addEventListener("click", () => {
    if (!lastResults) return;
    const rows = [
      ["Technique ID","Technique Name","Tactics","Visibility (0-5)","Detection (0-5)","D3FEND Controls","Priority"],
      ...lastResults.results.map(r => [
        r.technique_id,
        r.technique_name,
        r.tactics.join("; "),
        r.visibility_score,
        r.detection_score,
        r.d3fend.map(c => c.technique).join("; "),
        r.priority,
      ]),
    ];
    const csv  = rows.map(r => r.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), {
      href:     url,
      download: `${lastResults.group.id}_gap_analysis.csv`,
    });
    a.click();
    URL.revokeObjectURL(url);
  });
}

// ── Loading overlay ──────────────────────────────────────────────────────
function showLoading(show) {
  document.getElementById("loading-overlay").classList.toggle("hidden", !show);
}
