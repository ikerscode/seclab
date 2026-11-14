(function () {
  const grid = document.getElementById("cards");
  const cards = new Map();
  let failing = false;

  function statusTag(up) {
    return up ? '<span class="tag ok">up</span>' : '<span class="tag crit">down</span>';
  }

  function buildCard(p) {
    const el = document.createElement("section");
    el.className = "panel span-4 card";
    el.innerHTML = `
      <h2>${hud.esc(p.title)}</h2>
      <p class="muted desc">${hud.esc(p.description)}</p>
      <div class="row meta"><span class="status"></span><span class="port"></span><span class="ver"></span></div>
      <div class="row actions">
        <a class="btn primary open" target="_blank" rel="noopener">Open</a>
        <button class="btn start" type="button">Start</button>
        <button class="btn danger stop" type="button">Stop</button>
      </div>`;
    el.querySelector(".start").addEventListener("click", () => act(p.name, "start"));
    el.querySelector(".stop").addEventListener("click", () => act(p.name, "stop"));
    return el;
  }

  function update(p) {
    let el = cards.get(p.name);
    if (!el) {
      el = buildCard(p);
      cards.set(p.name, el);
      grid.appendChild(el);
    }
    el.querySelector(".status").innerHTML = statusTag(p.up);
    el.querySelector(".port").textContent = `port ${p.port}`;
    el.querySelector(".ver").textContent = p.version ? `v${p.version}` : "";
    const open = el.querySelector(".open");
    open.href = p.url;
    open.textContent = "Open";
    open.classList.toggle("disabled", !p.up);
    open.setAttribute("aria-disabled", String(!p.up));
  }

  async function refresh() {
    try {
      const list = await hud.api("/api/status");
      if (cards.size === 0) grid.innerHTML = "";
      list.forEach(update);
      failing = false;
    } catch (err) {
      if (!failing) hud.toast("Status check failed: " + err.message);
      failing = true;
    }
  }

  async function act(name, action) {
    const card = cards.get(name);
    const buttons = card.querySelectorAll("button");
    buttons.forEach((b) => (b.disabled = true));
    try {
      const res = await hud.api(`/api/${action}/${encodeURIComponent(name)}`, { method: "POST" });
      hud.toast(`${name}: ${res.output || action + " done"}`, 6000);
    } catch (err) {
      hud.toast(`${name} ${action} failed: ${err.message}`, 8000);
    } finally {
      buttons.forEach((b) => (b.disabled = false));
      refresh();
    }
  }

  // ---------------------------------------------------------------- pipeline panel
  const linkTag = (s) => String(s).startsWith("up") ? '<span class="tag ok">up</span>' : `<span class="tag crit">${hud.esc(s)}</span>`;

  async function refreshPipeline() {
    let view;
    try {
      view = await hud.api("/api/pipeline");
    } catch (err) {
      return;
    }
    const last = view.last_run;
    document.getElementById("pl-last").textContent = last && last.finished
      ? `last pass ${hud.fmtTime(last.finished)}, ${view.outbox} waiting for ai-ids, ${view.totals.forwarded || 0} alerts forwarded in total`
      : "not run yet";
    hud.renderTable("#pl-links", view.links, [
      { key: "link", label: "Link" }, { key: "status", label: "Status", render: linkTag },
      { key: "sent", label: "Last pass" }, { key: "note", label: "Note" }, { key: "carries", label: "Carries" },
    ]);
    hud.renderTable("#pl-incidents", view.incidents, [
      { key: "id", label: "Incident" }, { key: "severity", label: "Severity", render: (v) => hud.severityTag(v) },
      { key: "score", label: "Score" }, { key: "alerts", label: "Alerts" }, { key: "pipeline_alerts", label: "From pipeline" },
      { key: "systems", label: "Systems" }, { key: "stages", label: "Stages" }, { key: "title", label: "Title" },
    ], { empty: "No incidents with pipeline alerts yet. Start the labs and run the pipeline." });
    hud.renderTable("#pl-shared", view.shared_indicators, [
      { key: "indicator", label: "Indicator" }, { key: "labs", label: "Seen by" }, { key: "intel", label: "threat-intel" },
    ], { empty: "None yet." });
  }

  async function runPipeline() {
    const btn = document.getElementById("pl-run");
    btn.disabled = true;
    hud.toast("Pipeline pass running...");
    try {
      const res = await hud.api("/api/pipeline/run", { method: "POST" });
      hud.toast(`Pipeline: ${res.forward.accepted} alerts accepted by ai-ids, ${res.incidents} incidents`, 6000);
    } catch (err) {
      hud.toast("Pipeline failed: " + err.message, 8000);
    } finally {
      btn.disabled = false;
      refreshPipeline();
    }
  }

  document.getElementById("pl-run").addEventListener("click", runPipeline);
  document.getElementById("refresh").addEventListener("click", () => { refresh(); refreshPipeline(); });
  hud.every(5000, refresh);
  hud.every(15000, refreshPipeline);
})();
