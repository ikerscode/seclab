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

  document.getElementById("refresh").addEventListener("click", refresh);
  hud.every(5000, refresh);
})();
