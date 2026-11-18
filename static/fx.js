// seclab portal effects: boot splash + Matrix rain.
// Deliberately light on this laptop: capped frame rate, device pixel ratio 1,
// pauses when the tab is hidden, and disables itself under prefers-reduced-motion.
(function () {
  "use strict";
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---------------------------------------------------------------- boot splash
  const boot = document.getElementById("boot");
  if (boot) {
    const lines = [
      "seclab bootloader v3.1  (c) ikerscode",
      "",
      "[  OK  ] mounting /dev/labnet ... online",
      "[  OK  ] malware-lab     :8101  armed",
      "[  OK  ] threat-intel    :8102  feeds linked",
      "[  OK  ] honeypot-net    :8103  sensors live",
      "[  OK  ] ics-sim         :8104  plant nominal",
      "[  OK  ] ai-ids          :8105  model loaded",
      "",
      "establishing secure channel ................ done",
      "decrypting operator console ................ done",
      "",
      "> ACCESS GRANTED",
    ];
    const pre = document.createElement("div");
    boot.appendChild(pre);
    let i = 0;
    const finish = () => { boot.classList.add("done"); setTimeout(() => boot.remove(), 600); };
    boot.addEventListener("click", finish);
    if (reduce) {
      pre.textContent = lines.join("\n");
      setTimeout(finish, 600);
    } else {
      const tick = () => {
        if (!boot.isConnected) return;
        pre.textContent = lines.slice(0, ++i).join("\n") + " █";
        if (i < lines.length) setTimeout(tick, 90);
        else setTimeout(finish, 650);
      };
      tick();
    }
  }

  // ---------------------------------------------------------------- matrix rain
  const canvas = document.getElementById("matrix");
  if (!canvas || reduce) return;
  const ctx = canvas.getContext("2d", { alpha: true });
  const GLYPHS = "01<>[]{}#$%&*+=/\\|!?ｱｶｻﾀﾅﾊﾏﾔﾗ日ﾈﾁ".split("");
  const FONT = 14, FPS = 12;
  let cols = 0, drops = [], raf = 0, timer = 0, running = false;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.ceil(canvas.width / FONT);
    drops = new Array(cols).fill(0).map(() => Math.floor(Math.random() * -40));
    ctx.font = FONT + "px monospace";
  }

  function frame() {
    ctx.fillStyle = "rgba(0, 6, 0, 0.09)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#00ff41";
    for (let i = 0; i < cols; i++) {
      const ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
      const y = drops[i] * FONT;
      ctx.fillText(ch, i * FONT, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  function loop() {
    if (!running) return;
    frame();
    timer = setTimeout(() => { raf = requestAnimationFrame(loop); }, 1000 / FPS);
  }
  function start() { if (!running) { running = true; loop(); } }
  function stop() { running = false; clearTimeout(timer); cancelAnimationFrame(raf); }

  // Persisted on/off toggle (header button added in index.html).
  let on = localStorage.getItem("seclab.rain") !== "off";
  const btn = document.getElementById("fx-rain");
  function apply() {
    canvas.style.display = on ? "" : "none";
    if (btn) btn.textContent = on ? "RAIN ON" : "RAIN OFF";
    if (on && !document.hidden) start(); else stop();
  }
  if (btn) btn.addEventListener("click", () => {
    on = !on; localStorage.setItem("seclab.rain", on ? "on" : "off"); apply();
  });

  window.addEventListener("resize", resize);
  document.addEventListener("visibilitychange", () => { if (on) (document.hidden ? stop() : start()); });
  resize();
  apply();
})();
