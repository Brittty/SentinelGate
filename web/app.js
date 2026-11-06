/* ==========================================================================
   SentinelGate — Landing page interactivity
   Futuristic design: nav state, particle control, chain tamper demo,
   risk gauge animation, copy-to-clipboard, reveal-on-scroll
   ========================================================================== */
(function () {
  "use strict";

  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)");

  const reducedMotionStyles = document.createElement("style");
  reducedMotionStyles.textContent = `
    section { transition: none !important; opacity: 1 !important; transform: none !important; }
    .hero::before { animation: none !important; }
    .chain-block::before, .chain-link::before, .step-number::before, .gauge-wrapper::before, .ru-band::before { opacity: 0 !important; }
    .ticker-value.pulse { animation: none !important; }
  `;
  reducedMotionStyles.media = "(prefers-reduced-motion: reduce)";
  document.head.appendChild(reducedMotionStyles);

  // ------------------------------------------------------------------
  // Navigation scroll state + mobile toggle
  // ------------------------------------------------------------------
  const nav = document.getElementById("nav");
  const navToggle = document.querySelector(".nav-toggle");
  const mobileMenu = document.getElementById("mobile-menu");
  let lastScroll = 0;

  function updateNav() {
    const y = window.scrollY;
    if (y > 40) {
      nav.style.background = "rgba(5, 5, 8, 0.9)";
      nav.style.borderBottom = "1px solid rgba(238, 242, 255, 0.3)";
    } else {
      nav.style.background = "rgba(5, 5, 8, 0.6)";
      nav.style.borderBottom = "1px solid rgba(238, 242, 255, 0.12)";
    }
    lastScroll = y;
  }

  if (navToggle) {
    navToggle.addEventListener("click", () => {
      const expanded = navToggle.getAttribute("aria-expanded") === "true";
      navToggle.setAttribute("aria-expanded", !expanded);
      navToggle.classList.toggle("open");
      if (mobileMenu) {
        mobileMenu.hidden = expanded;
      }
    });
  }

  window.addEventListener("scroll", updateNav, { passive: true });
  updateNav();

  // ------------------------------------------------------------------
  // Scroll reveal + class-based entrance
  // ------------------------------------------------------------------
  const sections = Array.from(document.querySelectorAll("section"));
  const ioOptions = { threshold: 0.15, rootMargin: "0px 0px -40px 0px" };
  const sectionObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting && !entry.target.classList.contains("revealed")) {
        entry.target.classList.add("revealed");
      }
    });
  }, ioOptions);
  sections.forEach((sec) => sectionObserver.observe(sec));

  // ------------------------------------------------------------------
  // Particle engines
  // ------------------------------------------------------------------
  let heroParticles, liveParticles;

  function initParticles() {
    if (window.SentinelParticles) {
      heroParticles = new window.SentinelParticles.HeroParticles();
      liveParticles = new window.SentinelParticles.LiveParticles();

      window.SentinelParticles.initLayerCanvas("layerCanvas1", "rules");
      window.SentinelParticles.initLayerCanvas("layerCanvas2", "events");
      window.SentinelParticles.initLayerCanvas("layerCanvas3", "bucket");
    }
  }

  const visibilityHandler = () => {
    const hidden = document.hidden;
    if (heroParticles) heroParticles.setPaused(hidden);
    if (liveParticles) liveParticles.setPaused(hidden);
  };
  document.addEventListener("visibilitychange", visibilityHandler);


  // ------------------------------------------------------------------
  // Live field controls
  // ------------------------------------------------------------------
  const btnPause = document.getElementById("btnPause");
  const btnSimulate = document.getElementById("btnSimulate");
  const btnML = document.getElementById("btnML");

  let paused = false;
  if (btnPause) {
    btnPause.addEventListener("click", () => {
      paused = !paused;
      btnPause.setAttribute("aria-pressed", paused);
      btnPause.textContent = paused ? "Resume" : "Pause";
      if (liveParticles) liveParticles.setPaused(paused);
    });
  }
  if (btnSimulate && liveParticles) {
    btnSimulate.addEventListener("click", () => {
      btnSimulate.textContent = "Simulating…";
      btnSimulate.disabled = true;
      liveParticles.spawnCluster();
      setTimeout(() => {
        btnSimulate.disabled = false;
        btnSimulate.textContent = "Simulate attack";
        if (liveParticles && liveParticles.addLog) {
          liveParticles.addLog("attack", "Simulated multi-stage threat cluster spawned");
        }
      }, 1200);
    });
  }

  // ------------------------------------------------------------------
  // Hash-chain tamper demo
  // ------------------------------------------------------------------
  const blocks = ["block0", "block1", "block2"];
  const hashes = ["hash0", "hash1", "hash2"];
  let tampered = false;

  function generateHash(seed) {
    let h = 0;
    const str = String(seed);
    for (let i = 0; i < str.length; i++) {
      h = (h << 5) - h + str.charCodeAt(i);
      h |= 0;
    }
    return ("000000" + (h & 0xffffff).toString(16)).slice(-6);
  }

  function renderChain() {
    blocks.forEach((id, i) => {
      const el = document.getElementById(id);
      const hashEl = document.getElementById(hashes[i]);
      if (!el || !hashEl) return;
      const prev = i === 0 ? "genesis" : hashes[i - 1];
      const content = tampered && i === 1 ? "tampered-data" : `block-${i}-data`;
      const hash = generateHash(prev + content);
      hashEl.textContent = hash.slice(0, 4) + "…";
      el.classList.remove("chain-tampered");
      if (tampered && i >= 1) {
        el.classList.add("chain-tampered");
      }
    });
    const status = document.getElementById("chainStatus");
    const statusText = status ? status.querySelector("span") : null;
    if (statusText) {
      statusText.textContent = tampered ? "Tampered" : "Verified";
      statusText.className = tampered ? "status-bad" : "status-ok";
    }
  }

  const btnTamper = document.getElementById("btnTamper");
  const btnVerify = document.getElementById("btnVerify");

  if (btnTamper) {
    btnTamper.addEventListener("click", () => {
      tampered = true;
      renderChain();
      btnTamper.disabled = true;
      btnVerify.disabled = false;
    });
  }
  if (btnVerify) {
    btnVerify.addEventListener("click", () => {
      tampered = false;
      renderChain();
      btnTamper.disabled = false;
      btnVerify.disabled = true;
    });
  }
  renderChain();

  // ------------------------------------------------------------------
  // Risk gauge animation
  // ------------------------------------------------------------------
  const gaugeArc = document.getElementById("gaugeArc");
  const gaugeValue = document.getElementById("gaugeValue");
  const gaugeLabel = document.getElementById("gaugeLabel");
  const exampleIPs = [
    "203.0.113.7",
    "45.9.148.11",
    "185.220.101.4",
    "127.0.0.1",
    "10.0.0.55",
  ];
  let ipIndex = 0;

  function arcPath(value) {
    const startX = 30;
    const startY = 90;
    const rx = 60;
    const ry = 60;
    const largeArc = value > 50 ? 1 : 0;
    const endAngle = (180 * value) / 100;
    const endRad = (endAngle * Math.PI) / 180;
    const endX = startX + rx * (1 + Math.cos(endRad));
    const endY = startY - ry * Math.sin(endRad);
    return `M ${startX},${startY} A ${rx},${ry} 0 ${largeArc} 1 ${endX},${endY}`;
  }

  function animateGauge() {
    if (!gaugeArc || !gaugeValue) return;
    let current = 0;
    const target = Math.floor(rand(20, 95));
    const ip = exampleIPs[ipIndex];
    ipIndex = (ipIndex + 1) % exampleIPs.length;

    if (gaugeLabel) gaugeLabel.textContent = `Analyzing ${ip}…`;

    const frames = 60;
    let frame = 0;
    function step() {
      frame++;
      const ease = easeOutCubic(frame / frames);
      current = ease * target;
      gaugeArc.setAttribute("d", arcPath(current));
      gaugeValue.textContent = Math.round(current);
      if (frame < frames) {
        requestAnimationFrame(step);
      }
    }
    step();

    setTimeout(animateGauge, 4500);
  }
  animateGauge();

  // ------------------------------------------------------------------
  // Copy terminal
  // ------------------------------------------------------------------
  const btnCopy = document.getElementById("btnCopyTerminal");
  if (btnCopy) {
    btnCopy.addEventListener("click", async () => {
      const lines = [];
      document.querySelectorAll(".terminal-body .cmd-line").forEach((line) => {
        const prompt = line.querySelector(".prompt")?.textContent || "";
        const cmd = line.querySelector(".cmd")?.textContent || "";
        lines.push(prompt + " " + cmd);
      });
      const text = lines.join("\n");
      try {
        await navigator.clipboard.writeText(text);
        btnCopy.classList.add("copied");
        btnCopy.textContent = "Copied!";
        setTimeout(() => {
          btnCopy.classList.remove("copied");
          btnCopy.textContent = "Copy all";
        }, 1500);
      } catch (err) {
        const range = document.createRange();
        const terminal = document.querySelector(".terminal-body");
        range.selectNodeContents(terminal);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
      }
    });
  }

  // ------------------------------------------------------------------
  // Live metrics ticker: simulated counters with pulse on change
  // ------------------------------------------------------------------
  const tickerReq = document.getElementById("tickerRequests");
  const tickerBlocked = document.getElementById("tickerBlocked");
  const tickerLatency = document.getElementById("tickerLatency");
  let reqCount = 0;
  let blockedCount = 0;
  let latency = 42;

  function pad(n, w = 2) {
    return String(n).padStart(w, "0");
  }

  function formatTime() {
    const now = new Date();
    return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  }

  function tickTicker() {
    if (!tickerReq || !tickerBlocked || !tickerLatency) return;
    reqCount += Math.floor(rand(1, 6));
    if (Math.random() < 0.18) {
      blockedCount += 1;
    }
    latency = Math.max(8, Math.round(latency + rand(-6, 7)));
    tickerReq.textContent = reqCount.toLocaleString();
    tickerBlocked.textContent = blockedCount.toLocaleString();
    tickerLatency.textContent = latency;
    tickerReq.classList.remove("pulse");
    void tickerReq.offsetWidth;
    tickerReq.classList.add("pulse");
  }

  setInterval(tickTicker, 1400);
  setTimeout(tickTicker, 600);

  // ------------------------------------------------------------------
  // Start
  // ------------------------------------------------------------------
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initParticles);
  } else {
    initParticles();
  }

  window.easeOutCubic = function (t) {
    return 1 - Math.pow(1 - t, 3);
  };

  // ------------------------------------------------------------------
  // Live particle telemetry hook (optional enhancement panel)
  // ------------------------------------------------------------------
  if (window.SentinelParticles && window.SentinelParticles.LiveParticles) {
    try {
      const live = window.SentinelParticles.LiveParticles;
      if (typeof live.setTelemetry === "function") {
        live.setTelemetry(() => {});
        if (typeof live.addLog === "function") {
          live.addLog("safe", "Telemetry bridge attached to live canvas");
        }
      }
    } catch (e) {
      /* telemetry hook is optional */
    }
  }
})();
