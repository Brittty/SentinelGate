/* ==========================================================================
   SentinelGate — Futuristic particle engine
   Canvas 2D particle landscape with threat-cluster state machine
   ========================================================================== */
(function () {
  "use strict";

  const heroCanvas = document.getElementById("heroCanvas");
  const liveCanvas = document.getElementById("liveCanvas");

  const COLORS = {
    safe: "#00f3ff",
    warn: "#ffb454",
    threat: "#ff0033",
    blocked: "#666666",
    bg: "#050508",
  };

  function rand(min, max) {
    return Math.random() * (max - min) + min;
  }

  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  class Particle {
    constructor(canvas, opts = {}) {
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.x = rand(0, canvas.width);
      this.y = rand(0, canvas.height);
      this.vx = rand(-0.2, 0.2);
      this.vy = rand(-0.2, 0.2);
      this.size = rand(1, 3);
      this.depth = rand(0.4, 1);
      this.angle = rand(0, Math.PI * 2);
      this.state = "normal";
      this.stateTimer = 0;
      this.stateDuration = rand(60, 180);
      this.color = COLORS.safe;
      this.glow = 0;
      this.hillOffset = rand(0, Math.PI * 2);
      this.noiseOffset = rand(0, 1000);
    }

    resize() {
      this.x = Math.min(this.x, this.canvas.width);
      this.y = Math.min(this.y, this.canvas.height);
    }

    hillY(x) {
      const w = this.canvas.width;
      const h = this.canvas.height;
      const t = Date.now() * 0.001;
      const y =
        Math.sin(x * 0.005 + this.hillOffset) * 40 +
        Math.sin(x * 0.01 + t + this.hillOffset) * 20 +
        Math.sin(x * 0.02 - t + this.hillOffset) * 10;
      return h * 0.62 + y;
    }

    update(mouse, isThreatMode) {
      const w = this.canvas.width;
      const h = this.canvas.height;

      this.angle += 0.002 * this.depth;
      this.x += Math.cos(this.angle) * 0.4 * this.depth;
      this.y = this.hillY(this.x) + Math.sin(Date.now() * 0.002 + this.noiseOffset) * 6;

      if (this.x < -20) this.x = w + 20;
      if (this.x > w + 20) this.x = -20;
      if (this.y < -20) this.y = h + 20;
      if (this.y > h + 20) this.y = -20;

      if (mouse && mouse.active) {
        const dx = this.x - mouse.x;
        const dy = this.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const force = (120 - dist) / 120;
          this.x += (dx / dist) * force * 2;
          this.y += (dy / dist) * force * 2;
        }
      }

      if (isThreatMode) {
        this.stateTimer++;
        if (this.stateTimer > this.stateDuration) {
          this.stateTimer = 0;
          this.stateDuration = rand(90, 200);
          switch (this.state) {
            case "normal": this.state = "suspicious"; break;
            case "suspicious": this.state = "attack"; break;
            case "attack": this.state = "throttled"; break;
            case "throttled": this.state = "blocked"; break;
            default: this.state = "normal";
          }
        }
      } else {
        this.state = "normal";
      }

      switch (this.state) {
        case "normal":
          this.color = COLORS.safe;
          this.glow = 10;
          break;
        case "suspicious":
          this.color = COLORS.warn;
          this.glow = 14;
          break;
        case "attack":
          this.color = COLORS.threat;
          this.glow = 18;
          break;
        case "throttled":
        case "blocked":
          this.color = COLORS.blocked;
          this.glow = 6;
          break;
      }
    }

    draw() {
  // ------------------------------------------------------------------
  // Hero canvas — continuous particle landscape
  // ------------------------------------------------------------------
  class HeroParticles {
    constructor() {
      this.particles = [];
      this.mouse = { x: -1000, y: -1000, active: false };
      this.animationId = null;
      this.paused = false;
      this.visible = true;
      this.init();
    }

    init() {
      if (!heroCanvas) return;
      this.resize();
      const count = window.innerWidth < 760 ? 1800 : 6000;
      for (let i = 0; i < count; i++) {
        this.particles.push(new Particle(heroCanvas));
      }
      this.bindEvents();
      this.animate();
    }

    resize() {
      if (!heroCanvas) return;
      heroCanvas.width = heroCanvas.offsetWidth;
      heroCanvas.height = heroCanvas.offsetHeight;
      this.particles.forEach((p) => p.resize());
    }

    bindEvents() {
      window.addEventListener("resize", () => this.resize());
      window.addEventListener("mousemove", (e) => {
        this.mouse.x = e.clientX;
        this.mouse.y = e.clientY;
        this.mouse.active = true;
      });
      window.addEventListener("mouseleave", () => {
        this.mouse.active = false;
      });
    }

    setPaused(paused) {
      this.paused = paused;
    }

    setVisible(visible) {
      this.visible = visible;
    }

    animate() {
      if (!heroCanvas) return;
      if (!this.paused && this.visible) {
        const ctx = heroCanvas.getContext("2d");
        ctx.fillStyle = COLORS.bg;
        ctx.fillRect(0, 0, heroCanvas.width, heroCanvas.height);

        ctx.strokeStyle = "rgba(0, 243, 255, 0.03)";
        ctx.lineWidth = 1;
        for (let x = 0; x < heroCanvas.width; x += 60) {
          ctx.beginPath();
          ctx.moveTo(x, 0);
          ctx.lineTo(x, heroCanvas.height);
          ctx.stroke();
        }
        for (let y = 0; y < heroCanvas.height; y += 60) {
          ctx.beginPath();
          ctx.moveTo(0, y);
          ctx.lineTo(heroCanvas.width, y);
          ctx.stroke();
        }

        this.particles.forEach((p) => {
          p.update(this.mouse, false);
          p.draw();
  // ------------------------------------------------------------------
  // Live canvas — threat cluster simulation
  // ------------------------------------------------------------------
  class LiveParticles {
    constructor() {
      this.particles = [];
      this.mouse = { x: -1000, y: -1000, active: false };
      this.animationId = null;
      this.paused = false;
      this.visible = true;
      this.mlEnabled = true;
      this.detectionDelay = 40;
      this.logEl = document.getElementById("liveLog");
      this.metaEl = {
        glow: document.getElementById("metaGlow"),
        depth: document.getElementById("metaDepth"),
        fps: document.getElementById("metaFps"),
      };
      this.eventCount = 0;
      this.frameCount = 0;
      this.lastFpsTime = performance.now();
      this.init();
    }

    init() {
      if (!liveCanvas) return;
      this.resize();
      const count = window.innerWidth < 760 ? 600 : 1800;
      for (let i = 0; i < count; i++) {
        this.particles.push(new Particle(liveCanvas));
      }
      this.spawnCluster();
      this.bindEvents();
      this.animate();
    }

    resize() {
      if (!liveCanvas) return;
      liveCanvas.width = liveCanvas.offsetWidth;
      liveCanvas.height = liveCanvas.offsetHeight;
      this.particles.forEach((p) => p.resize());
    }

    bindEvents() {
      window.addEventListener("resize", () => this.resize());
      liveCanvas.addEventListener("mousemove", (e) => {
        const rect = liveCanvas.getBoundingClientRect();
        this.mouse.x = e.clientX - rect.left;
        this.mouse.y = e.clientY - rect.top;
        this.mouse.active = true;
      });
      liveCanvas.addEventListener("mouseleave", () => {
        this.mouse.active = false;
      });
    }

    setPaused(paused) {
      this.paused = paused;
    }

    setVisible(visible) {
      this.visible = visible;
    }

    setML(enabled) {
      this.mlEnabled = enabled;
      this.detectionDelay = enabled ? 40 : 120;
    }

    setTelemetry(cb) {
      this.telemetryCb = cb;
    }

    spawnCluster() {
      const cx = rand(liveCanvas.width * 0.2, liveCanvas.width * 0.8);
      const cy = rand(liveCanvas.height * 0.2, liveCanvas.height * 0.8);
      const radius = rand(60, 140);
      let converted = 0;
      this.particles.forEach((p) => {
        const dx = p.x - cx;
        const dy = p.y - cy;
        if (Math.sqrt(dx * dx + dy * dy) < radius && converted < 45) {
          p.state = "suspicious";
          p.stateTimer = 0;
          converted++;
        }
      });
      this.logEvent("Cluster detected — analyzing…", "warn");
      setTimeout(() => {
        this.particles.forEach((p) => {
          const dx = p.x - cx;
          const dy = p.y - cy;
          if (Math.sqrt(dx * dx + dy * dy) < radius && p.state !== "blocked") {
            p.state = "attack";
          }
        });
        this.logEvent("Attack pattern confirmed — risk 91", "threat");
      }, this.mlEnabled ? 1200 : 3500);
      setTimeout(() => {
        this.particles.forEach((p) => {
          const dx = p.x - cx;
          const dy = p.y - cy;
          if (Math.sqrt(dx * dx + dy * dy) < radius && p.state === "attack") {
            p.state = "throttled";
          }
        });
        this.logEvent("Gate engaged — traffic throttled", "warn");
      }, this.mlEnabled ? 2600 : 6000);
      setTimeout(() => {
        this.particles.forEach((p) => {
          const dx = p.x - cx;
          const dy = p.y - cy;
          if (Math.sqrt(dx * dx + dy * dy) < radius) {
            p.state = "blocked";
          }
        });
        this.logEvent("IP contained — 24h ban applied", "threat");
      }, this.mlEnabled ? 4000 : 9000);

      setTimeout(() => this.spawnCluster(), rand(3000, 8000));
    }

    logEvent(msg, type) {
      if (!this.logEl) return;
      const now = new Date();
      const time = now.toLocaleTimeString("en-US", { hour12: false });
      const entry = document.createElement("div");
      entry.className = `log-entry log-${type}`;
      entry.innerHTML = `<span class="log-time">${time}</span> <span class="log-msg">${msg}</span>`;
      this.logEl.prepend(entry);
      this.eventCount++;
      const blockedEl = document.getElementById("tickerBlocked");
      if (blockedEl) blockedEl.textContent = Math.floor(this.eventCount * 0.35);
      const reqEl = document.getElementById("tickerRequests");
      if (reqEl) reqEl.textContent = this.eventCount * 47;
      const latEl = document.getElementById("tickerLatency");
      if (latEl) latEl.textContent = Math.floor(rand(4, 12));
      while (this.logEl.children.length > 14) {
        this.logEl.removeChild(this.logEl.lastElementChild);
      }
    }

    updateTelemetry() {
      if (!this.metaEl) return;
      const now = performance.now();
      this.frameCount++;
      if (now - this.lastFpsTime >= 250) {
        const fps = Math.round((this.frameCount * 1000) / (now - this.lastFpsTime));
        this.lastFpsTime = now;
        this.frameCount = 0;
        if (this.metaEl.fps) this.metaEl.fps.textContent = fps;
      }
      if (this.metaEl.glow) this.metaEl.glow.textContent = "42%";
      if (this.metaEl.depth) this.metaEl.depth.textContent = "91%";
    }

    animate() {
      if (!liveCanvas) return;
      if (!this.paused && this.visible) {
        const ctx = liveCanvas.getContext("2d");
        ctx.fillStyle = COLORS.bg;
        ctx.fillRect(0, 0, liveCanvas.width, liveCanvas.height);
        this.updateTelemetry();
  // ------------------------------------------------------------------
  // Layer micro-canvases — small SVG-style animations
  // ------------------------------------------------------------------
  function initLayerCanvas(id, type) {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let frame = 0;

    function resize() {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    }
    window.addEventListener("resize", resize);
    resize();

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      frame++;

      const w = canvas.width;
      const h = canvas.height;
      const cx = w / 2;
      const cy = h / 2;
      const t = frame * 0.02;

      if (type === "rules") {
        ctx.strokeStyle = "rgba(0, 243, 255, 0.35)";
        ctx.lineWidth = 1;
        const scanY = (Math.sin(t) * 0.5 + 0.5) * h;
        ctx.beginPath();
        ctx.moveTo(0, scanY);
        ctx.lineTo(w, scanY);
        ctx.stroke();
        ctx.fillStyle = "rgba(0, 243, 255, 0.15)";
        ctx.fillRect(0, scanY - 2, w, 4);
        ctx.fillStyle = "rgba(255, 255, 255, 0.06)";
        for (let i = 0; i < 6; i++) {
          const bx = 20 + i * ((w - 40) / 5);
          const by = h * 0.3 + Math.sin(t + i) * 8;
          ctx.fillRect(bx, by, 24, 6);
        }
      } else if (type === "events") {
        const nodes = [
          { x: 40, y: 40 },
          { x: w - 40, y: 40 },
          { x: cx, y: h - 40 },
        ];
        ctx.strokeStyle = "rgba(0, 243, 255, 0.25)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(nodes[0].x, nodes[0].y);
        ctx.lineTo(nodes[2].x, nodes[2].y);
        ctx.moveTo(nodes[1].x, nodes[1].y);
        ctx.lineTo(nodes[2].x, nodes[2].y);
        ctx.stroke();
        nodes.forEach((n, i) => {
          const pulse = 1 + Math.sin(t + i) * 0.3;
          ctx.fillStyle = i === 2 ? "#ff0033" : "#00f3ff";
          ctx.shadowColor = ctx.fillStyle;
          ctx.shadowBlur = 12 * pulse;
          ctx.beginPath();
          ctx.arc(n.x, n.y, 4 * pulse, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        });
      } else if (type === "bucket") {
        const bucketX = cx;
        const bucketY = h * 0.55;
        const bucketW = 50;
        const bucketH = 70;
        ctx.strokeStyle = "rgba(0, 243, 255, 0.35)";
        ctx.lineWidth = 2;
        ctx.strokeRect(bucketX - bucketW / 2, bucketY - bucketH, bucketW, bucketH);
        const tokenCount = 20;
        const level = (Math.sin(t * 0.5) * 0.5 + 0.5) * tokenCount;
        for (let i = 0; i < tokenCount; i++) {
          if (i < level) {
            const tx = bucketX - bucketW / 2 + 10 + (i % 4) * 8;
            const ty = bucketY - 10 - Math.floor(i / 4) * 9;
            ctx.fillStyle = "#00f3ff";
            ctx.shadowColor = "#00f3ff";
            ctx.shadowBlur = 8;
            ctx.fillRect(tx, ty, 4, 4);
            ctx.shadowBlur = 0;
          }
        }
      }
      requestAnimationFrame(draw);
    }
    draw();
  }

  // ------------------------------------------------------------------
  // Export
  // ------------------------------------------------------------------
  window.SentinelParticles = {
    HeroParticles,
    LiveParticles,
    initLayerCanvas,
  };
})();
        this.particles.forEach((p) => {
          p.update(this.mouse, true);
          p.draw();
        });
      }
      this.animationId = requestAnimationFrame(() => this.animate());
    }

    destroy() {
      if (this.animationId) cancelAnimationFrame(this.animationId);
    }
  }
        });
      }
      this.animationId = requestAnimationFrame(() => this.animate());
    }

    destroy() {
      if (this.animationId) cancelAnimationFrame(this.animationId);
    }
  }
      const ctx = this.ctx;
      const alpha = 0.5 + 0.5 * this.depth;
      const size = this.size * this.depth;
      ctx.save();
      ctx.globalAlpha = alpha;
      ctx.fillStyle = this.color;
      ctx.shadowColor = this.color;
      ctx.shadowBlur = this.glow;
      ctx.beginPath();
      ctx.arc(this.x, this.y, size, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
  }