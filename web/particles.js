/* SentinelGate landing page — background particle animation.
 *
 * Renders a lightweight starfield of drifting nodes on #particles.
 * Nodes slowly wander; links are drawn between nearby nodes to suggest
 * a monitored network. Disabled entirely under prefers-reduced-motion
 * (the CSS also hides the canvas) and when canvas is unavailable.
 */
(function () {
    'use strict';

    var canvas = document.getElementById('particles');
    if (!canvas) {
        return;
    }

    var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    var ctx = canvas.getContext('2d');
    if (!ctx || reducedMotion.matches) {
        return;
    }

    var particles = [];
    var LINK_DISTANCE = 110;
    var MAX_PARTICLES = 70;
    var raf = null;

    function sizeCanvas() {
        var rect = canvas.parentElement.getBoundingClientRect();
        var dpr = window.devicePixelRatio || 1;
        canvas.width = Math.max(1, Math.floor(rect.width * dpr));
        canvas.height = Math.max(1, Math.floor(rect.height * dpr));
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function createParticles() {
        var rect = canvas.parentElement.getBoundingClientRect();
        var count = Math.min(MAX_PARTICLES, Math.round(rect.width / 18));
        particles = [];
        for (var i = 0; i < count; i++) {
            particles.push({
                x: Math.random() * rect.width,
                y: Math.random() * rect.height,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                r: 1 + Math.random() * 1.6,
            });
        }
    }

    function draw() {
        var rect = canvas.parentElement.getBoundingClientRect();
        ctx.clearRect(0, 0, rect.width, rect.height);

        var i, j, p, q, dx, dy, dist;
        for (i = 0; i < particles.length; i++) {
            p = particles[i];
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(238, 242, 255, 0.55)';
            ctx.fill();
        }

        ctx.lineWidth = 1;
        for (i = 0; i < particles.length; i++) {
            for (j = i + 1; j < particles.length; j++) {
                p = particles[i];
                q = particles[j];
                dx = p.x - q.x;
                dy = p.y - q.y;
                dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < LINK_DISTANCE) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(q.x, q.y);
                    ctx.strokeStyle = 'rgba(91, 79, 208, ' + (0.35 * (1 - dist / LINK_DISTANCE)).toFixed(3) + ')';
                    ctx.stroke();
                }
            }
        }
    }

    function step() {
        var rect = canvas.parentElement.getBoundingClientRect();
        for (var i = 0; i < particles.length; i++) {
            var p = particles[i];
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < -10) { p.x = rect.width + 10; }
            if (p.x > rect.width + 10) { p.x = -10; }
            if (p.y < -10) { p.y = rect.height + 10; }
            if (p.y > rect.height + 10) { p.y = -10; }
        }
        draw();
        raf = window.requestAnimationFrame(step);
    }

    function start() {
        if (raf !== null) {
            return;
        }
        sizeCanvas();
        createParticles();
        raf = window.requestAnimationFrame(step);
    }

    function stop() {
        if (raf !== null) {
            window.cancelAnimationFrame(raf);
            raf = null;
        }
    }

    function handleVisibility() {
        if (document.hidden) {
            stop();
        } else if (!reducedMotion.matches) {
            start();
        }
    }

    var resizeTimer = null;
    window.addEventListener('resize', function () {
        if (reducedMotion.matches) {
            return;
        }
        window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(function () {
            sizeCanvas();
            createParticles();
        }, 150);
    });

    document.addEventListener('visibilitychange', handleVisibility);
    if (reducedMotion.addEventListener) {
        reducedMotion.addEventListener('change', function (e) {
            if (e.matches) {
                stop();
            } else {
                start();
            }
        });
    }

    start();
})();
