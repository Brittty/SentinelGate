/* SentinelGate landing page interactions.
 *
 * - Mobile nav toggle (accessible, aria-expanded)
 * - Smooth in-page scrolling (skipped under prefers-reduced-motion)
 * - Animated hero counters and risk gauge (skipped under reduced motion)
 * - Copy-to-clipboard on the quick start terminal
 * Simulated values only — the landing page is fully static and collects nothing.
 */
(function () {
    'use strict';

    var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

    /* ------------------------------------------------------------------ */
    /* Mobile navigation                                                   */
    /* ------------------------------------------------------------------ */
    var toggle = document.querySelector('.nav-toggle');
    var navLinks = document.querySelector('.nav-links');
    var navButtons = document.querySelector('.nav-buttons');

    function closeMenu() {
        if (!toggle) {
            return;
        }
        toggle.setAttribute('aria-expanded', 'false');
        if (navLinks) { navLinks.classList.remove('nav-open'); }
        if (navButtons) { navButtons.classList.remove('nav-open'); }
    }

    if (toggle) {
        toggle.addEventListener('click', function () {
            var open = toggle.getAttribute('aria-expanded') === 'true';
            toggle.setAttribute('aria-expanded', open ? 'false' : 'true');
            if (navLinks) { navLinks.classList.toggle('nav-open', !open); }
            if (navButtons) { navButtons.classList.toggle('nav-open', !open); }
        });
    }

    document.addEventListener('click', function (e) {
        if (toggle && !toggle.contains(e.target)) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            closeMenu();
        }
    });

    /* ------------------------------------------------------------------ */
    /* Smooth scrolling for in-page anchors                                */
    /* ------------------------------------------------------------------ */
    document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
        anchor.addEventListener('click', function (e) {
            var id = anchor.getAttribute('href').slice(1);
            var target = document.getElementById(id);
            if (!target) {
                return;
            }
            e.preventDefault();
            closeMenu();
            if (reducedMotion.matches) {
                target.scrollIntoView();
            } else {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            history.replaceState(null, '', '#' + id);
        });
    });

    /* ------------------------------------------------------------------ */
    /* Animated counters (simulated, deterministic ramp)                   */
    /* ------------------------------------------------------------------ */
    function animateValue(el, target, duration, format) {
        var start = null;
        function tick(ts) {
            if (start === null) {
                start = ts;
            }
            var progress = Math.min((ts - start) / duration, 1);
            // ease-out cubic
            var eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = format(Math.round(target * eased));
            if (progress < 1) {
                window.requestAnimationFrame(tick);
            }
        }
        window.requestAnimationFrame(tick);
    }

    var statTargets = {
        requests: { value: 128492, format: function (n) { return n.toLocaleString('en-US'); } },
        threats: { value: 2317, format: function (n) { return n.toLocaleString('en-US'); } },
        latency: { value: 6, format: function (n) { return String(n); } },
    };

    function animateStats() {
        Object.keys(statTargets).forEach(function (key) {
            var el = document.querySelector('[data-stat="' + key + '"]');
            if (!el) {
                return;
            }
            var cfg = statTargets[key];
            if (reducedMotion.matches) {
                el.textContent = cfg.format(cfg.value);
            } else {
                animateValue(el, cfg.value, 1600, cfg.format);
            }
        });
    }

    /* ------------------------------------------------------------------ */
    /* Risk gauge (simulated score)                                        */
    /* ------------------------------------------------------------------ */
    function animateGauge() {
        var arc = document.getElementById('gauge-arc');
        var value = document.getElementById('gauge-value');
        if (!arc || !value) {
            return;
        }
        var CIRCUMFERENCE = 502.4; // 2 * pi * 80
        var score = 78;

        var set = function (n) {
            value.textContent = String(n);
            arc.setAttribute('stroke-dashoffset', String(CIRCUMFERENCE * (1 - n / 100)));
        };

        if (reducedMotion.matches) {
            set(score);
            return;
        }
        animateValue(value, score, 1800, function (n) { return String(n); });
        var start = null;
        function tick(ts) {
            if (start === null) {
                start = ts;
            }
            var progress = Math.min((ts - start) / 1800, 1);
            var eased = 1 - Math.pow(1 - progress, 3);
            arc.setAttribute('stroke-dashoffset', String(CIRCUMFERENCE * (1 - (score * eased) / 100)));
            if (progress < 1) {
                window.requestAnimationFrame(tick);
            }
        }
        window.requestAnimationFrame(tick);
    }

    /* ------------------------------------------------------------------ */
    /* Copy-to-clipboard                                                   */
    /* ------------------------------------------------------------------ */
    var copyBtn = document.querySelector('.terminal-copy');
    if (copyBtn) {
        copyBtn.addEventListener('click', function () {
            var code = document.querySelector('.terminal-content code');
            if (!code || !navigator.clipboard) {
                return;
            }
            navigator.clipboard.writeText(code.textContent).then(function () {
                copyBtn.classList.add('copied');
                copyBtn.setAttribute('aria-label', 'Copied to clipboard');
                window.setTimeout(function () {
                    copyBtn.classList.remove('copied');
                    copyBtn.setAttribute('aria-label', 'Copy to clipboard');
                }, 1500);
            });
        });
    }

    /* ------------------------------------------------------------------ */
    /* Kick off animations after first paint                               */
    /* ------------------------------------------------------------------ */
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        animateStats();
        animateGauge();
    } else {
        document.addEventListener('DOMContentLoaded', function () {
            animateStats();
            animateGauge();
        });
    }
})();
