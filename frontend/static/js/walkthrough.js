// Dashboard Walkthrough Tour
// Shows a guided tooltip tour on first visit. Uses localStorage to track completion.

(function () {
    'use strict';

    var STORAGE_KEY = 'siem-walkthrough-done';

    var STEPS = [
        {
            target: '.sidebar-nav',
            title: 'Sidebar Navigation',
            body: 'Navigate between pages: Dashboard for an overview, Events to browse logs, Alerts for detection hits, Search for AI-powered queries, Rules to manage detection logic, and Settings for configuration.'
        },
        {
            target: '.health-indicators',
            title: 'Health Status',
            body: 'Shows connection status for Elasticsearch (log storage) and Ollama (AI engine). Green means connected and working.'
        },
        {
            target: '.stats-grid',
            title: 'Key Metrics',
            body: 'Summary cards showing total events in the last 24 hours, critical and high severity counts, and the most active host.'
        },
        {
            target: '#collector-status',
            title: 'Collectors',
            body: 'Collectors ingest logs from different sources — syslog, Docker containers, and network logs. A green dot means the collector is actively running.',
            targetParent: true
        },
        {
            target: '.grid-3',
            title: 'Charts',
            body: 'The event timeline shows activity over the last 24 hours. Severity and source breakdowns help you spot patterns and anomalies at a glance.'
        },
        {
            target: '#recent-events',
            title: 'Recent Events',
            body: 'A live feed of the latest log events. Click "View All" to open the full event browser with filtering and search.',
            targetParent: true
        }
    ];

    var currentStep = 0;
    var overlay = null;
    var tooltip = null;
    var highlightedEl = null;

    function shouldRun() {
        if (window.location.pathname !== '/') return false;
        if (localStorage.getItem(STORAGE_KEY)) return false;
        return true;
    }

    function start() {
        overlay = document.createElement('div');
        overlay.className = 'wt-overlay';
        document.body.appendChild(overlay);

        tooltip = document.createElement('div');
        tooltip.className = 'wt-tooltip';
        document.body.appendChild(tooltip);

        currentStep = 0;
        showStep(currentStep);

        window.addEventListener('resize', onResize);
    }

    function end() {
        localStorage.setItem(STORAGE_KEY, 'true');
        if (highlightedEl) highlightedEl.classList.remove('wt-highlight');
        if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
        if (tooltip && tooltip.parentNode) tooltip.parentNode.removeChild(tooltip);
        window.removeEventListener('resize', onResize);
        overlay = null;
        tooltip = null;
        highlightedEl = null;
    }

    function showStep(index) {
        var step = STEPS[index];
        if (!step) { end(); return; }

        // Remove previous highlight
        if (highlightedEl) highlightedEl.classList.remove('wt-highlight');

        // Find target
        var el = document.querySelector(step.target);
        if (!el) { end(); return; }

        // If targetParent, highlight the parent .card
        if (step.targetParent) {
            var card = el.closest('.card');
            if (card) el = card;
        }

        el.classList.add('wt-highlight');
        highlightedEl = el;

        // Scroll target into view
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });

        // Build tooltip content
        var isLast = index === STEPS.length - 1;
        tooltip.innerHTML =
            '<div class="wt-arrow"></div>' +
            '<div class="wt-title">' + step.title + '</div>' +
            '<div class="wt-body">' + step.body + '</div>' +
            '<div class="wt-footer">' +
                '<span class="wt-step-count">' + (index + 1) + ' of ' + STEPS.length + '</span>' +
                '<div class="wt-actions">' +
                    '<button class="wt-skip">Skip</button>' +
                    '<button class="wt-next">' + (isLast ? 'Finish' : 'Next →') + '</button>' +
                '</div>' +
            '</div>';

        tooltip.querySelector('.wt-skip').addEventListener('click', end);
        tooltip.querySelector('.wt-next').addEventListener('click', function () {
            currentStep++;
            showStep(currentStep);
        });

        // Position after a short delay to let scroll complete
        setTimeout(function () { positionTooltip(el); }, 350);
    }

    function positionTooltip(el) {
        var rect = el.getBoundingClientRect();
        var tw = tooltip.offsetWidth;
        var th = tooltip.offsetHeight;
        var margin = 14;
        var arrowOffset = 24;
        var vw = window.innerWidth;
        var vh = window.innerHeight;

        var arrow = tooltip.querySelector('.wt-arrow');
        // Reset arrow classes
        arrow.className = 'wt-arrow';

        var top, left;

        // Try below
        if (rect.bottom + margin + th < vh) {
            top = rect.bottom + margin;
            left = rect.left + rect.width / 2 - tw / 2;
            arrow.classList.add('wt-arrow-top');
            arrow.style.left = (tw / 2 - 6) + 'px';
            arrow.style.top = '';
            arrow.style.bottom = '';
            arrow.style.right = '';
        }
        // Try above
        else if (rect.top - margin - th > 0) {
            top = rect.top - margin - th;
            left = rect.left + rect.width / 2 - tw / 2;
            arrow.classList.add('wt-arrow-bottom');
            arrow.style.left = (tw / 2 - 6) + 'px';
            arrow.style.top = '';
            arrow.style.bottom = '';
            arrow.style.right = '';
        }
        // Try right
        else if (rect.right + margin + tw < vw) {
            top = rect.top + rect.height / 2 - th / 2;
            left = rect.right + margin;
            arrow.classList.add('wt-arrow-left');
            arrow.style.top = (th / 2 - 6) + 'px';
            arrow.style.left = '';
            arrow.style.bottom = '';
            arrow.style.right = '';
        }
        // Fall back to left
        else {
            top = rect.top + rect.height / 2 - th / 2;
            left = rect.left - margin - tw;
            arrow.classList.add('wt-arrow-right');
            arrow.style.top = (th / 2 - 6) + 'px';
            arrow.style.left = '';
            arrow.style.bottom = '';
            arrow.style.right = '';
        }

        // Clamp to viewport
        if (left < 8) left = 8;
        if (left + tw > vw - 8) left = vw - tw - 8;
        if (top < 8) top = 8;
        if (top + th > vh - 8) top = vh - th - 8;

        tooltip.style.top = top + 'px';
        tooltip.style.left = left + 'px';
    }

    function onResize() {
        if (highlightedEl) positionTooltip(highlightedEl);
    }

    // Init on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            if (shouldRun()) setTimeout(start, 800);
        });
    } else {
        if (shouldRun()) setTimeout(start, 800);
    }
})();
