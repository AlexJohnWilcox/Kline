// Kline Dashboard - Client-side utilities

// Configure HTMX
document.addEventListener('htmx:configRequest', (event) => {
    // Add CSRF or other headers if needed
});

// Handle HTMX errors gracefully
document.addEventListener('htmx:responseError', (event) => {
    console.warn('HTMX request failed:', event.detail);
});

// Auto-refresh helper for Alpine components
function autoRefresh(callback, intervalMs = 30000) {
    callback();
    return setInterval(callback, intervalMs);
}

// Format numbers with commas
function formatNumber(n) {
    return (n || 0).toLocaleString();
}

// Severity color helper
function severityColor(severity) {
    const map = {
        low: 'var(--info)',
        medium: 'var(--warning)',
        high: 'var(--danger)',
        critical: '#ff3333',
    };
    return map[severity] || 'var(--text-muted)';
}

// ── Theme toggle ──
// Symbols: ☀ (&#9728;) shown while dark → click for light;
//          ☾ (&#9789;) shown while light → click for dark.
function getCurrentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function applyTheme(theme) {
    if (theme === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
    try { localStorage.setItem('theme', theme); } catch (e) {}
    updateThemeIcon(theme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (!icon) return;
    icon.innerHTML = theme === 'light' ? '&#9789;' : '&#9728;';
}

function toggleTheme() {
    applyTheme(getCurrentTheme() === 'light' ? 'dark' : 'light');
}

document.addEventListener('DOMContentLoaded', () => {
    let t = 'dark';
    try { t = localStorage.getItem('theme') || 'dark'; } catch (e) {}
    updateThemeIcon(t);
});

// ── Logout ──
async function logout() {
    try {
        await fetch('/api/v1/auth/logout', {
            method: 'POST',
            credentials: 'same-origin',
        });
    } catch (e) {
        // Ignore network errors — we're leaving the page anyway.
    }
    window.location.href = '/login';
}
