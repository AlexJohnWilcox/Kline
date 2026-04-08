// SIEM Dashboard - Client-side utilities

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
