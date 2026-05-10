function resolveAppBase() {
    if (typeof window.getAppBase === 'function') {
        return window.getAppBase();
    }
    const origin = window.location.origin;
    if (origin.includes(':8000')) {
        return origin;
    }
    return 'http://localhost:8000';
}

const APP_BASE = resolveAppBase();
const API_BASE = `${APP_BASE}/api`;

function getHeaders() {
    const token = localStorage.getItem('access_token');
    if (!token || token === 'null' || token === 'undefined') {
        return {};
    }
    return { Authorization: `Bearer ${token}` };
}

function redirectToLogin() {
    window.location.href = `${APP_BASE}/static/index.html`;
}

async function fetchJson(endpoint) {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
    const res = await fetch(url, { headers: getHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        if (res.status === 401) {
            redirectToLogin();
        }
        const message = data && data.detail ? data.detail : 'Request failed';
        throw new Error(message);
    }
    return data;
}

function navigateTo(path) {
    window.location.href = `${APP_BASE}${path}`;
}

function formatCompact(value) {
    if (!Number.isFinite(value)) return '0';
    return new Intl.NumberFormat('en-US', { notation: 'compact', compactDisplay: 'short' }).format(value);
}

function formatDate(value) {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
}

function setEmpty(container, message) {
    if (!container) return;
    container.innerHTML = `<div class="page-empty">${message}</div>`;
}
