/* -------------------------------------------------------------------------- */
/*                               Breach Checker                               */
/* -------------------------------------------------------------------------- */

const DEFAULT_BREACH_ENDPOINT = '/api/breach/check';

function initBreachCheck() {
    if (window.__breachCheckInitialized) return;
    window.__breachCheckInitialized = true;

    const container = document.getElementById('breach-checker');
    const input = document.getElementById('breach-input');
    const submit = document.getElementById('breach-submit');
    const panel = document.getElementById('breach-panel');
    const reset = document.getElementById('breach-reset');
    const title = document.getElementById('breach-panel-title');
    const subtitle = document.getElementById('breach-panel-subtitle');
    const summary = document.getElementById('breach-summary');
    const cards = document.getElementById('breach-cards');
    const inlineError = document.getElementById('breach-inline-error');

    if (!container || !input || !submit || !panel || !reset || !title || !subtitle || !summary || !cards) {
        return;
    }

    const showPanel = () => {
        panel.classList.add('is-active');
        container.classList.add('is-hidden');
        document.body.classList.add('breach-active');
    };

    const hidePanel = () => {
        panel.classList.remove('is-active', 'is-safe');
        container.classList.remove('is-hidden');
        document.body.classList.remove('breach-active');
    };

    reset.addEventListener('click', hidePanel);

    submit.addEventListener('click', () => {
        const email = input.value.trim();
        if (!isValidEmail(email)) {
            alert('Please enter a valid email address.');
            return;
        }
        setInlineError(inlineError, '');
        runBreachCheck(email, {
            panel,
            title,
            subtitle,
            summary,
            cards,
            showPanel,
            hidePanel,
            inlineError,
            submit,
            container
        });
    });

    input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            submit.click();
        }
    });
}

async function runBreachCheck(email, refs) {
    const { panel, title, subtitle, summary, cards, showPanel, hidePanel, inlineError, submit } = refs;

    title.textContent = 'Breach Check';
    subtitle.textContent = `Scanning ${email}...`;
    summary.innerHTML = '';
    cards.innerHTML = '';
    panel.classList.remove('is-safe');
    setInlineError(inlineError, '');
    setLoadingState(submit, true);

    try {
        const payload = await fetchBreachData(email, refs.container);
        const breaches = normalizeBreaches(payload);

        if (breaches.length > 0) {
            panel.classList.remove('is-safe');
            showPanel();
            renderBreachedState(email, breaches, refs);
        } else {
            panel.classList.add('is-safe');
            showPanel();
            renderSafeState(email, refs);
        }
    } catch (err) {
        panel.classList.remove('is-safe');
        showPanel();
        setInlineError(inlineError, '');
        renderErrorState(
            err instanceof Error ? err.message : 'Breach check failed.',
            refs
        );
    } finally {
        setLoadingState(submit, false);
    }
}

async function fetchBreachData(email, container) {
    const token = localStorage.getItem('access_token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const endpoint = resolveEndpoint(container);
    const response = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email })
    });

    if (response.status === 401) {
        window.location.href = 'index.html';
        return {};
    }

    if (response.status === 404) {
        throw new Error('Breach endpoint not found. Update the data-endpoint value.');
    }

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.detail || data.error || 'Breach check failed');
    }
    return data;
}

function resolveEndpoint(container) {
    const override = container && container.dataset ? container.dataset.endpoint : '';
    const raw = override || DEFAULT_BREACH_ENDPOINT;
    if (/^https?:\/\//i.test(raw)) {
        return raw;
    }
    if (raw.startsWith('/')) {
        return `${window.location.origin}${raw}`;
    }
    return `${window.location.origin}/${raw}`;
}

function normalizeBreaches(payload) {
    if (!payload) return [];
    const list = payload.Breaches || payload.breaches || [];
    return Array.isArray(list) ? list : [];
}

function renderBreachedState(email, breaches, refs) {
    const { title, subtitle, summary, cards } = refs;
    title.textContent = 'Warning: Breaches Detected';
    subtitle.textContent = `${email} appears in ${breaches.length} breach record(s).`;

    summary.innerHTML = `
        <div class="breach-summary-card">
            <span>Total Breaches</span>
            <strong>${breaches.length}</strong>
        </div>
        <div class="breach-summary-card">
            <span>Verified Entries</span>
            <strong>${breaches.filter((item) => item.IsVerified).length}</strong>
        </div>
    `;

    cards.innerHTML = '';
    breaches.forEach((item) => {
        cards.appendChild(buildBreachCard(item));
    });
}

function renderSafeState(email, refs) {
    const { title, subtitle, summary, cards } = refs;
    title.textContent = 'All Clear';
    subtitle.textContent = `${email} has no known breaches.`;

    summary.innerHTML = `
        <div class="breach-safe-banner">
            <div class="breach-safe-icon">
                <i class="fa-solid fa-shield"></i>
            </div>
            <div>
                <div style="font-size: 16px; font-weight: 600;">No Breaches Found.</div>
                <div style="font-size: 13px; color: #94a3b8;">This email is clean.</div>
            </div>
        </div>
    `;

    cards.innerHTML = '';
    triggerConfetti();
}

function renderErrorState(message, refs) {
    const { title, subtitle, summary, cards } = refs;
    title.textContent = 'Unable to Check';
    subtitle.textContent = 'Please try again later.';
    summary.innerHTML = `
        <div class="breach-summary-card">
            <span>Error</span>
            <strong>${escapeHtml(message)}</strong>
        </div>
    `;
    cards.innerHTML = '';
}

function setInlineError(element, message) {
    if (!element) return;
    if (!message) {
        element.textContent = '';
        element.classList.remove('is-visible');
        return;
    }
    element.textContent = message;
    element.classList.add('is-visible');
}

function setLoadingState(button, isLoading) {
    if (!button) return;
    if (isLoading) {
        button.dataset.label = button.textContent;
        button.textContent = 'Checking...';
        button.disabled = true;
    } else {
        button.textContent = button.dataset.label || 'Check';
        button.disabled = false;
    }
}

function buildBreachCard(item) {
    const card = document.createElement('div');
    card.className = 'breach-card';

    const logo = extractLogoUrl(item.LogoPath);
    const title = item.Title || item.Name || 'Unknown Breach';
    const date = formatDate(item.BreachDate);
    const description = item.Description || '';
    const classes = Array.isArray(item.DataClasses) ? item.DataClasses : [];
    const verified = item.IsVerified === true;
    const pwnCount = item.PwnCount ? Number(item.PwnCount) : null;

    const tagsMarkup = classes.map((entry) => `<span class="breach-tag">${escapeHtml(entry)}</span>`).join('');
    const verifiedMarkup = verified
        ? '<span class="breach-verified"><i class="fa-solid fa-circle-check"></i> Verified</span>'
        : '';
    const metricMarkup = Number.isFinite(pwnCount)
        ? `<div class="breach-metric">Affected accounts: ${formatCompactNumber(pwnCount)}</div>`
        : '';

    card.innerHTML = `
        <div class="breach-card-header">
            <div style="display:flex; align-items:center; gap:12px;">
                ${logo ? `<img class="breach-logo" src="${logo}" alt="${escapeHtml(title)} logo">` : ''}
                <div>
                    <div class="breach-title">${escapeHtml(title)}</div>
                    <div class="breach-date">${date}</div>
                </div>
            </div>
            ${verifiedMarkup}
        </div>
        <div class="breach-description">${description}</div>
        ${metricMarkup}
        <div class="breach-tags">${tagsMarkup}</div>
    `;

    return card;
}

function extractLogoUrl(value) {
    if (!value) return '';
    const match = String(value).match(/\((https?:\/\/[^)]+)\)/);
    if (match) return match[1];
    if (String(value).startsWith('http')) return value;
    return '';
}

function formatDate(value) {
    if (!value) return 'Unknown date';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: '2-digit'
    }).format(date);
}

function formatCompactNumber(value) {
    return new Intl.NumberFormat('en-US', { notation: 'compact', compactDisplay: 'short' }).format(value);
}

function triggerConfetti() {
    if (typeof confetti !== 'function') return;
    confetti({
        particleCount: 120,
        spread: 70,
        origin: { y: 0.6 },
        colors: ['#22c55e', '#10b981', '#34d399', '#a7f3d0']
    });
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

document.addEventListener('DOMContentLoaded', initBreachCheck);
