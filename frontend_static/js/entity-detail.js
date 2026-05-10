/* -------------------------------------------------------------------------- */
/*                            Entity Detail Pages                             */
/* -------------------------------------------------------------------------- */

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

const TAB_LABELS = [
    'Overview',
    'Knowledge',
    'Content',
    'Analyses',
    'Data',
    'History'
];

document.addEventListener('DOMContentLoaded', () => {
    initEntityPage();
});

function initEntityPage() {
    const pageType = document.body.dataset.page || 'cve';
    renderShell(pageType);
    loadEntityData(pageType);
}

function renderShell(pageType) {
    const headerEl = document.getElementById('entity-header');
    const tabsEl = document.getElementById('entity-tabs');
    const contentEl = document.getElementById('entity-content');

    if (headerEl) {
        headerEl.innerHTML = EntityHeader({ title: 'Loading...' });
    }
    if (tabsEl) {
        tabsEl.innerHTML = EntityTabs({ active: 'overview' });
    }
    if (contentEl) {
        contentEl.innerHTML = buildSkeleton(pageType);
    }
}

async function loadEntityData(pageType) {
    try {
        const params = getEntityParams(pageType);
        if (!params) {
            renderNotFound('Missing entity identifier');
            return;
        }

        const data = await fetchJson(params.endpoint);
        if (!data || data.found === false) {
            renderNotFound('No data has been found');
            return;
        }

        renderEntity(pageType, data, params);
    } catch (err) {
        console.error('Entity load failed', err);
        renderNotFound(err && err.message ? err.message : 'No data has been found');
    }
}

function getEntityParams(pageType) {
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const queryParams = new URLSearchParams(window.location.search);
    const hasHtml = pathParts.some((part) => part.endsWith('.html'));

    if (pageType === 'cve') {
        const pathId = !hasHtml && pathParts[0] === 'cves' ? pathParts[1] : '';
        const cveId = decodeURIComponent(pathId || queryParams.get('id') || queryParams.get('cve') || '');
        if (!cveId) return null;
        return {
            id: cveId,
            endpoint: `${API_BASE}/entities/cves/${encodeURIComponent(cveId)}`
        };
    }

    if (pageType === 'threat') {
        const pathId = !hasHtml && pathParts[0] === 'threats' ? pathParts[1] : '';
        const threatId = decodeURIComponent(pathId || queryParams.get('id') || '');
        if (!threatId) return null;
        return {
            id: threatId,
            endpoint: `${API_BASE}/entities/threats/${encodeURIComponent(threatId)}`
        };
    }

    let indicatorType = queryParams.get('type') || 'domain';
    let indicatorValue = queryParams.get('value') || '';

    if (!hasHtml && pathParts[0] === 'indicators') {
        indicatorType = pathParts[1] || indicatorType;
        indicatorValue = pathParts.length >= 3 ? pathParts.slice(2).join('/') : indicatorValue;
    }

    indicatorValue = decodeURIComponent(indicatorValue || '');
    if (!indicatorValue) return null;
    return {
        id: indicatorValue,
        indicatorType: indicatorType,
        endpoint: `${API_BASE}/entities/indicators/${encodeURIComponent(indicatorType)}/${encodeURIComponent(indicatorValue)}`
    };
}

function renderEntity(pageType, data, params) {
    const headerEl = document.getElementById('entity-header');
    const contentEl = document.getElementById('entity-content');

    if (pageType === 'cve') {
        const title = data.cve && data.cve.id ? data.cve.id : params.id;
        if (headerEl) {
            headerEl.innerHTML = EntityHeader({ title: title });
        }
        if (contentEl) {
            contentEl.innerHTML = renderCveOverview(data);
        }
    } else if (pageType === 'threat') {
        const entity = data.entity || {};
        if (headerEl) {
            headerEl.innerHTML = EntityHeader({ title: entity.name || params.id });
        }
        if (contentEl) {
            contentEl.innerHTML = renderThreatOverview(data);
        }
    } else {
        const indicator = data.indicator || {};
        if (headerEl) {
            headerEl.innerHTML = EntityHeader({ title: indicator.value || params.id });
        }
        if (contentEl) {
            contentEl.innerHTML = renderDomainOverview(data);
        }
    }

    setupTabs();
    const shell = document.getElementById('entity-shell');
    if (shell) shell.classList.remove('loading-mask');
}

function renderNotFound(message) {
    const headerEl = document.getElementById('entity-header');
    const contentEl = document.getElementById('entity-content');
    if (headerEl) {
        headerEl.innerHTML = EntityHeader({ title: 'Not Found' });
    }
    if (contentEl) {
        contentEl.innerHTML = EmptyStatePanel(message);
    }
    setupTabs();
    const shell = document.getElementById('entity-shell');
    if (shell) shell.classList.remove('loading-mask');
}

function renderCveOverview(data) {
    const summary = data.summary || {};
    const cve = data.cve || {};
    const meta = data.meta || {};
    const vector = cve.vector || {};
    const references = Array.isArray(data.external_references) ? data.external_references : [];
    const relationships = Array.isArray(data.relationships) ? data.relationships : [];

    return `
        <div data-tab="overview">
        ${SummaryCardsRow([
            { label: 'Total Reports', value: summary.total_reports || 0 },
            { label: 'Total Relationships', value: summary.total_relationships || 0 },
            { label: 'Total Sightings', value: summary.total_sightings || 0 }
        ])}
        <div class="entity-grid grid-two">
            <div class="card">
                <h3>CVE Metadata</h3>
                ${KeyValueGrid([
                    { key: 'CVSS Score', value: formatValue(cve.cvss && cve.cvss.score) },
                    { key: 'Severity', value: formatValue(cve.cvss && cve.cvss.severity) },
                    { key: 'EPSS', value: formatValue(cve.epss) },
                    { key: 'Vendor', value: formatValue(cve.vendor) },
                    { key: 'Product', value: formatValue(cve.product) },
                    { key: 'Published', value: formatDate(cve.published) },
                    { key: 'Modified', value: formatDate(cve.updated) },
                    { key: 'Attack Vector', value: formatValue(vector.attack_vector) },
                    { key: 'Attack Complexity', value: formatValue(vector.attack_complexity) },
                    { key: 'Privileges Required', value: formatValue(vector.privileges_required) },
                    { key: 'User Interaction', value: formatValue(vector.user_interaction) },
                    { key: 'Scope', value: formatValue(vector.scope) },
                    { key: 'Confidentiality', value: formatValue(vector.confidentiality) },
                    { key: 'Integrity', value: formatValue(vector.integrity) },
                    { key: 'Availability', value: formatValue(vector.availability) }
                ])}
            </div>
            <div class="card">
                <h3>Basic Information</h3>
                ${KeyValueGrid([
                    { key: 'Confidence', value: formatValue(meta.confidence) },
                    { key: 'Reliability', value: formatValue(meta.reliability) },
                    { key: 'Processing Status', value: formatValue(meta.processing_status) },
                    { key: 'Labels', raw: formatList(meta.labels) },
                    { key: 'Creator', value: formatValue(meta.creator) }
                ])}
            </div>
        </div>
        <div class="entity-grid grid-two" style="margin-top: 14px;">
            <div class="card">
                <h3>Latest Created Relationships</h3>
                ${relationships.length ? RelationshipsTable(relationships) : EmptyStatePanel('No data has been found')}
            </div>
            <div class="card">
                <h3>External References</h3>
                ${references.length ? ExternalReferencesList(references) : EmptyStatePanel('No data has been found')}
            </div>
        </div>
        </div>
        ${buildTabEmptyState('knowledge')}
        ${buildTabEmptyState('content')}
        ${buildTabEmptyState('analyses')}
        ${buildTabEmptyState('data')}
        ${buildTabEmptyState('history')}
    `;
}

function renderThreatOverview(data) {
    const summary = data.summary || {};
    const entity = data.entity || {};
    const meta = data.meta || {};
    const references = Array.isArray(data.external_references) ? data.external_references : [];
    const relationships = Array.isArray(data.relationships) ? data.relationships : [];

    return `
        <div data-tab="overview">
        ${SummaryCardsRow([
            { label: 'Total Reports', value: summary.total_reports || 0 },
            { label: 'Total Relationships', value: summary.total_relationships || 0 },
            { label: 'Total Sightings', value: summary.total_sightings || 0 }
        ])}
        <div class="entity-grid grid-two">
            <div class="card">
                <h3>Threat Overview</h3>
                ${KeyValueGrid([
                    { key: 'Type', value: formatValue(entity.type) },
                    { key: 'Description', value: formatValue(entity.description) },
                    { key: 'First Seen', value: formatDate(entity.first_seen) },
                    { key: 'Last Seen', value: formatDate(entity.last_seen) },
                    { key: 'MITRE ID', value: formatValue(entity.external_id) },
                    { key: 'Labels', raw: formatList(entity.labels) },
                    { key: 'Confidence', value: formatValue(entity.confidence) }
                ])}
            </div>
            <div class="card">
                <h3>Basic Information</h3>
                ${KeyValueGrid([
                    { key: 'Status', value: formatValue(meta.status) },
                    { key: 'Author', value: formatValue(meta.author) },
                    { key: 'Labels', raw: formatList(meta.labels) },
                    { key: 'Created', value: formatDate(meta.created) },
                    { key: 'Modified', value: formatDate(meta.modified) }
                ])}
            </div>
        </div>
        <div class="entity-grid grid-two" style="margin-top: 14px;">
            <div class="card">
                <h3>Latest Created Relationships</h3>
                ${relationships.length ? RelationshipsTable(relationships) : EmptyStatePanel('No data has been found')}
            </div>
            <div class="card">
                <h3>External References</h3>
                ${references.length ? ExternalReferencesList(references) : EmptyStatePanel('No data has been found')}
            </div>
        </div>
        </div>
        ${buildTabEmptyState('knowledge')}
        ${buildTabEmptyState('content')}
        ${buildTabEmptyState('analyses')}
        ${buildTabEmptyState('data')}
        ${buildTabEmptyState('history')}
    `;
}

function renderDomainOverview(data) {
    const indicator = data.indicator || {};
    const meta = data.meta || {};
    const relationships = Array.isArray(data.relationships) ? data.relationships : [];
    const history = Array.isArray(data.history) ? data.history : [];

    return `
        <div data-tab="overview">
        ${SummaryCardsRow([
            { label: 'Total Relationships', value: relationships.length },
            { label: 'Valid From', value: formatDate(indicator.valid_from) },
            { label: 'Valid Until', value: formatDate(indicator.valid_until) }
        ])}
        <div class="entity-grid grid-three">
            <div class="card">
                <h3>Indicator Details</h3>
                ${KeyValueGrid([
                    { key: 'Pattern', value: formatValue(indicator.pattern) },
                    { key: 'Score', value: formatValue(indicator.score) },
                    { key: 'Description', value: formatValue(indicator.description) },
                    { key: 'Indicator Types', raw: formatList(indicator.indicator_types) },
                    { key: 'Observable Type', value: formatValue(indicator.observable_type) }
                ])}
            </div>
            <div class="card">
                <h3>Relationship Snapshot</h3>
                <div class="mini-graph">No data has been found</div>
                <div style="margin-top: 10px;">
                    ${relationships.length ? RelationshipsTable(relationships.slice(0, 3)) : EmptyStatePanel('No data has been found')}
                </div>
            </div>
            <div class="card">
                <h3>Basic Information</h3>
                ${KeyValueGrid([
                    { key: 'Marking', value: formatValue(meta.marking) },
                    { key: 'Author', value: formatValue(meta.author) },
                    { key: 'Reliability', value: formatValue(meta.reliability) },
                    { key: 'Confidence', value: formatValue(meta.confidence) },
                    { key: 'Processing Status', value: formatValue(meta.processing_status) },
                    { key: 'Labels', raw: formatList(meta.labels) },
                    { key: 'Created', value: formatDate(meta.created) },
                    { key: 'Modified', value: formatDate(meta.modified) },
                    { key: 'STIX ID', value: formatValue(meta.stix_id) }
                ])}
            </div>
        </div>
        <div class="entity-grid grid-two" style="margin-top: 14px;">
            <div class="card">
                <h3>Latest Created Relationships</h3>
                ${relationships.length ? RelationshipsTable(relationships) : EmptyStatePanel('No data has been found')}
            </div>
            <div class="card">
                <h3>Most Recent History</h3>
                ${history.length ? RelationshipsTable(history) : EmptyStatePanel('No data has been found')}
            </div>
        </div>
        </div>
        ${buildTabEmptyState('knowledge')}
        ${buildTabEmptyState('content')}
        ${buildTabEmptyState('analyses')}
        ${buildTabEmptyState('data')}
        ${buildTabEmptyState('history')}
    `;
}

function EntityHeader({ title }) {
    return `
        <div class="entity-header">
            <div class="entity-title-group">
                <div class="entity-title">${escapeHtml(title)}</div>
            </div>
            <div class="entity-actions">
                <button class="entity-action-btn"><i class="fa-solid fa-link"></i> Create Relationship</button>
                <button class="entity-action-btn primary"><i class="fa-solid fa-pen"></i> Update</button>
            </div>
        </div>
    `;
}

function EntityTabs({ active }) {
    const tabs = TAB_LABELS.map((label) => {
        const key = label.toLowerCase();
        const isActive = key === active;
        return `<div class="entity-tab ${isActive ? 'active' : ''}" data-tab="${key}">${label}</div>`;
    }).join('');
    return `<div class="entity-tabs">${tabs}</div>`;
}

function SummaryCardsRow(cards) {
    const markup = cards.map(card => `
        <div class="summary-card">
            <div class="label">${escapeHtml(card.label)}</div>
            <div class="value">${escapeHtml(String(card.value ?? 0))}</div>
        </div>
    `).join('');
    return `<div class="summary-row">${markup}</div>`;
}

function KeyValueGrid(items) {
    const rows = items.map(item => `
        <div>
            <div class="key">${escapeHtml(item.key)}</div>
            <div class="value">${item.raw ? item.raw : formatValue(item.value)}</div>
        </div>
    `).join('');
    return `<div class="key-value-grid">${rows}</div>`;
}

function RelationshipsTable(rows) {
    const body = rows.map((row) => {
        const source = row.source ? `${row.source.name} (${row.source.type})` : '-';
        const target = row.target ? `${row.target.name} (${row.target.type})` : '-';
        return `
            <tr>
                <td>${escapeHtml(row.relationship_type || '-')}</td>
                <td>${escapeHtml(source)}</td>
                <td>${escapeHtml(target)}</td>
                <td>${formatDate(row.created)}</td>
            </tr>
        `;
    }).join('');
    return `
        <table class="table">
            <thead>
                <tr>
                    <th>Relationship</th>
                    <th>Source</th>
                    <th>Target</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>${body}</tbody>
        </table>
    `;
}

function ExternalReferencesList(items) {
    const list = items.map((ref) => {
        const url = typeof ref === 'string' ? ref : ref.url;
        if (!url) return '';
        return `<li><a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(url)}</a></li>`;
    }).join('');
    return `<ul class="external-list">${list}</ul>`;
}

function EmptyStatePanel(message) {
    return `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function buildTabEmptyState(tabKey) {
    return `
        <div class="card" data-tab="${tabKey}">
            <h3>${tabKey.toUpperCase()}</h3>
            ${EmptyStatePanel('No data has been found')}
        </div>
    `;
}

function buildSkeleton(pageType) {
    const summarySkeleton = `
        <div class="summary-row">
            <div class="summary-card skeleton"><div class="skeleton-line skeleton-title"></div></div>
            <div class="summary-card skeleton"><div class="skeleton-line skeleton-title"></div></div>
            <div class="summary-card skeleton"><div class="skeleton-line skeleton-title"></div></div>
        </div>
    `;
    const gridCount = pageType === 'domain' ? 3 : 2;
    const grid = `
        <div class="entity-grid ${gridCount === 3 ? 'grid-three' : 'grid-two'}">
            <div class="card skeleton" style="height: 180px;"></div>
            <div class="card skeleton" style="height: 180px;"></div>
            ${gridCount === 3 ? '<div class="card skeleton" style="height: 180px;"></div>' : ''}
        </div>
    `;
    return `${summarySkeleton}${grid}<div class="entity-grid grid-two" style="margin-top: 14px;">
        <div class="card skeleton" style="height: 160px;"></div>
        <div class="card skeleton" style="height: 160px;"></div>
    </div>`;
}

function setupTabs() {
    const tabs = document.querySelectorAll('.entity-tab');
    if (!tabs.length) return;

    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            tabs.forEach((t) => t.classList.remove('active'));
            tab.classList.add('active');
            const key = tab.dataset.tab;
            document.querySelectorAll('[data-tab]').forEach((section) => {
                if (section.classList.contains('entity-tab')) return;
                const target = section.getAttribute('data-tab');
                if (!target) return;
                section.style.display = target === key ? 'block' : 'none';
            });
        });
    });

    const active = document.querySelector('.entity-tab.active');
    if (active) active.click();
}

function formatValue(value) {
    if (value === null || value === undefined || value === '') return '-';
    return escapeHtml(String(value));
}

function formatList(list) {
    if (!list || !Array.isArray(list) || list.length === 0) return '-';
    return `<div class="pill-row">${list.map(item => `<span class="pill">${escapeHtml(String(item))}</span>`).join('')}</div>`;
}

function formatDate(value) {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

async function fetchJson(url) {
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

function getHeaders() {
    const token = localStorage.getItem('access_token');
    if (!token) return {};
    return { Authorization: `Bearer ${token}` };
}

function redirectToLogin() {
    window.location.href = `${APP_BASE}/static/index.html`;
}
