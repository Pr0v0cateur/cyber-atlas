document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('threats-page')) initThreatsPage();
    if (document.getElementById('search-page')) initSearchPage();
    if (document.getElementById('ips-page')) initIpPage();
    if (document.getElementById('domains-page')) initDomainPage();
    if (document.getElementById('cves-page')) initCvesPage();
    if (document.getElementById('mitre-page')) initMitrePage();
    if (document.getElementById('reports-page')) initReportsPage();
});

async function initThreatsPage() {
    const threatsList = document.getElementById('most-active-threats-list');
    const intrusionList = document.getElementById('intrusion-sets-list');
    const malwareList = document.getElementById('active-malware-list');

    try {
        const [threats, intrusion, malware] = await Promise.all([
            fetchJson('/dashboard/most-active-threats?limit=12'),
            fetchJson('/dashboard/active-intrusion-sets?limit=12'),
            fetchJson('/dashboard/active-malware?limit=12')
        ]);

        renderThreatList(threatsList, threats.data || []);
        renderIntrusionList(intrusionList, intrusion.data || []);
        renderMalwareList(malwareList, malware.data || []);
    } catch (err) {
        setEmpty(threatsList, 'Unable to load threat intelligence.');
        setEmpty(intrusionList, 'Unable to load intrusion sets.');
        setEmpty(malwareList, 'Unable to load malware data.');
    }
}

function renderThreatList(container, items) {
    if (!container) return;
    if (!items.length) return setEmpty(container, 'No active threats found.');
    container.innerHTML = items.map((item) => `
        <div class="page-row is-clickable" data-id="${item.id}">
            <strong>${item.name}</strong>
            <span class="page-badge">${formatCompact(item.count)}</span>
        </div>
    `).join('');
    container.querySelectorAll('.page-row').forEach((row) => {
        row.addEventListener('click', () => {
            const id = row.getAttribute('data-id');
            if (id) navigateTo(`/threats/${encodeURIComponent(id)}`);
        });
    });
}

function renderIntrusionList(container, items) {
    if (!container) return;
    if (!items.length) return setEmpty(container, 'No intrusion sets available.');
    container.innerHTML = items.map((item) => `
        <div class="page-row is-clickable" data-id="${item.id}">
            <strong>${item.name}</strong>
            <span class="page-badge">${formatCompact(item.count)}</span>
        </div>
    `).join('');
    container.querySelectorAll('.page-row').forEach((row) => {
        row.addEventListener('click', () => {
            const id = row.getAttribute('data-id');
            if (id) navigateTo(`/threats/${encodeURIComponent(id)}`);
        });
    });
}

function renderMalwareList(container, items) {
    if (!container) return;
    if (!items.length) return setEmpty(container, 'No malware families available.');
    container.innerHTML = items.map((item) => `
        <div class="page-row">
            <strong>${item.name}</strong>
            <span class="page-badge">${formatCompact(item.count)}</span>
        </div>
    `).join('');
}

async function initSearchPage() {
    const form = document.getElementById('ioc-search-form');
    const input = document.getElementById('ioc-search-input');
    const results = document.getElementById('ioc-search-results');
    const enrichment = document.getElementById('ioc-search-enrichment');

    if (!form || !input || !results) return;

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const value = input.value.trim();
        if (!value) return;

        results.innerHTML = '';
        if (enrichment) enrichment.innerHTML = '';

        try {
            const payload = await fetchJson(`/search/lookup/${encodeURIComponent(value)}`);
            renderSearchResults(results, payload.results || []);
            renderIpEnrichment(enrichment, payload.enrichment && payload.enrichment.ip_api);
        } catch (err) {
            setEmpty(results, err.message || 'Search failed.');
        }
    });
}

function renderSearchResults(container, items) {
    if (!container) return;
    if (!items.length) return setEmpty(container, 'No IOCs found for this query.');
    const rows = items.map((item) => `
        <tr class="is-clickable" data-type="${item.type}" data-value="${item.value}">
            <td>${item.value}</td>
            <td>${item.type}</td>
            <td>${item.source || '-'}</td>
            <td>${item.risk ?? '-'}</td>
            <td>${formatDate(item.last_seen)}</td>
        </tr>
    `).join('');
    container.innerHTML = `
        <table class="page-table">
            <thead>
                <tr>
                    <th>Value</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Risk</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
    container.querySelectorAll('tr.is-clickable').forEach((row) => {
        row.addEventListener('click', () => {
            const type = row.getAttribute('data-type');
            const value = row.getAttribute('data-value');
            if (!value || !type) return;
            if (type === 'ip' || type === 'cidr') {
                navigateTo(`/indicators/ip/${encodeURIComponent(value)}`);
            } else if (type === 'domain') {
                navigateTo(`/indicators/domain/${encodeURIComponent(value)}`);
            } else if (type === 'url') {
                navigateTo(`/indicators/url/${encodeURIComponent(value)}`);
            }
        });
    });
}

function renderIpEnrichment(container, data) {
    if (!container) return;
    if (!data) return;
    container.innerHTML = `
        <div class="page-card">
            <h3>IP Enrichment</h3>
            <div class="page-list">
                <div class="page-row"><strong>Country</strong><span>${data.country || '-'}</span></div>
                <div class="page-row"><strong>City</strong><span>${data.city || '-'}</span></div>
                <div class="page-row"><strong>ISP</strong><span>${data.isp || '-'}</span></div>
                <div class="page-row"><strong>ASN</strong><span>${data.asn || '-'}</span></div>
            </div>
        </div>
    `;
}

async function initIpPage() {
    const table = document.getElementById('ips-table');
    const meta = document.getElementById('ips-meta');
    const pagination = document.getElementById('ips-pagination');
    if (!table) return;
    let currentPage = 1;
    const pageSize = 25;

    const loadPage = async () => {
        table.innerHTML = '<div class="page-empty">Loading IPs...</div>';
        if (meta) meta.textContent = '';
        if (pagination) pagination.innerHTML = '';

        const data = await fetchJson(`/search/iocs?type=ip&page=${currentPage}&page_size=${pageSize}`);
        const items = data.items || [];
        const total = Number.isFinite(data.total)
            ? data.total
            : (Number.isFinite(data.pages) ? data.pages * pageSize : items.length);

        if (!items.length) {
            return setEmpty(table, 'No IP indicators available.');
        }

        renderIocTable(table, items, 'ip');

        if (meta) {
            const start = (currentPage - 1) * pageSize + 1;
            const end = Math.min(currentPage * pageSize, total);
            meta.textContent = `${start}-${end} of ${total}`;
        }

        if (pagination) {
            renderPagination(pagination, total, pageSize, currentPage, (page) => {
                currentPage = page;
                loadPage().catch((err) => {
                    setEmpty(table, err.message || 'Unable to load IPs.');
                });
            });
        }
    };

    try {
        await loadPage();
    } catch (err) {
        setEmpty(table, err.message || 'Unable to load IPs.');
    }
}

async function initDomainPage() {
    const table = document.getElementById('domains-table');
    const meta = document.getElementById('domains-meta');
    const pagination = document.getElementById('domains-pagination');
    if (!table) return;
    let currentPage = 1;
    const pageSize = 25;

    const loadPage = async () => {
        table.innerHTML = '<div class="page-empty">Loading domains...</div>';
        if (meta) meta.textContent = '';
        if (pagination) pagination.innerHTML = '';

        const data = await fetchJson(`/search/iocs?type=domain&page=${currentPage}&page_size=${pageSize}`);
        const items = data.items || [];
        const total = Number.isFinite(data.total)
            ? data.total
            : (Number.isFinite(data.pages) ? data.pages * pageSize : items.length);

        if (!items.length) {
            return setEmpty(table, 'No domain indicators available.');
        }

        renderIocTable(table, items, 'domain');

        if (meta) {
            const start = (currentPage - 1) * pageSize + 1;
            const end = Math.min(currentPage * pageSize, total);
            meta.textContent = `${start}-${end} of ${total}`;
        }

        if (pagination) {
            renderPagination(pagination, total, pageSize, currentPage, (page) => {
                currentPage = page;
                loadPage().catch((err) => {
                    setEmpty(table, err.message || 'Unable to load domains.');
                });
            });
        }
    };

    try {
        await loadPage();
    } catch (err) {
        setEmpty(table, err.message || 'Unable to load domains.');
    }
}

function renderIocTable(container, items, kind) {
    if (!container) return;
    if (!items.length) return setEmpty(container, 'No records available.');
    const rows = items.map((item) => `
        <tr class="is-clickable" data-value="${item.value}">
            <td>${item.value}</td>
            <td>${item.source || '-'}</td>
            <td>${item.risk ?? '-'}</td>
            <td>${item.country || '-'}</td>
            <td>${formatDate(item.last_seen)}</td>
        </tr>
    `).join('');
    container.innerHTML = `
        <div class="table-scroll">
            <table class="page-table">
                <thead>
                    <tr>
                        <th>Value</th>
                        <th>Source</th>
                        <th>Risk</th>
                        <th>Country</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
    container.querySelectorAll('tr.is-clickable').forEach((row) => {
        row.addEventListener('click', () => {
            const value = row.getAttribute('data-value');
            if (!value) return;
            const path = kind === 'ip' ? `/indicators/ip/${encodeURIComponent(value)}` : `/indicators/domain/${encodeURIComponent(value)}`;
            navigateTo(path);
        });
    });
}

async function initCvesPage() {
    const list = document.getElementById('cves-list');
    const meta = document.getElementById('cves-meta');
    const sortButtons = document.querySelectorAll('[data-cve-sort]');
    const pagination = document.getElementById('cves-pagination');
    if (!list) return;
    let activeSort = 'latest';
    let activeDays = 30;
    let currentPage = 1;
    const pageSize = 25;

    const setActiveButton = (sortValue) => {
        sortButtons.forEach((btn) => {
            const isActive = btn.getAttribute('data-cve-sort') === sortValue;
            btn.classList.toggle('is-active', isActive);
        });
    };

    const loadCves = async (sortValue) => {
        list.innerHTML = '<div class="page-empty">Loading CVEs...</div>';
        if (meta) meta.textContent = '';
        if (pagination) pagination.innerHTML = '';

        const query = new URLSearchParams();
        query.set('sort', sortValue);
        query.set('limit', String(pageSize));
        query.set('offset', String((currentPage - 1) * pageSize));
        if (sortValue === 'critical') {
            query.set('days', String(activeDays));
        }

        const data = await fetchJson(`/kev/cves?${query.toString()}`);
        const items = data.data || [];
        const available = data.meta && Number.isFinite(data.meta.available) ? data.meta.available : items.length;

        if (!items.length) {
            return setEmpty(list, 'No CVEs available for this view.');
        }

        if (meta) {
            const start = (currentPage - 1) * pageSize + 1;
            const end = Math.min(currentPage * pageSize, available);
            meta.textContent = `${start}-${end} of ${available}`;
        }

        list.innerHTML = items.map((item) => {
            const cveId = escapeHtml(item.cve || 'Unknown CVE');
            const vendor = escapeHtml(item.vendor || 'Unknown vendor');
            const product = escapeHtml(item.product || 'Unknown product');
            const name = escapeHtml(item.name || item.description || 'Known exploited vulnerability');
            const ransomware = item.ransomware || 'Unknown';
            const ransomwareClass = String(ransomware).toLowerCase() === 'known' ? 'tag-danger' : 'tag-neutral';
            const severity = getKevSeverity(item.critical_score);

            return `
                <div class="page-row cve-row is-clickable" data-id="${cveId}">
                    <div class="page-row-main">
                        <strong>${cveId}</strong>
                        <span class="page-subtext">${name}</span>
                        <span class="page-subtext is-muted">${vendor} • ${product}</span>
                    </div>
                    <div class="page-row-meta">
                        <span class="page-tag ${ransomwareClass}">Ransomware: ${escapeHtml(ransomware)}</span>
                        <span class="page-date">${formatDate(item.date_added)}</span>
                        <span class="page-severity ${severity.className}">${severity.label}</span>
                    </div>
                </div>
            `;
        }).join('');

        list.querySelectorAll('.page-row').forEach((row) => {
            row.addEventListener('click', () => {
                const id = row.getAttribute('data-id');
                if (id) navigateTo(`/cves/${encodeURIComponent(id)}`);
            });
        });

        if (pagination) {
            renderPagination(pagination, available, pageSize, currentPage, (page) => {
                currentPage = page;
                loadCves(activeSort).catch((err) => {
                    setEmpty(list, err.message || 'Unable to load CVEs.');
                });
            });
        }
    };

    sortButtons.forEach((btn) => {
        btn.addEventListener('click', async () => {
            const sortValue = btn.getAttribute('data-cve-sort') || 'latest';
            const daysValue = btn.getAttribute('data-days');
            if (daysValue) {
                const parsed = Number.parseInt(daysValue, 10);
                if (!Number.isNaN(parsed)) activeDays = parsed;
            }
            activeSort = sortValue;
            currentPage = 1;
            setActiveButton(sortValue);
            try {
                await loadCves(sortValue);
            } catch (err) {
                setEmpty(list, err.message || 'Unable to load CVEs.');
            }
        });
    });

    setActiveButton(activeSort);
    try {
        await loadCves(activeSort);
    } catch (err) {
        setEmpty(list, err.message || 'Unable to load CVEs.');
    }
}

async function initMitrePage() {
    const tacticsList = document.getElementById('mitre-tactics-list');
    const techniquesList = document.getElementById('mitre-techniques-list');
    if (!tacticsList || !techniquesList) return;

    try {
        const [tactics, techniques] = await Promise.all([
            fetchJson('/mitre/tactics'),
            fetchJson('/mitre/techniques?limit=30')
        ]);

        tacticsList.innerHTML = tactics.map((item) => `
            <div class="page-row">
                <strong>${item.name}</strong>
                <span>${item.short_name || item.external_id || '-'}</span>
            </div>
        `).join('');

        techniquesList.innerHTML = techniques.map((item) => `
            <div class="page-row">
                <strong>${item.name}</strong>
                <span>${item.external_id || '-'}</span>
            </div>
        `).join('');
    } catch (err) {
        setEmpty(tacticsList, 'Unable to load tactics.');
        setEmpty(techniquesList, 'Unable to load techniques.');
    }
}

async function initReportsPage() {
    const list = document.getElementById('reports-list');
    if (!list) return;
    try {
        const data = await fetchJson('/dashboard/recent-reports?limit=15');
        const items = data.data || [];
        if (!items.length) return setEmpty(list, 'No recent reports.');
        list.innerHTML = items.map((item) => `
            <div class="page-row">
                <div>
                    <strong>${item.title || 'Untitled report'}</strong>
                    <div><span>${item.source || 'Unknown source'}</span></div>
                </div>
                <span class="page-badge">${item.confidence ?? 0}</span>
            </div>
        `).join('');
    } catch (err) {
        setEmpty(list, err.message || 'Unable to load reports.');
    }
}

function getKevSeverity(score) {
    const value = Number.isFinite(score) ? score : 0;
    if (value >= 120) return { label: 'Critical', className: 'severity-critical' };
    if (value >= 80) return { label: 'High', className: 'severity-high' };
    if (value >= 50) return { label: 'Medium', className: 'severity-medium' };
    return { label: 'Low', className: 'severity-low' };
}

function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderPagination(container, totalItems, pageSize, currentPage, onPageChange) {
    const totalPages = Math.ceil(totalItems / pageSize);
    if (totalPages <= 1) return;

    const buildPages = () => {
        const pages = new Set();
        pages.add(1);
        pages.add(totalPages);
        for (let i = currentPage - 2; i <= currentPage + 2; i++) {
            if (i > 1 && i < totalPages) pages.add(i);
        }
        return Array.from(pages).sort((a, b) => a - b);
    };

    const pages = buildPages();
    let html = '<div class="page-pagination">';

    html += `
        <button class="page-page-btn" data-page="${Math.max(1, currentPage - 1)}" ${currentPage === 1 ? 'disabled' : ''}>
            Prev
        </button>
    `;

    pages.forEach((page, index) => {
        const prev = pages[index - 1];
        if (index > 0 && page - prev > 1) {
            html += '<span class="page-ellipsis">…</span>';
        }
        html += `
            <button class="page-page-btn ${page === currentPage ? 'is-active' : ''}" data-page="${page}">
                ${page}
            </button>
        `;
    });

    html += `
        <button class="page-page-btn" data-page="${Math.min(totalPages, currentPage + 1)}" ${currentPage === totalPages ? 'disabled' : ''}>
            Next
        </button>
    `;

    html += '</div>';
    container.innerHTML = html;

    container.querySelectorAll('.page-page-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const page = Number.parseInt(btn.getAttribute('data-page'), 10);
            if (!Number.isNaN(page) && page !== currentPage) {
                onPageChange(page);
            }
        });
    });
}
