/* -------------------------------------------------------------------------- */
/*                                 IOC Search                                 */
/* -------------------------------------------------------------------------- */

function initSearch() {
    const searchInput = document.getElementById('ioc-search');
    const resultsContainer = document.getElementById('search-results');
    let debounceTimer;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.trim();
        clearTimeout(debounceTimer);

        if (query.length < 2) {
            resultsContainer.style.display = 'none';
            return;
        }

        debounceTimer = setTimeout(() => {
            performSearch(query, resultsContainer);
        }, 300);
    });

    // Close on click outside
    document.addEventListener('click', (e) => {
        if (!searchInput.contains(e.target) && !resultsContainer.contains(e.target)) {
            resultsContainer.style.display = 'none';
        }
    });
}

async function performSearch(query, container) {
    try {
        const token = localStorage.getItem('access_token');
        const API_URL = 'http://localhost:8000/api';

        // Use our real backend search
        const response = await fetch(`${API_URL}/search/iocs?q=${encodeURIComponent(query)}&limit=5`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            const data = await response.json();
            renderResults(data.items || [], container);
        } else {
            // Fallback for demo if backend offline
            renderMockResults(query, container);
        }
    } catch (e) {
        console.error("Search failed", e);
        renderMockResults(query, container);
    }
}

function renderResults(items, container) {
    if (items.length === 0) {
        container.innerHTML = '<div class="search-result-item">No results found</div>';
        container.style.display = 'block';
        return;
    }

    const html = items.map(item => `
        <div class="search-result-item" onclick="alert('View details for ${item.value}')">
            <div style="flex: 1;">
                <div style="font-weight: 500; color: #e2e8f0;">${item.value}</div>
                <div style="font-size: 0.8rem; color: #94a3b8;">
                    <span class="badge badge-low">${item.type}</span> • ${item.source || 'Unknown'}
                </div>
            </div>
            <div style="font-size: 1.2rem;">${getIconForType(item.type)}</div>
        </div>
    `).join('');

    container.innerHTML = html;
    container.style.display = 'block';
}

function renderMockResults(query, container) {
    // Demo mode results
    const mockItems = [
        { value: `${query}.com`, type: 'domain', source: 'ThreatFox' },
        { value: `192.168.1.${Math.floor(Math.random() * 255)}`, type: 'ip', source: 'AbuseIPDB' },
        { value: `${query}_malware.exe`, type: 'hash', source: 'MalwareBazaar' }
    ];
    renderResults(mockItems, container);
}

function getIconForType(type) {
    switch (type) {
        case 'ip': return '🌐';
        case 'domain': return '🔗';
        case 'hash': return '📦';
        case 'url': return '🔗';
        default: return '❓';
    }
}
