document.addEventListener('DOMContentLoaded', () => {
    // 1. Auth Check
    const token = localStorage.getItem('access_token');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    // 2. Initialize Components
    loadKPIs();

    // Defer other scripts initialization if they rely on DOM
    if (typeof initCharts === 'function') initCharts();
    if (typeof initSearch === 'function') initSearch();
    if (typeof initBreachCheck === 'function') initBreachCheck();

    document.getElementById('logout-btn').addEventListener('click', () => {
        localStorage.removeItem('access_token');
        window.location.href = 'index.html';
    });
});

/* -------------------------------------------------------------------------- */
/*                                 KPI Manager                                */
/* -------------------------------------------------------------------------- */
async function loadKPIs() {
    // In a real app, fetch from network. Here we simulate or use the real API if available.
    // For demonstration, I will animate mock data first, then try to fetch.

    const kpiData = {
        actors: 24,
        intrusion_sets: 912,
        campaigns: 750,
        malware: 6620,
        indicators: 430600,
        observables: 460600
    };

    // Try API fetch
    try {
        const token = localStorage.getItem('access_token');
        const API_URL = 'http://localhost:8000/api';

        const response = await fetch(`${API_URL}/stats/dashboard`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            const payload = await response.json();
            const summary = payload.summary || {};

            kpiData.actors = summary.threat_actor_count ?? kpiData.actors;
            kpiData.intrusion_sets = summary.intrusion_set_count ?? kpiData.intrusion_sets;
            kpiData.campaigns = summary.campaign_count ?? kpiData.campaigns;
            kpiData.malware = summary.malware_count ?? kpiData.malware;
            kpiData.indicators = summary.total_indicators ?? summary.total_iocs ?? kpiData.indicators;
            kpiData.observables = summary.total_observables ?? kpiData.observables;
        }
    } catch (e) {
        console.warn('Backend generic fetch failed, using mock data for KPIs');
    }

    // Animate updates
    updateKPI('kpi-actors', kpiData.actors);
    updateKPI('kpi-intrusion', kpiData.intrusion_sets);
    updateKPI('kpi-campaigns', kpiData.campaigns);
    updateKPI('kpi-malware', kpiData.malware);
    updateKPI('kpi-indicators', kpiData.indicators);
    updateKPI('kpi-observables', kpiData.observables);
}

function updateKPI(id, value) {
    const el = document.getElementById(id);
    if (!el) return;

    // Format large numbers
    const formatted = new Intl.NumberFormat('en-US', {
        notation: "compact",
        compactDisplay: "short"
    }).format(value);

    // Simple count up
    el.innerText = formatted;
}
