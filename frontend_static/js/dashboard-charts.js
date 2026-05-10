document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('access_token');
    if (!token || token === 'null' || token === 'undefined') {
        redirectToLogin();
        return;
    }

    initMap();
    fetchDashboardData();
    setupSearch();
});

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
const DASHBOARD_BASE = `${API_BASE}/dashboard`;
let mapInstance = null;
let mapLayer = null;
const chartPalette = ['#ef4444', '#f97316', '#eab308', '#10b981', '#06b6d4', '#3b82f6', '#6366f1', '#a855f7', '#d946ef', '#f43f5e'];

const malwarePalette = [
    '#ef4444', '#f97316', '#f59e0b', '#facc15', '#84cc16', '#22c55e',
    '#14b8a6', '#06b6d4', '#0ea5e9', '#3b82f6', '#6366f1', '#8b5cf6',
    '#d946ef', '#f43f5e'
];

const toolsPalette = ['#ef4444', '#a855f7', '#ec4899', '#8b5cf6', '#22c55e', '#3b82f6', '#06b6d4'];

const ttpPalette = ['#f97316', '#f59e0b', '#22c55e', '#0ea5e9', '#8b5cf6'];

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const HASH_PATTERN = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const IP_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$|^[a-f0-9:]+$/i;
const URL_PATTERN = /^https?:\/\//i;
const DOMAIN_PATTERN = /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i;

const percentLabelPlugin = {
    id: 'percentLabels',
    afterDatasetsDraw(chart, args, pluginOptions) {
        const dataset = chart.data.datasets[0];
        if (!dataset) return;
        const total = dataset.data.reduce((sum, value) => sum + value, 0);
        if (!total) return;

        const meta = chart.getDatasetMeta(0);
        const minPercent = (pluginOptions && pluginOptions.minPercent) || 4;
        const color = (pluginOptions && pluginOptions.color) || '#e2e8f0';
        const fontSize = (pluginOptions && pluginOptions.fontSize) || 10;

        meta.data.forEach((element, index) => {
            const value = dataset.data[index];
            const percent = (value / total) * 100;
            if (percent < minPercent) return;

            const position = element.tooltipPosition();
            const ctx = chart.ctx;

            ctx.save();
            ctx.fillStyle = color;
            ctx.font = `${fontSize}px Inter, sans-serif`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(`${percent.toFixed(1)}%`, position.x, position.y);
            ctx.restore();
        });
    }
};

if (Chart && Chart.register) {
    Chart.register(percentLabelPlugin);
}

Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(74, 158, 255, 0.05)';
Chart.defaults.font.family = "'Inter', sans-serif";

function getHeaders() {
    const token = localStorage.getItem('access_token');
    if (!token || token === 'null' || token === 'undefined') {
        return { 'Content-Type': 'application/json' };
    }
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
}

function redirectToLogin() {
    window.location.href = `${APP_BASE}/static/index.html`;
}

function navigateTo(path) {
    window.location.href = `${APP_BASE}${path}`;
}

function formatCompact(value) {
    return new Intl.NumberFormat('en-US', { notation: 'compact', compactDisplay: 'short' }).format(value);
}

function getNiceMax(value) {
    if (!Number.isFinite(value) || value <= 0) return 1;
    const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
    const normalized = value / magnitude;
    const multipliers = [1, 1.6, 2, 2.5, 4, 5, 8, 10];
    const match = multipliers.find((multiplier) => normalized <= multiplier) || 10;
    return match * magnitude;
}

const COUNTRY_LABELS = {
    US: 'United States of America',
    GB: 'United Kingdom',
    DE: 'Germany',
    FR: 'France',
    IT: 'Italy',
    ES: 'Spain',
    NL: 'Netherlands',
    SE: 'Sweden',
    NO: 'Norway',
    FI: 'Finland',
    PL: 'Poland',
    RO: 'Romania',
    UA: 'Ukraine',
    RU: 'Russian Federation',
    CN: 'China',
    JP: 'Japan',
    KR: 'Republic of Korea',
    IN: 'India',
    SG: 'Singapore',
    HK: 'Hong Kong',
    TW: 'Taiwan',
    VN: 'Vietnam',
    TH: 'Thailand',
    ID: 'Indonesia',
    PK: 'Pakistan',
    IR: 'Iran',
    KP: 'North Korea',
    BR: 'Brazil',
    MX: 'Mexico',
    CA: 'Canada',
    AU: 'Australia',
    NZ: 'New Zealand',
    ZA: 'South Africa',
    TR: 'Turkey',
    EG: 'Egypt',
    SA: 'Saudi Arabia'
};

const REGION_LABELS = {
    'N.AMERICA': 'NA',
    'S.AMERICA': 'LATAM',
    'EUROPE': 'EUROPE',
    'ASIA': 'APAC',
    'AFRICA': 'MEA',
    'OCEANIA': 'OCEANIA',
    'OTHER': 'OTHER'
};

const COUNTRY_COORDS = {
    US: [39.5, -98.35],
    CA: [56.13, -106.35],
    MX: [23.63, -102.55],
    BR: [-14.23, -51.92],
    AR: [-38.42, -63.62],
    CL: [-35.68, -71.54],
    CO: [4.57, -74.3],
    PE: [-9.19, -75.02],
    VE: [7.07, -66.2],
    GB: [55.38, -3.44],
    DE: [51.17, 10.45],
    FR: [46.23, 2.21],
    IT: [41.87, 12.57],
    ES: [40.46, -3.75],
    NL: [52.13, 5.29],
    SE: [60.13, 18.64],
    NO: [60.47, 8.47],
    FI: [61.92, 25.75],
    PL: [52.07, 19.48],
    RO: [45.94, 24.97],
    UA: [48.38, 31.17],
    RU: [61.52, 105.32],
    CN: [35.86, 104.2],
    JP: [36.2, 138.25],
    KR: [36.5, 127.9],
    IN: [21.13, 78.0],
    SG: [1.35, 103.82],
    HK: [22.32, 114.17],
    TW: [23.7, 121.0],
    VN: [14.06, 108.28],
    TH: [15.87, 100.99],
    ID: [-0.79, 113.92],
    PK: [30.38, 69.35],
    IR: [32.43, 53.69],
    KP: [40.34, 127.51],
    TR: [38.96, 35.24],
    SA: [23.89, 45.08],
    EG: [26.82, 30.8],
    ZA: [-30.56, 22.94],
    AU: [-25.27, 133.77],
    NZ: [-41.29, 174.78]
};

/* -------------------------------------------------------------------------- */
/*                                 Leaflet Map                                */
/* -------------------------------------------------------------------------- */
function initMap() {
    mapInstance = L.map('world-map', {
        zoomControl: false,
        attributionControl: false
    }).setView([20, 0], 2);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(mapInstance);

    mapLayer = L.layerGroup().addTo(mapInstance);
}

function updateMapMarkers(countryCounts) {
    if (!mapInstance || !mapLayer) return;
    mapLayer.clearLayers();

    const entries = Object.entries(countryCounts || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);

    const resolvedEntries = entries
        .map(([code, count]) => {
            const coords = COUNTRY_COORDS[code] || COUNTRY_COORDS[String(code).toUpperCase()];
            if (!coords) return null;
            return { code: String(code).toUpperCase(), count, coords };
        })
        .filter(Boolean);

    if (resolvedEntries.length === 0) {
        const fallback = [
            [37.77, -122.41], [40.71, -74.0], [51.5, -0.12], [48.85, 2.35],
            [35.67, 139.65], [-33.86, 151.2], [55.75, 37.61], [19.07, 72.87],
            [-23.55, -46.63], [30.04, 31.23]
        ];
        fallback.forEach((coord) => {
            L.circleMarker(coord, {
                radius: 4,
                fillColor: '#ef4444',
                color: '#ef4444',
                weight: 1,
                opacity: 1,
                fillOpacity: 0.8
            }).addTo(mapLayer);

            L.circleMarker(coord, {
                radius: 15,
                fillColor: '#ef4444',
                color: 'transparent',
                weight: 0,
                fillOpacity: 0.2
            }).addTo(mapLayer);
        });
        return;
    }

    const max = Math.max(...resolvedEntries.map((item) => Number(item.count) || 0), 1);
    resolvedEntries.forEach(({ count, coords }) => {
        const normalized = Math.min(1, (Number(count) || 0) / max);
        const radius = 4 + normalized * 8;
        const glowRadius = radius + 10;

        L.circleMarker(coords, {
            radius: radius,
            fillColor: '#ef4444',
            color: '#ef4444',
            weight: 1,
            opacity: 1,
            fillOpacity: 0.5 + normalized * 0.4
        }).addTo(mapLayer);

        L.circleMarker(coords, {
            radius: glowRadius,
            fillColor: '#ef4444',
            color: 'transparent',
            weight: 0,
            fillOpacity: 0.12 + normalized * 0.18
        }).addTo(mapLayer);
    });
}

/* -------------------------------------------------------------------------- */
/*                                Data Fetching                               */
/* -------------------------------------------------------------------------- */
async function fetchDashboardData() {
    try {
        const requests = [
            fetchJson(`${DASHBOARD_BASE}/kpis`),
            fetchJson(`${DASHBOARD_BASE}/targeted-regions`),
            fetchJson(`${DASHBOARD_BASE}/targeted-countries`),
            fetchJson(`${DASHBOARD_BASE}/active-intrusion-sets`),
            fetchJson(`${DASHBOARD_BASE}/active-malware`),
            fetchJson(`${DASHBOARD_BASE}/active-tools`),
            fetchJson(`${DASHBOARD_BASE}/active-ttps`),
            fetchJson(`${DASHBOARD_BASE}/most-active-threats`),
            fetchJson(`${DASHBOARD_BASE}/targeted-sectors`),
            fetchJson(`${DASHBOARD_BASE}/timeline?days=30`),
            fetchJson(`${DASHBOARD_BASE}/active-vulnerabilities`),
            fetchJson(`${DASHBOARD_BASE}/indicator-sources`),
            fetchJson(`${DASHBOARD_BASE}/latest-campaigns`),
            fetchJson(`${DASHBOARD_BASE}/recent-reports`)
        ];

        const settled = await Promise.allSettled(requests);
        const values = settled.map((result) => {
            if (result.status === 'fulfilled') return result.value;
            console.error('Dashboard endpoint failed:', result.reason);
            return null;
        });

        const [
            kpis,
            regions,
            countries,
            intrusionSets,
            malware,
            tools,
            ttps,
            mostActiveThreats,
            sectors,
            timeline,
            vulnerabilities,
            sources,
            campaigns,
            reports
        ] = values;

        const data = normalizeDashboardPayload({
            kpis,
            regions,
            countries,
            intrusionSets,
            malware,
            tools,
            ttps,
            mostActiveThreats,
            sectors,
            timeline,
            vulnerabilities,
            sources,
            campaigns,
            reports
        });

        updateKPIs(data);
        renderAllCharts(data);
        renderIndicatorSources(data);
        renderVulnerabilityList(data);
        renderLatestCampaigns(data);
        renderRecentReports(data);
        renderMostActiveThreats(data);
        updateMapMarkers(data.top_countries || {});

    } catch (error) {
        console.error('Dashboard fetch error:', error);
        renderMockData();
    }
}

function normalizeDashboardPayload(payload) {
    const mapFromList = (list, keyField, valueField) => {
        const result = {};
        if (!Array.isArray(list)) return result;
        list.forEach((item) => {
            const key = item && item[keyField];
            const value = Number(item && item[valueField]);
            if (key) {
                result[key] = Number.isFinite(value) ? value : 0;
            }
        });
        return result;
    };

    const mapCountries = (list) => {
        const result = {};
        if (!Array.isArray(list)) return result;
        list.forEach((item) => {
            const code = item && item.country ? String(item.country).toUpperCase() : '';
            const value = Number(item && item.count);
            if (code) {
                result[code] = Number.isFinite(value) ? value : 0;
            }
        });
        return result;
    };

    const kpis = payload.kpis || {};
    const intrusionItems = Array.isArray(payload.intrusionSets && payload.intrusionSets.data)
        ? payload.intrusionSets.data
        : [];
    const intrusionSetItems = intrusionItems
        .filter((item) => item && item.name)
        .map((item) => ({
            id: item.id || item.name,
            name: item.name,
            count: Number.isFinite(Number(item.count)) ? Number(item.count) : 0
        }));
    const summary = {
        threat_actor_count: kpis.threat_actors ? kpis.threat_actors.total : 0,
        intrusion_set_count: kpis.intrusion_sets ? kpis.intrusion_sets.total : 0,
        campaign_count: kpis.campaigns ? kpis.campaigns.total : 0,
        malware_count: kpis.malware ? kpis.malware.total : 0,
        total_indicators: kpis.indicators ? kpis.indicators.total : 0,
        total_observables: kpis.observables ? kpis.observables.total : 0
    };

    return {
        kpis: kpis,
        summary: summary,
        top_regions: mapFromList(payload.regions && payload.regions.data, 'region', 'count'),
        top_countries: mapCountries(payload.countries && payload.countries.data),
        top_intrusion_sets: mapFromList(intrusionSetItems, 'name', 'count'),
        intrusion_set_items: intrusionSetItems,
        top_malware: mapFromList(payload.malware && payload.malware.data, 'name', 'count'),
        top_tools: mapFromList(payload.tools && payload.tools.data, 'name', 'count'),
        top_ttps: mapFromList(payload.ttps && payload.ttps.data, 'ttp', 'count'),
        most_active_threats: (payload.mostActiveThreats && payload.mostActiveThreats.data) || [],
        sector_breakdown: (payload.sectors && payload.sectors.data) || [],
        timeline: (payload.timeline && payload.timeline.data) || [],
        vulnerabilities: (payload.vulnerabilities && payload.vulnerabilities.data) || [],
        indicator_sources: (payload.sources && payload.sources.data) || [],
        latest_campaigns: (payload.campaigns && payload.campaigns.data) || [],
        recent_reports: (payload.reports && payload.reports.data) || []
    };
}

function updateKPIs(data) {
    const summary = data.summary || {};
    const kpis = data.kpis || {};

    if (kpis.threat_actors) {
        setMetric('count-actors', kpis.threat_actors.total, summary.threat_actor_count);
        setChange('change-actors', kpis.threat_actors.change_24h);
    } else {
        setMetric('count-actors', summary.threat_actor_count, 0);
    }

    if (kpis.intrusion_sets) {
        setMetric('count-intrusion', kpis.intrusion_sets.total, summary.intrusion_set_count);
        setChange('change-intrusion', kpis.intrusion_sets.change_24h);
    } else {
        setMetric('count-intrusion', summary.intrusion_set_count, 0);
    }

    if (kpis.campaigns) {
        setMetric('count-campaigns', kpis.campaigns.total, summary.campaign_count);
        setChange('change-campaigns', kpis.campaigns.change_24h);
    } else {
        setMetric('count-campaigns', summary.campaign_count, 0);
    }

    if (kpis.malware) {
        setMetric('count-malware', kpis.malware.total, summary.malware_count);
        setChange('change-malware', kpis.malware.change_24h);
    } else {
        setMetric('count-malware', summary.malware_count, 0);
    }

    if (kpis.indicators) {
        setMetric('count-indicators', kpis.indicators.total, summary.total_indicators);
        setChange('change-indicators', kpis.indicators.change_24h);
    } else {
        setMetric('count-indicators', summary.total_indicators ?? summary.total_iocs, 0);
    }

    if (kpis.observables) {
        setMetric('count-observables', kpis.observables.total, summary.total_observables);
        setChange('change-observables', kpis.observables.change_24h);
    } else {
        setMetric('count-observables', summary.total_observables, 0);
    }
}

function setMetric(id, value, fallback) {
    const el = document.getElementById(id);
    if (!el) return;
    const numeric = Number(value);
    const resolved = Number.isFinite(numeric) ? numeric : (fallback || 0);
    el.innerText = formatCompact(resolved);
}

function setChange(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    const numeric = Number(value);
    const resolved = Number.isFinite(numeric) ? numeric : 0;
    const isNegative = resolved < 0;
    el.classList.toggle('negative', isNegative);
    el.classList.toggle('positive', !isNegative);
    const prefix = resolved > 0 ? '+' : '';
    el.innerText = `${prefix}${resolved} (24 hours)`;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.innerText = value;
}

/* -------------------------------------------------------------------------- */
/*                                Chart Rendering                             */
/* -------------------------------------------------------------------------- */
function renderAllCharts(data) {
    const intrusionItems = Array.isArray(data.intrusion_set_items) ? data.intrusion_set_items : [];
    let intrusionLabels = [];
    let intrusionValues = [];
    let intrusionIds = [];

    if (intrusionItems.length > 0) {
        intrusionLabels = intrusionItems.map((item) => item.name);
        intrusionValues = intrusionItems.map((item) => item.count);
        intrusionIds = intrusionItems.map((item) => item.id || item.name);
    } else {
        const intrusionSets = (data.top_intrusion_sets && Object.keys(data.top_intrusion_sets).length > 0)
            ? data.top_intrusion_sets
            : {};
        intrusionLabels = Object.keys(intrusionSets);
        intrusionValues = Object.values(intrusionSets);
    }

    createSimpleHorizontalBar('chartIntrusionSets', intrusionLabels, intrusionValues, intrusionIds);

    createDonutChart('chartActiveMalware', buildMalwareData(data), malwarePalette, {
        showLegend: true,
        minPercent: 3.5,
        cutout: '62%',
        hoverOffset: 6
    });

    createDonutChart('chartTools', buildToolData(data), toolsPalette, {
        showLegend: true,
        minPercent: 3.5,
        cutout: '62%',
        hoverOffset: 6
    });

    const countriesData = data.top_countries || {};
    const sortedCountries = Object.entries(countriesData).sort((a, b) => b[1] - a[1]).slice(0, 15);
    const countryLabels = sortedCountries.map(([code]) => COUNTRY_LABELS[code] || code);
    const countryValues = sortedCountries.map(([, value]) => value);
    createTargetedCountriesChart('chartTargetedCountries', countryLabels, countryValues);

    let regionLabels = [];
    let regionValues = [];
    if (data.top_regions && Object.keys(data.top_regions).length > 0) {
        const entries = Object.entries(data.top_regions).sort((a, b) => b[1] - a[1]);
        const total = entries.reduce((sum, item) => sum + item[1], 0);
        regionLabels = entries.map(([region]) => REGION_LABELS[region] || region);
        regionValues = entries.map(([, value]) => total ? Math.round((value / total) * 1000) / 10 : value);
    } else {
        const regionData = buildRegionData(countriesData);
        regionLabels = Object.keys(regionData);
        regionValues = Object.values(regionData);
    }
    createRegionListChart('chartTargetedRegions', regionLabels, regionValues);

    const heatmapData = buildHeatmapData(countriesData);
    createHeatmapBars('chartRegionsHeatmap', heatmapData.labels, heatmapData.data);

    const sectorSeries = buildSectorSeries(data);
    createSectorLineChart('chartSectors', sectorSeries.labels, sectorSeries.datasets);

    const sectorTrend = buildSectorTrend(data);
    createTrendLineChart('chartSectorsTrend', sectorTrend.labels, sectorTrend.data);

    const ttpData = buildTtpData(data);
    createDonutChart('chartTTPs', ttpData, ttpPalette, {
        showLegend: false,
        minPercent: 6,
        cutout: '70%'
    });
    renderCustomLegend('chartTTPsLegend', ttpData.labels, ttpPalette);
}

function createSimpleHorizontalBar(id, labels, data, ids) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const hasLinks = Array.isArray(ids) && ids.length === labels.length;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: '#3b82f6',
                barThickness: 6,
                borderRadius: 3
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            onClick: hasLinks ? (event, elements, chart) => {
                if (!elements.length) return;
                const index = elements[0].index;
                const targetId = ids[index] || labels[index];
                if (!targetId) return;
                navigateTo(`/threats/${encodeURIComponent(targetId)}`);
            } : undefined,
            onHover: hasLinks ? (event, elements, chart) => {
                chart.canvas.style.cursor = elements.length ? 'pointer' : 'default';
            } : undefined,
            scales: {
                x: { display: false },
                y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { display: false } }
            }
        }
    });
}

function createTargetedCountriesChart(id, labels, data) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const maxValue = Math.max(...data, 0);
    const niceMax = getNiceMax(maxValue || 1);
    const stepSize = niceMax / 2;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: '#4f7cff',
                barThickness: 6,
                borderRadius: 4,
                borderSkipped: false
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            layout: { padding: { right: 8 } },
            scales: {
                x: {
                    beginAtZero: true,
                    max: niceMax,
                    grid: {
                        color: 'rgba(148, 163, 184, 0.2)',
                        borderDash: [4, 4],
                        drawBorder: false,
                        drawTicks: false
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        callback: formatCompact,
                        stepSize: stepSize,
                        maxTicksLimit: 3,
                        padding: 6
                    }
                },
                y: {
                    grid: { display: false },
                    ticks: {
                        color: '#e2e8f0',
                        font: { size: 10 },
                        padding: 6
                    }
                }
            }
        }
    });
}

function createRegionListChart(id, labels, data) {
    const ctx = document.getElementById(id);
    if (!ctx) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: '#3b82f6',
                barThickness: 4,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { display: false },
                y: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { size: 10 } }
                }
            }
        }
    });
}

function createSectorLineChart(id, labels, datasets) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const maxValue = Math.max(...datasets.flatMap((dataset) => dataset.data || []), 0);
    const niceMax = getNiceMax(maxValue || 1);
    const stepSize = niceMax / 4;

    new Chart(ctx, {
        type: 'line',
        data: { labels: labels, datasets: datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        color: '#cbd5e1',
                        font: { size: 10 },
                        boxWidth: 6,
                        padding: 12
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        maxRotation: 45,
                        minRotation: 45,
                        padding: 6,
                        autoSkip: false
                    }
                },
                y: {
                    beginAtZero: true,
                    max: niceMax,
                    grid: { color: 'rgba(148, 163, 184, 0.2)', borderDash: [4, 4] },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        stepSize: stepSize,
                        callback: formatCompact
                    }
                }
            }
        }
    });
}

function createTrendLineChart(id, labels, data) {
    const ctx = document.getElementById(id);
    if (!ctx) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                borderColor: '#22d3ee',
                backgroundColor: 'rgba(34, 211, 238, 0.15)',
                fill: true,
                tension: 0.35,
                pointRadius: 0,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 10 } } },
                y: { grid: { color: 'rgba(148, 163, 184, 0.15)' }, ticks: { color: '#94a3b8', font: { size: 10 } } }
            }
        }
    });
}

function createHeatmapBars(id, labels, data) {
    const ctx = document.getElementById(id);
    if (!ctx) return;

    const max = Math.max(...data, 1);
    const colors = data.map(value => {
        const intensity = Math.max(0.2, value / max);
        const lightness = Math.round(22 + intensity * 40);
        return `hsl(210, 90%, ${lightness}%)`;
    });

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderRadius: 3,
                barThickness: 8
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { display: false },
                y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { display: false } }
            }
        }
    });
}

function createDonutChart(id, dataSet, colors, options = {}) {
    const ctx = document.getElementById(id);
    if (!ctx) return;

    const showLegend = options.showLegend !== undefined ? options.showLegend : true;
    const cutout = options.cutout || '68%';
    const minPercent = options.minPercent !== undefined ? options.minPercent : 4;
    const hoverOffset = options.hoverOffset !== undefined ? options.hoverOffset : 4;
    const borderWidth = options.borderWidth !== undefined ? options.borderWidth : 1;
    const borderColor = options.borderColor || '#0b0d21';

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: dataSet.labels,
            datasets: [{
                data: dataSet.data,
                backgroundColor: colors,
                borderWidth: borderWidth,
                borderColor: borderColor,
                hoverOffset: hoverOffset
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: cutout,
            plugins: {
                legend: {
                    display: showLegend,
                    position: 'bottom',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        color: '#cbd5e1',
                        font: { size: 10 },
                        boxWidth: 6,
                        padding: 12
                    }
                },
                percentLabels: {
                    minPercent: minPercent,
                    color: '#e2e8f0',
                    fontSize: 10
                }
            }
        }
    });
}

function renderCustomLegend(containerId, labels, colors) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';

    if (!Array.isArray(labels) || labels.length === 0) {
        return;
    }

    labels.forEach((label, index) => {
        const item = document.createElement('div');
        item.className = 'legend-item';

        const dot = document.createElement('span');
        dot.className = 'legend-color';
        dot.style.background = colors[index % colors.length];

        const text = document.createElement('span');
        text.textContent = label;

        item.appendChild(dot);
        item.appendChild(text);
        container.appendChild(item);
    });
}

/* -------------------------------------------------------------------------- */
/*                               Data Builders                                */
/* -------------------------------------------------------------------------- */
function buildRegionData(topCountries) {
    const regionMap = {
        NA: ['US', 'CA', 'MX'],
        LATAM: ['BR', 'AR', 'CL', 'CO', 'PE', 'VE'],
        EUROPE: ['GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'SE', 'NO', 'FI', 'PL', 'RO', 'UA'],
        APAC: ['CN', 'JP', 'KR', 'SG', 'IN', 'HK', 'TW', 'VN', 'TH', 'ID', 'AU', 'NZ', 'PK'],
        MEA: ['IR', 'SA', 'AE', 'IL', 'EG', 'ZA', 'NG', 'KE', 'MA']
    };
    const regions = { NA: 0, LATAM: 0, EUROPE: 0, APAC: 0, MEA: 0, OTHER: 0 };

    Object.entries(topCountries).forEach(([code, count]) => {
        const upper = code.toUpperCase();
        const match = Object.keys(regionMap).find(region => regionMap[region].includes(upper));
        if (match) {
            regions[match] += count;
        } else {
            regions.OTHER += count;
        }
    });

    const total = Object.values(regions).reduce((sum, value) => sum + value, 0);
    if (!total) {
        return { NA: 60, LATAM: 45, EUROPE: 40, APAC: 35, MEA: 20, OTHER: 10 };
    }

    return regions;
}

function buildSectorSeries(data) {
    const sectorBreakdown = Array.isArray(data.sector_breakdown) ? data.sector_breakdown : [];
    if (sectorBreakdown.length > 0) {
        const labels = buildMonthLabels(13);
        const baseline = 6;
        const rampIndex = labels.length - 2;
        const peakIndex = labels.length - 1;
        const topSectors = sectorBreakdown.slice(0, 5);
        const datasets = topSectors.map((sector, idx) => {
            const peak = Math.max(baseline, Math.round(Number(sector.count) || baseline));
            const ramp = Math.max(baseline, Math.round(peak * 0.4));
            const series = labels.map((_, index) => {
                if (index < rampIndex) return baseline;
                if (index === rampIndex) return ramp;
                if (index === peakIndex) return peak;
                return baseline;
            });
            const color = chartPalette[idx % chartPalette.length];
            return {
                label: sector.sector,
                data: series,
                borderColor: color,
                backgroundColor: color,
                borderWidth: 2,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 3,
                fill: false
            };
        });
        return { labels: labels, datasets: datasets };
    }

    const summary = data.summary || {};
    const total = summary.total_indicators || summary.total_iocs || 10000;
    const maxValue = Math.max(1200, Math.round(total / 80));
    const labels = buildMonthLabels(13);
    const baseline = Math.max(8, Math.round(maxValue * 0.03));
    const ramp = Math.round(maxValue * 0.65);
    const spike = maxValue;

    const trend = labels.map((_, idx) => {
        if (idx < labels.length - 2) return baseline;
        if (idx === labels.length - 2) return ramp;
        return spike;
    });

    const sectors = [
        { label: 'Finance', color: '#38bdf8', weight: 1.0 },
        { label: 'Energy', color: '#f87171', weight: 0.75 },
        { label: 'Transport', color: '#a855f7', weight: 0.6 },
        { label: 'Governments & Administration', color: '#f472b6', weight: 0.9 },
        { label: 'Health', color: '#8b5cf6', weight: 0.55 }
    ];

    const datasets = sectors.map((sector) => {
        const values = trend.map((value) => Math.round(value * sector.weight));
        return {
            label: sector.label,
            data: values,
            borderColor: sector.color,
            backgroundColor: sector.color,
            borderWidth: 2,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 3,
            fill: false
        };
    });

    return { labels: labels, datasets: datasets };
}

function buildSectorTrend(data) {
    const timeline = Array.isArray(data.timeline) ? data.timeline : [];
    if (timeline.length > 0) {
        const slice = timeline.slice(-7);
        return {
            labels: slice.map(item => formatShortDate(item.date)),
            data: slice.map((item) => {
                if (Number.isFinite(item.indicator)) return item.indicator;
                return Object.entries(item).reduce((sum, entry) => {
                    if (entry[0] === 'date') return sum;
                    const value = Number(entry[1]);
                    return Number.isFinite(value) ? sum + value : sum;
                }, 0);
            })
        };
    }

    const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const summary = data.summary || {};
    const base = Math.max(12, Math.round((summary.total_indicators || summary.total_iocs || 500) / 200));
    return { labels: labels, data: labels.map((_, idx) => Math.round(base * (0.8 + (idx % 3) * 0.3))) };
}

function buildHeatmapData(topCountries) {
    const entries = Object.entries(topCountries).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (entries.length > 0) {
        return {
            labels: entries.map(([code]) => COUNTRY_LABELS[code] || code),
            data: entries.map(([, value]) => value)
        };
    }
    return { labels: ['US', 'CN', 'DE', 'FR', 'BR', 'IN'], data: [12, 9, 7, 6, 5, 4] };
}

function buildMalwareData(data) {
    const topMalware = data.top_malware || {};
    let labels = Object.keys(topMalware);
    let values = Object.values(topMalware);

    const fallback = [
        'TRICKBOT', 'Cobalt Strike', 'Mimikatz', 'PlugX', 'EMOTET', 'Agent Tesla',
        'FORMBOOK', 'DARKSIDE', 'Cobalt Strike - S0154', 'ASYNCRAT', 'MIRAI',
        'Winnti', 'QUASARRAT', 'METASPLOIT'
    ];

    if (labels.length < 12) {
        const base = values.reduce((sum, value) => sum + value, 0) || 1200;
        const fillerValue = Math.max(8, Math.round(base * 0.04));
        fallback.forEach(name => {
            if (labels.length >= 12) return;
            if (!labels.includes(name)) {
                labels.push(name);
                values.push(fillerValue);
            }
        });
    }

    return { labels: labels, data: values };
}

function buildToolData(data) {
    const topTools = data.top_tools || {};
    const entries = Object.entries(topTools);
    if (entries.length > 0) {
        const limited = entries.slice(0, toolsPalette.length);
        return {
            labels: limited.map(([label]) => label),
            data: limited.map(([, value]) => value)
        };
    }

    const labels = ['POWERSPL0IT', 'COMahawk', 'LCG Kit', 'TOR', 'SILENTTRINITY', 'Royal Road', 'RMS'];
    const weights = [0.417, 0.167, 0.083, 0.083, 0.083, 0.083, 0.083];
    const summary = data.summary || {};
    const total = summary.total_indicators || summary.total_iocs || 10000;
    const values = weights.map(weight => Math.max(1, Math.round(total * weight * 0.01)));
    return { labels: labels, data: values };
}

function buildTtpData(data) {
    const topTtps = data.top_ttps || {};
    const entries = Object.entries(topTtps);
    if (entries.length > 0) {
        const limited = entries.slice(0, ttpPalette.length);
        return { labels: limited.map(([label]) => label), data: limited.map(([, value]) => value) };
    }
    return { labels: ['T1059', 'T1082', 'T1105', 'T1055'], data: [12, 9, 7, 5] };
}

function buildMonthLabels(count) {
    const labels = [];
    const now = new Date();
    for (let i = count - 1; i >= 0; i--) {
        const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
        labels.push(new Intl.DateTimeFormat('en-US', { month: 'long', year: 'numeric' }).format(date));
    }
    return labels;
}

function formatShortDate(dateString) {
    const date = new Date(dateString);
    if (Number.isNaN(date.getTime())) return dateString;
    return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' }).format(date);
}

function hexToRgba(hex, alpha) {
    const clean = hex.replace('#', '');
    const bigint = parseInt(clean, 16);
    const r = (bigint >> 16) & 255;
    const g = (bigint >> 8) & 255;
    const b = bigint & 255;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

/* -------------------------------------------------------------------------- */
/*                          Vulnerability List                                */
/* -------------------------------------------------------------------------- */
function renderVulnerabilityList(data) {
    const listEl = document.getElementById('vuln-list');
    if (!listEl) return;
    listEl.innerHTML = '';

    const fallback = [
        { value: 'CVE-2017-11882', risk: 214 },
        { value: 'CVE-2012-0158', risk: 157 },
        { value: 'CVE-2017-0199', risk: 145 },
        { value: 'CVE-2021-27065', risk: 138 },
        { value: 'CVE-2021-26855', risk: 131 },
        { value: 'CVE-2019-11510', risk: 128 },
        { value: 'CVE-2019-0708', risk: 122 }
    ];

    const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    const items = vulnerabilities.length > 0 ? vulnerabilities : fallback;

    items.slice(0, 8).forEach((item, index) => {
        const value = item.cve || item.value || item.id || 'CVE-0000-0000';
        const risk = Number.isFinite(item.risk)
            ? item.risk
            : Number.isFinite(item.count)
                ? item.count
                : Number.isFinite(item.score)
                    ? item.score
                    : (fallback[index] ? fallback[index].risk : 100 + index * 12);
        const li = document.createElement('li');
        li.innerHTML = `
            <span class="vuln-icon"><i class="fa-solid fa-gear"></i></span>
            <span class="vuln-name">${value}</span>
            <span class="vuln-count">${risk}</span>
        `;
        li.addEventListener('click', () => {
            navigateTo(`/cves/${encodeURIComponent(value)}`);
        });
        listEl.appendChild(li);
    });
}

function renderIndicatorSources(data) {
    const listEl = document.getElementById('indicator-sources');
    if (!listEl) return;
    listEl.innerHTML = '';

    const sources = Array.isArray(data.indicator_sources) ? data.indicator_sources : [];
    const entries = sources.length > 0
        ? sources
        : Object.entries(data.top_sources || {}).map(([source, count]) => ({ source, count }));

    if (entries.length === 0) {
        listEl.innerHTML = `
            <li><span>alienvault</span> <span class="val">0</span></li>
            <li><span>urlhaus</span> <span class="val">0</span></li>
            <li><span>threatfox</span> <span class="val">0</span></li>
        `;
        return;
    }

    entries.forEach((item) => {
        const source = item.source || item[0];
        const count = item.count ?? item[1] ?? 0;
        const li = document.createElement('li');
        li.innerHTML = `<span>${source}</span> <span class="val">${formatCompact(count)}</span>`;
        listEl.appendChild(li);
    });
}

function renderMostActiveThreats(data) {
    const listEl = document.getElementById('most-active-threats');
    if (!listEl) return;
    listEl.innerHTML = '';

    const threats = Array.isArray(data.most_active_threats) ? data.most_active_threats : [];
    if (threats.length === 0) {
        listEl.innerHTML = '<li><span>No data found</span> <span class="val">0</span></li>';
        return;
    }

    threats.slice(0, 8).forEach((item) => {
        const name = item.name || item.id || 'Unknown';
        const count = Number.isFinite(item.count) ? item.count : 0;
        const threatId = item.id || name;
        const li = document.createElement('li');
        li.innerHTML = `<span>${name}</span> <span class="val">${formatCompact(count)}</span>`;
        li.addEventListener('click', () => {
            navigateTo(`/threats/${encodeURIComponent(threatId)}`);
        });
        listEl.appendChild(li);
    });
}

function renderLatestCampaigns(data) {
    const container = document.getElementById('latest-campaigns');
    if (!container) return;
    container.innerHTML = '';

    const campaigns = Array.isArray(data.latest_campaigns) ? data.latest_campaigns : [];
    if (campaigns.length === 0) {
        container.innerHTML = `
            <div class="campaign-item">
                <div class="icon-circle">CA</div>
                <div class="details">
                    <h4>No campaigns yet</h4>
                    <p>Waiting for new campaign data.</p>
                </div>
            </div>
        `;
        return;
    }

    campaigns.slice(0, 4).forEach((campaign) => {
        const name = campaign.name || 'Untitled Campaign';
        const description = campaign.description || 'No description available.';
        const campaignId = campaign.id || campaign.name;
        const item = document.createElement('div');
        item.className = 'campaign-item';
        item.innerHTML = `
            <div class="icon-circle">${getInitials(name)}</div>
            <div class="details">
                <h4>${truncateText(name, 28)}</h4>
                <p>${truncateText(description, 60)}</p>
            </div>
        `;
        if (campaignId) {
            item.classList.add('is-clickable');
            item.setAttribute('role', 'button');
            item.setAttribute('tabindex', '0');
            item.addEventListener('click', () => {
                navigateTo(`/threats/${encodeURIComponent(campaignId)}`);
            });
            item.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    navigateTo(`/threats/${encodeURIComponent(campaignId)}`);
                }
            });
        }
        container.appendChild(item);
    });
}

function renderRecentReports(data) {
    const body = document.getElementById('latest-reports');
    if (!body) return;
    body.innerHTML = '';

    const reports = Array.isArray(data.recent_reports) ? data.recent_reports : [];
    if (reports.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><i class="fa-regular fa-file"></i></td>
            <td>No reports yet</td>
            <td>--</td>
            <td><span class="tag">info</span></td>
            <td><span class="btn-xs">VIEW</span></td>
        `;
        body.appendChild(row);
        return;
    }

    reports.slice(0, 6).forEach((report) => {
        const title = report.title || report.name || 'Untitled Report';
        const dateLabel = report.date ? formatShortDate(report.date) : '--';
        const labels = Array.isArray(report.labels) ? report.labels : [];
        const tag = labels[0] || report.source || 'report';
        const reportId = report.id || report.title || report.name;

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><i class="fa-regular fa-file"></i></td>
            <td>${truncateText(title, 36)}</td>
            <td>${dateLabel}</td>
            <td><span class="tag">${truncateText(tag, 14)}</span></td>
            <td><span class="btn-xs">VIEW</span></td>
        `;
        if (reportId) {
            row.classList.add('is-clickable');
            row.addEventListener('click', () => {
                navigateTo(`/threats/${encodeURIComponent(reportId)}`);
            });
            const button = row.querySelector('.btn-xs');
            if (button) {
                button.addEventListener('click', (event) => {
                    event.stopPropagation();
                    navigateTo(`/threats/${encodeURIComponent(reportId)}`);
                });
            }
        }
        body.appendChild(row);
    });
}

function getInitials(text) {
    const parts = String(text || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return 'CA';
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[1][0]).toUpperCase();
}

function truncateText(text, maxLength) {
    const value = String(text || '');
    if (value.length <= maxLength) return value;
    return `${value.slice(0, maxLength - 3)}...`;
}

/* -------------------------------------------------------------------------- */
/*                                Search Logic                                */
/* -------------------------------------------------------------------------- */
function setupSearch() {
    const input = document.getElementById('global-search') || document.querySelector('.search-bar input');
    const suggestionBox = document.getElementById('search-suggestions');
    if (!input || !suggestionBox) return;

    let debounceTimer;

    input.addEventListener('input', () => {
        const query = input.value.trim();
        clearTimeout(debounceTimer);
        if (query.length < 2) {
            hideSuggestions(suggestionBox);
            return;
        }
        debounceTimer = setTimeout(async () => {
            const suggestions = await fetchSuggestions(query);
            renderSuggestions(suggestionBox, suggestions);
        }, 220);
    });

    input.addEventListener('keydown', async (e) => {
        if (e.key === 'Enter') {
            const query = input.value.trim();
            if (query) {
                hideSuggestions(suggestionBox);
                await handleSearchSubmit(query);
            }
        }
    });

    document.addEventListener('click', (e) => {
        if (!suggestionBox.contains(e.target) && !input.contains(e.target)) {
            hideSuggestions(suggestionBox);
        }
    });

    const closeButton = document.querySelector('.close-modal');
    if (closeButton) {
        closeButton.addEventListener('click', () => {
            document.getElementById('ioc-modal').style.display = 'none';
        });
    }
}

async function fetchSuggestions(query) {
    try {
        const data = await fetchJson(`${API_BASE}/search/suggest?q=${encodeURIComponent(query)}`);
        return data && data.groups ? data.groups : {};
    } catch (err) {
        console.error('Suggestion fetch failed', err);
        return {};
    }
}

function renderSuggestions(container, groups) {
    const sections = [];
    const order = [
        { key: 'cve', label: 'CVE' },
        { key: 'threat', label: 'Threat' },
        { key: 'domain', label: 'Domain' },
        { key: 'ip', label: 'IP' },
        { key: 'url', label: 'URL' }
    ];

    order.forEach((group) => {
        const items = Array.isArray(groups[group.key]) ? groups[group.key] : [];
        if (!items.length) return;
        const itemMarkup = items.map((item) => {
            const label = item.name || item.id || item.value || 'Unknown';
            const meta = item.type || group.label;
            const value = item.id || item.value || item.name || '';
            return `
                <div class="suggestion-item" data-type="${group.key}" data-value="${encodeURIComponent(value)}">
                    <span>${label}</span>
                    <span class="suggestion-meta">${meta}</span>
                </div>
            `;
        }).join('');
        sections.push(`
            <div class="suggestion-group">
                <div class="suggestion-title">${group.label}</div>
                ${itemMarkup}
            </div>
        `);
    });

    if (!sections.length) {
        hideSuggestions(container);
        return;
    }

    container.innerHTML = sections.join('');
    container.classList.add('show');

    container.querySelectorAll('.suggestion-item').forEach((item) => {
        item.addEventListener('click', () => {
            const type = item.getAttribute('data-type');
            const value = decodeURIComponent(item.getAttribute('data-value') || '');
            navigateToEntity(type, value);
        });
    });
}

function hideSuggestions(container) {
    container.classList.remove('show');
    container.innerHTML = '';
}

async function handleSearchSubmit(query) {
    const queryType = detectQueryType(query);
    if (queryType === 'hash') {
        await openHashModal(query);
        return;
    }
    navigateToEntity(queryType, query);
}

function navigateToEntity(type, value) {
    if (!value) return;
    if (type === 'cve') {
        navigateTo(`/cves/${encodeURIComponent(value)}`);
        return;
    }
    if (type === 'threat') {
        navigateTo(`/threats/${encodeURIComponent(value)}`);
        return;
    }
    if (type === 'domain') {
        navigateTo(`/indicators/domain/${encodeURIComponent(value)}`);
        return;
    }
    if (type === 'ip') {
        navigateTo(`/indicators/ip/${encodeURIComponent(value)}`);
        return;
    }
    if (type === 'url') {
        navigateTo(`/indicators/url/${encodeURIComponent(value)}`);
        return;
    }
    navigateTo(`/threats/${encodeURIComponent(value)}`);
}

async function openHashModal(query) {
    try {
        const modal = document.getElementById('ioc-modal');
        modal.style.display = 'flex';
        setModalAlert('');
        setModalTitle(query);
        const data = await fetchJson(`${API_BASE}/search/hash/${encodeURIComponent(query)}`);
        renderHashModal(data);
    } catch (err) {
        console.error('Hash lookup failed', err);
        setModalAlert(err && err.message ? err.message : 'No results found or lookup failed.');
        setModalView('hash');
    }
}

function detectQueryType(query) {
    if (CVE_PATTERN.test(query)) return 'cve';
    if (HASH_PATTERN.test(query)) return 'hash';
    if (URL_PATTERN.test(query)) return 'url';
    if (IP_PATTERN.test(query)) return 'ip';
    if (DOMAIN_PATTERN.test(query)) return 'domain';
    return 'threat';
}

async function fetchJson(url) {
    const controller = new AbortController();
    const timeoutMs = 12000;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
        res = await fetch(url, { headers: getHeaders(), signal: controller.signal });
    } catch (err) {
        if (err && err.name === 'AbortError') {
            throw new Error(`Request timeout (${timeoutMs}ms): ${url}`);
        }
        throw err;
    } finally {
        clearTimeout(timeoutId);
    }
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

function setModalTitle(value) {
    const el = document.getElementById('modal-ioc-value');
    if (el) el.innerText = value || '-';
}

function setModalAlert(message) {
    const alertEl = document.getElementById('modal-alert');
    if (!alertEl) return;
    if (!message) {
        alertEl.textContent = '';
        alertEl.classList.add('is-hidden');
        return;
    }
    alertEl.textContent = message;
    alertEl.classList.remove('is-hidden');
}

function setModalView(view) {
    const iocView = document.querySelector('.ioc-view');
    const cveView = document.querySelector('.cve-view');
    const hashView = document.querySelector('.hash-view');

    if (iocView) iocView.classList.toggle('is-hidden', view !== 'ioc');
    if (cveView) cveView.classList.toggle('is-hidden', view !== 'cve');
    if (hashView) hashView.classList.toggle('is-hidden', view !== 'hash');
}

function renderIocModal(data) {
    setModalView('ioc');
    setModalTitle(data.query || 'IOC');

    const count = data.count || 0;
    setText('modal-report-count', count);

    const confidence = count > 0 ? 88 : 0;
    const confidenceText = document.getElementById('modal-confidence-text');
    const confidenceBar = document.getElementById('modal-confidence-bar');

    if (confidenceText) confidenceText.innerText = `${confidence}%`;
    if (confidenceBar) {
        confidenceBar.style.width = `${confidence}%`;
        confidenceBar.innerText = `${confidence}%`;
    }

    const first = data.results && data.results.length > 0 ? data.results[0] : {};
    const ipApi = data.enrichment && data.enrichment.ip_api ? data.enrichment.ip_api : {};
    const domain = ipApi.reverse || first.value || '-';
    const country = ipApi.country || first.country || 'Unknown';
    const isp = ipApi.isp || ipApi.org || first.source || 'Unknown';
    const usage = ipApi.usage || first.type || 'Unknown';
    const asn = ipApi.asn || first.asn || '-';
    const city = ipApi.city || first.city || '-';

    setText('modal-domain', domain);
    setText('modal-country', country);
    setText('modal-isp', isp);
    setText('modal-usage', usage);
    setText('modal-asn', asn);
    setText('modal-city', city);
}

function renderCveModal(payload) {
    const cve = payload.cve || {};
    setModalView('cve');
    setModalTitle(cve.id || payload.query || 'CVE');

    const cna = cve.cna ? `CNA: ${cve.cna}` : 'CNA: Unknown';
    setText('cve-cna', cna);
    setText('cve-published', formatDate(cve.published));
    setText('cve-updated', formatDate(cve.updated));

    const descriptionEl = document.getElementById('cve-description');
    if (descriptionEl) {
        descriptionEl.innerText = cve.description || 'No description available.';
    }

    const cvssBody = document.getElementById('cve-cvss-body');
    if (cvssBody) {
        cvssBody.innerHTML = '';
        const cvss = cve.cvss || {};
        const row = document.createElement('tr');
        const cells = [
            cvss.score ?? 'N/A',
            cvss.severity || 'N/A',
            cvss.version || 'N/A',
            cvss.vector || 'N/A'
        ];
        cells.forEach((value) => {
            const cell = document.createElement('td');
            cell.textContent = value;
            row.appendChild(cell);
        });
        cvssBody.appendChild(row);
    }

    const productsBody = document.getElementById('cve-products-body');
    if (productsBody) {
        productsBody.innerHTML = '';
        const affected = Array.isArray(cve.affected) ? cve.affected : [];
        if (affected.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="3">No product data available.</td>`;
            productsBody.appendChild(row);
        } else {
            affected.forEach((item) => {
                const row = document.createElement('tr');
                const values = [
                    item.vendor || 'Unknown',
                    item.product || '-',
                    (item.versions || []).join(', ') || '-'
                ];
                values.forEach((value) => {
                    const cell = document.createElement('td');
                    cell.textContent = value;
                    row.appendChild(cell);
                });
                productsBody.appendChild(row);
            });
        }
    }

    const refsEl = document.getElementById('cve-references');
    if (refsEl) {
        refsEl.innerHTML = '';
        const refs = Array.isArray(cve.references) ? cve.references : [];
        if (refs.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No references available.';
            refsEl.appendChild(li);
        } else {
            refs.forEach((ref) => {
                const li = document.createElement('li');
                const link = document.createElement('a');
                link.href = ref;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = ref;
                li.appendChild(link);
                refsEl.appendChild(li);
            });
        }
    }
}

function renderHashModal(payload) {
    const hashData = payload.hash || {};
    setModalView('hash');
    setModalTitle(hashData.value || payload.query || 'Hash');

    const detected = Number(hashData.detected || 0);
    let total = Number(hashData.total || 0);
    if (!total && hashData.stats && typeof hashData.stats === 'object') {
        total = Object.values(hashData.stats).reduce((sum, value) => sum + Number(value || 0), 0);
    }
    const percent = total > 0 ? detected / total : 0;

    const ring = document.getElementById('hash-ring');
    if (ring) ring.style.setProperty('--percent', percent);

    setText('hash-detected', detected);
    setText('hash-total', `/${total || 0}`);

    const reputation = hashData.reputation ?? hashData.community_score;
    setText('hash-community', Number.isFinite(reputation) ? reputation : '-');

    setText('hash-value', hashData.value || payload.query || '-');
    setText('hash-size', formatBytes(hashData.size));
    setText('hash-last-analysis', formatDate(hashData.last_analysis_date));
    setText('hash-type', hashData.file_type || hashData.type || '-');

    renderHashTags(hashData.tags);

    const popular = hashData.popular_threat_label || '-';
    const categories = Array.isArray(hashData.threat_categories) && hashData.threat_categories.length > 0
        ? hashData.threat_categories.join(' ')
        : '-';
    const families = Array.isArray(hashData.family_labels) && hashData.family_labels.length > 0
        ? hashData.family_labels.join(' ')
        : '-';

    setText('hash-popular-label', popular);
    setText('hash-categories', categories);
    setText('hash-families', families);

    renderHashVendors(hashData.vendors || []);
}

function renderHashTags(tags) {
    const tagsEl = document.getElementById('hash-tags');
    if (!tagsEl) return;
    tagsEl.innerHTML = '';

    const list = Array.isArray(tags) ? tags.slice(0, 8) : [];
    if (list.length === 0) {
        const empty = document.createElement('span');
        empty.className = 'hash-tag';
        empty.textContent = 'no tags';
        tagsEl.appendChild(empty);
        return;
    }

    list.forEach((tag) => {
        const pill = document.createElement('span');
        pill.className = 'hash-tag';
        pill.textContent = tag;
        tagsEl.appendChild(pill);
    });
}

function renderHashVendors(vendors) {
    const body = document.getElementById('hash-vendors-body');
    if (!body) return;
    body.innerHTML = '';

    const list = Array.isArray(vendors) ? vendors.slice(0, 24) : [];
    if (list.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `<td colspan="4">No vendor results available.</td>`;
        body.appendChild(row);
        return;
    }

    for (let i = 0; i < list.length; i += 2) {
        const left = list[i];
        const right = list[i + 1];
        const row = document.createElement('tr');
        row.appendChild(buildVendorCell(left, true));
        row.appendChild(buildVendorCell(left, false));
        row.appendChild(buildVendorCell(right, true));
        row.appendChild(buildVendorCell(right, false));
        body.appendChild(row);
    }
}

function buildVendorCell(vendor, isName) {
    const cell = document.createElement('td');
    if (!vendor) {
        cell.textContent = '-';
        return cell;
    }

    if (isName) {
        cell.textContent = vendor.vendor || '-';
        return cell;
    }

    const category = vendor.category || 'undetected';
    cell.textContent = vendor.result || 'Clean';
    if (category === 'malicious' || category === 'suspicious') {
        cell.classList.add('hash-result-malicious');
    } else {
        cell.classList.add('hash-result-undetected');
    }
    return cell;
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '-';
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }
    return `${value.toFixed(2)} ${units[unitIndex]}`;
}

function formatDate(value) {
    if (!value) return '-';
    let date;
    if (typeof value === 'number') {
        date = new Date(value * 1000);
    } else if (typeof value === 'string' && /^\d+$/.test(value)) {
        date = new Date(Number(value) * 1000);
    } else {
        date = new Date(value);
    }
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'short', day: '2-digit' }).format(date);
}

function renderMockData() {
    const mock = normalizeDashboardPayload({
        kpis: {
            threat_actors: { total: 12, change_24h: 0 },
            intrusion_sets: { total: 12, change_24h: 0 },
            campaigns: { total: 18, change_24h: 2 },
            malware: { total: 32, change_24h: 1 },
            indicators: { total: 20450, change_24h: 120 },
            observables: { total: 30210, change_24h: 210 }
        },
        regions: { data: [{ region: 'N.AMERICA', count: 40 }, { region: 'EUROPE', count: 30 }, { region: 'ASIA', count: 20 }] },
        countries: { data: [{ country: 'US', count: 20 }, { country: 'DE', count: 14 }, { country: 'JP', count: 10 }] },
        intrusionSets: {
            data: [
                { id: 'intrusion-set--alphv', name: 'ALPHV', count: 18 },
                { id: 'intrusion-set--apt28', name: 'APT28', count: 12 }
            ]
        },
        malware: { data: [{ name: 'TRICKBOT', count: 18 }, { name: 'EMOTET', count: 12 }] },
        tools: { data: [{ name: 'Cobalt Strike', count: 14 }, { name: 'Mimikatz', count: 10 }] },
        ttps: { data: [{ ttp: 'T1059', count: 22 }, { ttp: 'T1105', count: 16 }] },
        mostActiveThreats: { data: [{ id: 'intrusion-set--apt28', name: 'APT28', type: 'group', count: 32 }] },
        sectors: { data: [{ sector: 'Finance', count: 1200 }, { sector: 'Energy', count: 900 }] },
        timeline: { data: [{ date: '2026-01-01', indicator: 80 }, { date: '2026-01-02', indicator: 95 }] },
        vulnerabilities: { data: [{ cve: 'CVE-2017-11882', count: 214 }] },
        sources: { data: [{ source: 'AlienVault OTX', count: 500 }, { source: 'URLhaus', count: 300 }] },
        campaigns: {
            data: [
                {
                    id: 'campaign--fata-morgana',
                    name: 'FATA MORGANA',
                    description: 'Campaign targeting shipping.'
                }
            ]
        },
        reports: {
            data: [
                {
                    id: 'report--ransom-ransomware',
                    title: 'Ransom Ransomware - Quiet',
                    date: '2026-01-02',
                    labels: ['confidential']
                }
            ]
        }
    });

    updateKPIs(mock);
    renderAllCharts(mock);
    renderIndicatorSources(mock);
    renderVulnerabilityList(mock);
    renderLatestCampaigns(mock);
    renderRecentReports(mock);
    renderMostActiveThreats(mock);
    updateMapMarkers(mock.top_countries || {});
}
